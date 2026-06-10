// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package acmez implements the higher-level flow of the ACME specification,
// RFC 8555: https://tools.ietf.org/html/rfc8555, specifically the sequence
// in Section 7.1 (page 21).
//
// It makes it easy to obtain certificates with various challenge types
// using pluggable challenge solvers, and provides some handy utilities for
// implementing solvers and using the certificates. It DOES NOT manage
// certificates, it only gets them from the ACME server.
//
// NOTE: This package's primary purpose is to get a certificate, not manage it.
// Most users actually want to *manage* certificates over the lifetime of
// long-running programs such as HTTPS or TLS servers, and should use CertMagic
// instead: https://github.com/caddyserver/certmagic.
//
// COMPATIBILITY: Exported identifiers that are related to draft specifications
// are subject to change or removal without a major version bump.
package acmez

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

// Client is a high-level API for ACME operations. It wraps
// a lower-level ACME client with useful functions to make
// common flows easier, especially for the issuance of
// certificates.
type Client struct {
	*acme.Client

	// Map of solvers keyed by name of the challenge type.
	ChallengeSolvers map[string]Solver
}

// CSRSource is an interface that provides users of this
// package the ability to provide a CSR as part of the
// ACME flow. This allows the final CSR to be provided
// just before the Order is finalized.
type CSRSource interface {
	CSR(context.Context) (*x509.CertificateRequest, error)
}

// ObtainCertificateUsingCSRSource obtains all resulting certificate chains using the given
// ACME Identifiers and the CSRSource. The CSRSource can be used to create and sign a final
// CSR to be submitted to the ACME server just before finalization. The CSR  must be completely
// and properly filled out, because the provided ACME Identifiers will be validated against
// the Identifiers that can be extracted from the CSR. This package currently supports the
// DNS, IP address, Permanent Identifier and Hardware Module Name identifiers. The Subject
// CommonName is NOT considered.
//
// The CSR's Raw field containing the DER encoded signed certificate request must also be
// set. This usually involves creating a template CSR, then calling x509.CreateCertificateRequest,
// then x509.ParseCertificateRequest on the output.
//
// The method implements every single part of the ACME flow described in RFC 8555 §7.1 with the
// exception of "Create account" because this method signature does not have a way to return
// the updated account object. The account's status MUST be "valid" in order to succeed.
func (c *Client) ObtainCertificateUsingCSRSource(ctx context.Context, account acme.Account, identifiers []acme.Identifier, source CSRSource) ([]acme.Certificate, error) {
	if account.Status != acme.StatusValid {
		return nil, fmt.Errorf("account status is not valid: %s", account.Status)
	}
	if source == nil {
		return nil, errors.New("missing CSR source")
	}

	var err error
	order := acme.Order{Identifiers: identifiers}

	// remember which challenge types failed for which identifiers
	// so we can retry with other challenge types
	failedChallengeTypes := make(failedChallengeMap)

	const maxAttempts = 3 // hard cap on number of retries for good measure
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-time.After(1 * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// create order for a new certificate
		order, err = c.Client.NewOrder(ctx, account, order)
		if err != nil {
			return nil, fmt.Errorf("creating new order: %w", err)
		}

		// solve one challenge for each authz on the order
		err = c.solveChallenges(ctx, account, order, failedChallengeTypes)

		// yay, we win!
		if err == nil {
			break
		}

		// for some errors, we can retry with different challenge types
		var problem acme.Problem
		if errors.As(err, &problem) {
			authz, haveAuthz := problem.Resource.(acme.Authorization)
			if c.Logger != nil {
				l := c.Logger
				if haveAuthz {
					l = l.With(zap.String("identifier", authz.IdentifierValue()))
				}
				l.Error("validating authorization",
					zap.Object("problem", problem),
					zap.String("order", order.Location),
					zap.Int("attempt", attempt),
					zap.Int("max_attempts", maxAttempts))
			}
			errStr := "solving challenge"
			if haveAuthz {
				errStr += ": " + authz.IdentifierValue()
			}
			err = fmt.Errorf("%s: %w", errStr, err)
			if errors.As(err, &retryableErr{}) {
				continue
			}
			return nil, err
		}

		return nil, fmt.Errorf("solving challenges: %w (order=%s)", err, order.Location)
	}

	if c.Logger != nil {
		c.Logger.Info("validations succeeded; finalizing order", zap.String("order", order.Location))
	}

	// get the CSR from its source
	csr, err := source.CSR(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting CSR from source: %w", err)
	}
	if csr == nil {
		return nil, errors.New("source did not provide CSR")
	}

	// validate the order identifiers
	if err := validateOrderIdentifiers(&order, csr); err != nil {
		return nil, fmt.Errorf("validating order identifiers: %w", err)
	}

	// finalize the order, which requests the CA to issue us a certificate
	order, err = c.Client.FinalizeOrder(ctx, account, order, csr.Raw)
	if err != nil {
		return nil, fmt.Errorf("finalizing order %s: %w", order.Location, err)
	}

	// finally, download the certificate
	certChains, err := c.Client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate chain from %s: %w (order=%s)",
			order.Certificate, err, order.Location)
	}

	if c.Logger != nil {
		if len(certChains) == 0 {
			c.Logger.Info("no certificate chains offered by server")
		} else {
			c.Logger.Info("successfully downloaded available certificate chains",
				zap.Int("count", len(certChains)),
				zap.String("first_url", certChains[0].URL))
		}
	}

	return certChains, nil
}

// validateOrderIdentifiers checks if the ACME identifiers provided for the
// Order match the identifiers that are in the CSR. A mismatch between the two
// should result the certificate not being issued by the ACME server, but
// checking this on the client side is faster. Currently there's no way to
// skip this validation.
func validateOrderIdentifiers(order *acme.Order, csr *x509.CertificateRequest) error {
	csrIdentifiers, err := createIdentifiersUsingCSR(csr)
	if err != nil {
		return fmt.Errorf("extracting identifiers from CSR: %w", err)
	}
	if len(csrIdentifiers) != len(order.Identifiers) {
		return fmt.Errorf("number of identifiers in Order %v (%d) does not match the number of identifiers extracted from CSR %v (%d)", order.Identifiers, len(order.Identifiers), csrIdentifiers, len(csrIdentifiers))
	}

	identifiers := make([]acme.Identifier, 0, len(order.Identifiers))
	for _, identifier := range order.Identifiers {
		for _, csrIdentifier := range csrIdentifiers {
			if csrIdentifier.Value == identifier.Value && csrIdentifier.Type == identifier.Type {
				identifiers = append(identifiers, identifier)
			}
		}
	}

	if len(identifiers) != len(csrIdentifiers) {
		return fmt.Errorf("identifiers in Order %v do not match the identifiers extracted from CSR %v", order.Identifiers, csrIdentifiers)
	}

	return nil
}

// csrSource implements the CSRSource interface and is used internally
// to pass a CSR to ObtainCertificateUsingCSRSource from the existing
// ObtainCertificateUsingCSR method.
type csrSource struct {
	csr *x509.CertificateRequest
}

func (i *csrSource) CSR(_ context.Context) (*x509.CertificateRequest, error) {
	return i.csr, nil
}

var _ CSRSource = (*csrSource)(nil)

// ObtainCertificateUsingCSR obtains all resulting certificate chains using the given CSR, which
// must be completely and properly filled out (particularly its DNSNames and Raw fields - this
// usually involves creating a template CSR, then calling x509.CreateCertificateRequest, then
// x509.ParseCertificateRequest on the output). The Subject CommonName is NOT considered.
//
// It implements every single part of the ACME flow described in RFC 8555 §7.1 with the exception
// of "Create account" because this method signature does not have a way to return the updated
// account object. The account's status MUST be "valid" in order to succeed.
//
// As far as SANs go, this method currently only supports DNSNames, IPAddresses, Permanent
// Identifiers and Hardware Module Names on the CSR.
func (c *Client) ObtainCertificateUsingCSR(ctx context.Context, account acme.Account, csr *x509.CertificateRequest) ([]acme.Certificate, error) {
	if csr == nil {
		return nil, errors.New("missing CSR")
	}

	ids, err := createIdentifiersUsingCSR(csr)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New("no identifiers found")
	}

	csrSource := &csrSource{
		csr: csr,
	}

	return c.ObtainCertificateUsingCSRSource(ctx, account, ids, csrSource)
}

// ObtainCertificate is the same as ObtainCertificateUsingCSR, except it is a slight wrapper
// that generates the CSR for you. Doing so requires the private key you will be using for
// the certificate (different from the account private key). It obtains a certificate for
// the given SANs (domain names) using the provided account.
func (c *Client) ObtainCertificate(ctx context.Context, account acme.Account, certPrivateKey crypto.Signer, sans []string) ([]acme.Certificate, error) {
	if len(sans) == 0 {
		return nil, fmt.Errorf("no DNS names provided: %v", sans)
	}
	if certPrivateKey == nil {
		return nil, fmt.Errorf("missing certificate private key")
	}

	csrTemplate := new(x509.CertificateRequest)
	for _, name := range sans {
		if ip := net.ParseIP(name); ip != nil {
			csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
		} else if strings.Contains(name, "@") {
			csrTemplate.EmailAddresses = append(csrTemplate.EmailAddresses, name)
		} else if u, err := url.Parse(name); err == nil && strings.Contains(name, "/") {
			csrTemplate.URIs = append(csrTemplate.URIs, u)
		} else {
			// "The domain name MUST be encoded in the form in which it would appear
			// in a certificate.  That is, it MUST be encoded according to the rules
			// in Section 7 of [RFC5280]." §7.1.4
			normalizedName, err := idna.ToASCII(name)
			if err != nil {
				return nil, fmt.Errorf("converting identifier '%s' to ASCII: %v", name, err)
			}
			csrTemplate.DNSNames = append(csrTemplate.DNSNames, normalizedName)
		}
	}

	// to properly fill out the CSR, we need to create it, then parse it
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("generating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CSR: %v", err)
	}

	return c.ObtainCertificateUsingCSR(ctx, account, csr)
}

// getAuthzObjects constructs stateful authorization objects for each authz on the order.
// It includes all authorizations regardless of their status so that they can be
// deactivated at the end if necessary. Be sure to check authz status before operating
// on the authz; not all will be "pending" - some authorizations might already be valid.
func (c *Client) getAuthzObjects(ctx context.Context, account acme.Account, order acme.Order,
	failedChallengeTypes failedChallengeMap) ([]*authzState, error) {
	var authzStates []*authzState
	var err error

	// start by allowing each authz's solver to present for its challenge
	for _, authzURL := range order.Authorizations {
		authz := &authzState{account: account}
		authz.Authorization, err = c.Client.GetAuthorization(ctx, account, authzURL)
		if err != nil {
			return nil, fmt.Errorf("getting authorization at %s: %w", authzURL, err)
		}

		// add all offered challenge types to our memory if they
		// arent't there already; we use this for statistics to
		// choose the most successful challenge type over time;
		// if initial fill, randomize challenge order
		preferredChallengesMu.Lock()
		preferredWasEmpty := len(preferredChallenges) == 0
		for _, chal := range authz.Challenges {
			preferredChallenges.addUnique(chal.Type)
		}
		if preferredWasEmpty {
			randomSourceMu.Lock()
			randomSource.Shuffle(len(preferredChallenges), func(i, j int) {
				preferredChallenges[i], preferredChallenges[j] =
					preferredChallenges[j], preferredChallenges[i]
			})
			randomSourceMu.Unlock()
		}
		preferredChallengesMu.Unlock()

		// copy over any challenges that are not known to have already
		// failed, making them candidates for solving for this authz
		failedChallengeTypes.enqueueUnfailedChallenges(authz)

		authzStates = append(authzStates, authz)
	}

	// sort authzs so that challenges which require waiting go first; no point
	// in getting authorizations quickly while others will take a long time
	sort.SliceStable(authzStates, func(i, j int) bool {
		_, iIsWaiter := authzStates[i].currentSolver.(Waiter)
		_, jIsWaiter := authzStates[j].currentSolver.(Waiter)
		// "if i is a waiter, and j is not a waiter, then i is less than j"
		return iIsWaiter && !jIsWaiter
	})

	return authzStates, nil
}

func (c *Client) solveChallenges(ctx context.Context, account acme.Account, order acme.Order, failedChallengeTypes failedChallengeMap) error {
	authzStates, err := c.getAuthzObjects(ctx, account, order, failedChallengeTypes)
	if err != nil {
		return err
	}

	// when the function returns, make sure we clean up any and all resources
	defer func() {
		// always clean up any remaining challenge solvers
		for _, authz := range authzStates {
			if authz.currentSolver == nil {
				// happens when authz state ended on a challenge we have no
				// solver for or if we have already cleaned up this solver
				continue
			}
			if err := authz.currentSolver.CleanUp(ctx, authz.currentChallenge); err != nil {
				if c.Logger != nil {
					c.Logger.Error("cleaning up solver",
						zap.String("identifier", authz.IdentifierValue()),
						zap.String("challenge_type", authz.currentChallenge.Type),
						zap.Error(err))
				}
			}
		}

		if err == nil {
			return
		}

		// if this function returns with an error, make sure to deactivate
		// all pending or valid authorization objects so they don't "leak"
		// See: https://github.com/go-acme/lego/issues/383 and https://github.com/go-acme/lego/issues/353
		for _, authz := range authzStates {
			if authz.Status != acme.StatusPending && authz.Status != acme.StatusValid {
				continue
			}
			updatedAuthz, err := c.Client.DeactivateAuthorization(ctx, account, authz.Location)
			if err != nil {
				if c.Logger != nil {
					c.Logger.Error("deactivating authorization",
						zap.String("identifier", authz.IdentifierValue()),
						zap.String("authz", authz.Location),
						zap.Error(err))
				}
			}
			authz.Authorization = updatedAuthz
		}
	}()

	// present for all challenges first; this allows them all to begin any
	// slow tasks up front if necessary before we start polling/waiting
	for _, authz := range authzStates {
		// see §7.1.6 for state transitions
		if authz.Status != acme.StatusPending && authz.Status != acme.StatusValid {
			return fmt.Errorf("authz %s has unexpected status; order will fail: %s", authz.Location, authz.Status)
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		err = c.presentForNextChallenge(ctx, authz)
		if err != nil {
			return err
		}
	}

	// now that all solvers have had the opportunity to present, tell
	// the server to begin the selected challenge for each authz
	for _, authz := range authzStates {
		err = c.initiateCurrentChallenge(ctx, authz)
		if err != nil {
			return err
		}
	}

	// poll each authz to wait for completion of all challenges
	for _, authz := range authzStates {
		err = c.pollAuthorization(ctx, account, authz, failedChallengeTypes)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Client) presentForNextChallenge(ctx context.Context, authz *authzState) error {
	if authz.Status != acme.StatusPending {
		if authz.Status == acme.StatusValid && c.Logger != nil {
			c.Logger.Info("authorization already valid",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("authz_url", authz.Location),
				zap.Time("expires", authz.Expires))
		}
		return nil
	}

	err := c.nextChallenge(authz)
	if err != nil {
		return err
	}

	if c.Logger != nil {
		c.Logger.Info("trying to solve challenge",
			zap.String("identifier", authz.IdentifierValue()),
			zap.String("challenge_type", authz.currentChallenge.Type),
			zap.String("ca", c.Directory))
	}

	err = authz.currentSolver.Present(ctx, authz.currentChallenge)
	if err != nil {
		return fmt.Errorf("presenting for challenge: %w", err)
	}

	return nil
}

func (c *Client) initiateCurrentChallenge(ctx context.Context, authz *authzState) error {
	if authz.Status != acme.StatusPending {
		if c.Logger != nil {
			c.Logger.Debug("skipping challenge initiation because authorization is not pending",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("authz_status", authz.Status))
		}
		return nil
	}

	// by now, all challenges should have had an opportunity to present, so
	// if this solver needs more time to finish presenting, wait on it now
	// (yes, this does block the initiation of the other challenges, but
	// that's probably OK, since we can't finalize the order until the slow
	// challenges are done too)
	if waiter, ok := authz.currentSolver.(Waiter); ok {
		if c.Logger != nil {
			c.Logger.Debug("waiting for solver before continuing",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("challenge_type", authz.currentChallenge.Type))
		}
		err := waiter.Wait(ctx, authz.currentChallenge)
		if c.Logger != nil {
			c.Logger.Debug("done waiting for solver",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("challenge_type", authz.currentChallenge.Type))
		}
		if err != nil {
			return fmt.Errorf("waiting for solver %T to be ready: %w", authz.currentSolver, err)
		}
	}

	// for device-attest-01 challenges the client needs to present a payload
	// that will be validated by the CA.
	if payloader, ok := authz.currentSolver.(Payloader); ok {
		if c.Logger != nil {
			c.Logger.Debug("getting payload from solver before continuing",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("challenge_type", authz.currentChallenge.Type))
		}
		p, err := payloader.Payload(ctx, authz.currentChallenge)
		if c.Logger != nil {
			c.Logger.Debug("done getting payload from solver",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("challenge_type", authz.currentChallenge.Type))
		}
		if err != nil {
			return fmt.Errorf("getting payload from solver %T failed: %w", authz.currentSolver, err)
		}
		authz.currentChallenge.Payload = p
	}

	// tell the server to initiate the challenge
	var err error
	authz.currentChallenge, err = c.Client.InitiateChallenge(ctx, authz.account, authz.currentChallenge)
	if err != nil {
		return fmt.Errorf("initiating challenge with server: %w", err)
	}

	if c.Logger != nil {
		c.Logger.Debug("challenge accepted",
			zap.String("identifier", authz.IdentifierValue()),
			zap.String("challenge_type", authz.currentChallenge.Type))
	}

	return nil
}

// nextChallenge sets the next challenge (and associated solver) on
// authz; it returns an error if there is no compatible challenge.
func (c *Client) nextChallenge(authz *authzState) error {
	preferredChallengesMu.Lock()
	defer preferredChallengesMu.Unlock()

	// find the most-preferred challenge that is also in the list of
	// remaining challenges, then make sure we have a solver for it
	for _, prefChalType := range preferredChallenges {
		for i, remainingChal := range authz.remainingChallenges {
			if remainingChal.Type != prefChalType.typeName {
				continue
			}
			authz.currentChallenge = remainingChal
			authz.currentSolver = c.ChallengeSolvers[authz.currentChallenge.Type]
			if authz.currentSolver != nil {
				authz.remainingChallenges = append(authz.remainingChallenges[:i], authz.remainingChallenges[i+1:]...)
				return nil
			}
			if c.Logger != nil {
				c.Logger.Debug("no solver configured", zap.String("challenge_type", remainingChal.Type))
			}
			break
		}
	}
	return fmt.Errorf("%s: no solvers available for remaining challenges (configured=%v offered=%v remaining=%v)",
		authz.IdentifierValue(), c.enabledChallengeTypes(), authz.listOfferedChallenges(), authz.listRemainingChallenges())
}

func (c *Client) pollAuthorization(ctx context.Context, account acme.Account, authz *authzState, failedChallengeTypes failedChallengeMap) error {
	// In §7.5.1, the spec says:
	//
	// "For challenges where the client can tell when the server has
	// validated the challenge (e.g., by seeing an HTTP or DNS request
	// from the server), the client SHOULD NOT begin polling until it has
	// seen the validation request from the server."
	//
	// However, in practice, this is difficult in the general case because
	// we would need to design some relatively-nuanced concurrency and hope
	// that the solver implementations also get their side right -- and the
	// fact that it's even possible only sometimes makes it harder, because
	// each solver needs a way to signal whether we should wait for its
	// approval. So no, I've decided not to implement that recommendation
	// in this particular library, but any implementations that use the lower
	// ACME API directly are welcome and encouraged to do so where possible.
	var err error
	authz.Authorization, err = c.Client.PollAuthorization(ctx, account, authz.Authorization)

	// if a challenge was attempted (i.e. did not start valid)...
	if authz.currentSolver != nil {
		// increment the statistics on this challenge type before handling error
		preferredChallengesMu.Lock()
		preferredChallenges.increment(authz.currentChallenge.Type, err == nil)
		preferredChallengesMu.Unlock()

		// always clean up the challenge solver after polling, regardless of error
		cleanupErr := authz.currentSolver.CleanUp(ctx, authz.currentChallenge)
		if cleanupErr != nil && c.Logger != nil {
			c.Logger.Error("cleaning up solver",
				zap.String("identifier", authz.IdentifierValue()),
				zap.String("challenge_type", authz.currentChallenge.Type),
				zap.Error(cleanupErr))
		}
		authz.currentSolver = nil // avoid cleaning it up again later
	}

	// finally, handle any error from validating the authz
	if err != nil {
		var problem acme.Problem
		if errors.As(err, &problem) {
			if c.Logger != nil {
				c.Logger.Error("challenge failed",
					zap.String("identifier", authz.IdentifierValue()),
					zap.String("challenge_type", authz.currentChallenge.Type),
					zap.Object("problem", problem))
			}

			failedChallengeTypes.rememberFailedChallenge(authz)

			if c.countAvailableChallenges(authz) > 0 {
				switch problem.Type {
				case acme.ProblemTypeConnection,
					acme.ProblemTypeDNS,
					acme.ProblemTypeServerInternal,
					acme.ProblemTypeUnauthorized,
					acme.ProblemTypeTLS:
					// this error might be recoverable with another challenge type
					return retryableErr{err}
				}
			}
		}
		return fmt.Errorf("[%s] %w", authz.Authorization.IdentifierValue(), err)
	}

	if c.Logger != nil {
		c.Logger.Info("authorization finalized",
			zap.String("identifier", authz.IdentifierValue()),
			zap.String("authz_status", authz.Status))
	}

	return nil
}

func (c *Client) countAvailableChallenges(authz *authzState) int {
	count := 0
	for _, remainingChal := range authz.remainingChallenges {
		if _, ok := c.ChallengeSolvers[remainingChal.Type]; ok {
			count++
		}
	}
	return count
}

func (c *Client) enabledChallengeTypes() []string {
	enabledChallenges := make([]string, 0, len(c.ChallengeSolvers))
	for name, val := range c.ChallengeSolvers {
		if val != nil {
			enabledChallenges = append(enabledChallenges, name)
		}
	}
	return enabledChallenges
}

type authzState struct {
	acme.Authorization
	account             acme.Account
	currentChallenge    acme.Challenge
	currentSolver       Solver
	remainingChallenges []acme.Challenge
}

func (authz authzState) listOfferedChallenges() []string {
	return challengeTypeNames(authz.Challenges)
}

func (authz authzState) listRemainingChallenges() []string {
	return challengeTypeNames(authz.remainingChallenges)
}

func challengeTypeNames(challengeList []acme.Challenge) []string {
	names := make([]string, 0, len(challengeList))
	for _, chal := range challengeList {
		names = append(names, chal.Type)
	}
	return names
}

// TODO: possibly configurable policy? converge to most successful (current) vs. completely random

// challengeHistory is a memory of how successful a challenge type is.
type challengeHistory struct {
	typeName         string
	successes, total int
}

func (ch challengeHistory) successRatio() float64 {
	if ch.total == 0 {
		return 1.0
	}
	return float64(ch.successes) / float64(ch.total)
}

// failedChallengeMap keeps track of failed challenge types per identifier.
type failedChallengeMap map[string][]string

func (fcm failedChallengeMap) rememberFailedChallenge(authz *authzState) {
	idKey := fcm.idKey(authz)
	fcm[idKey] = append(fcm[idKey], authz.currentChallenge.Type)
}

// enqueueUnfailedChallenges enqueues each challenge offered in authz if it
// is not known to have failed for the authz's identifier already.
func (fcm failedChallengeMap) enqueueUnfailedChallenges(authz *authzState) {
	idKey := fcm.idKey(authz)
	for _, chal := range authz.Challenges {
		if !contains(fcm[idKey], chal.Type) {
			authz.remainingChallenges = append(authz.remainingChallenges, chal)
		}
	}
}

func (fcm failedChallengeMap) idKey(authz *authzState) string {
	return authz.Identifier.Type + authz.IdentifierValue()
}

// challengeTypes is a list of challenges we've seen and/or
// used previously. It sorts from most successful to least
// successful, such that most successful challenges are first.
type challengeTypes []challengeHistory

// Len is part of sort.Interface.
func (ct challengeTypes) Len() int { return len(ct) }

// Swap is part of sort.Interface.
func (ct challengeTypes) Swap(i, j int) { ct[i], ct[j] = ct[j], ct[i] }

// Less is part of sort.Interface. It sorts challenge
// types from highest success ratio to lowest.
func (ct challengeTypes) Less(i, j int) bool {
	return ct[i].successRatio() > ct[j].successRatio()
}

func (ct *challengeTypes) addUnique(challengeType string) {
	for _, c := range *ct {
		if c.typeName == challengeType {
			return
		}
	}
	*ct = append(*ct, challengeHistory{typeName: challengeType})
}

func (ct challengeTypes) increment(challengeType string, successful bool) {
	defer sort.Stable(ct) // keep most successful challenges in front
	for i, c := range ct {
		if c.typeName == challengeType {
			ct[i].total++
			if successful {
				ct[i].successes++
			}
			return
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// retryableErr wraps an error that indicates the caller should retry
// the operation; specifically with a different challenge type.
type retryableErr struct{ error }

func (re retryableErr) Unwrap() error { return re.error }

// Keep a list of challenges we've seen offered by servers, ordered by success rate.
var (
	preferredChallenges   challengeTypes
	preferredChallengesMu sync.Mutex
)

// Best practice is to avoid the default RNG source and seed our own;
// custom sources are not safe for concurrent use, hence the mutex.
var (
	randomSource   = weakrand.New(weakrand.NewSource(time.Now().UnixNano()))
	randomSourceMu sync.Mutex
)

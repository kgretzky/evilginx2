// Copyright 2015 Matthew Holt
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

package certmagic

import (
	"context"
	"crypto/x509"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())
}

// acmeClient holds state necessary to perform ACME operations
// for certificate management with an ACME account. Call
// ACMEIssuer.newACMEClientWithAccount() to get a valid one.
type acmeClient struct {
	iss        *ACMEIssuer
	acmeClient *acmez.Client
	account    acme.Account
}

// newACMEClientWithAccount creates an ACME client ready to use with an account, including
// loading one from storage or registering a new account with the CA if necessary. If
// useTestCA is true, am.TestCA will be used if set; otherwise, the primary CA will be used.
func (iss *ACMEIssuer) newACMEClientWithAccount(ctx context.Context, useTestCA, interactive bool) (*acmeClient, error) {
	// first, get underlying ACME client
	client, err := iss.newACMEClient(useTestCA)
	if err != nil {
		return nil, err
	}

	// look up or create the ACME account
	var account acme.Account
	if iss.AccountKeyPEM != "" {
		account, err = iss.GetAccount(ctx, []byte(iss.AccountKeyPEM))
	} else {
		account, err = iss.getAccount(ctx, client.Directory, iss.getEmail())
	}
	if err != nil {
		return nil, fmt.Errorf("getting ACME account: %v", err)
	}

	// register account if it is new
	if account.Status == "" {
		if iss.NewAccountFunc != nil {
			// obtain lock here, since NewAccountFunc calls happen concurrently and they typically read and change the issuer
			iss.mu.Lock()
			account, err = iss.NewAccountFunc(ctx, iss, account)
			iss.mu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("account pre-registration callback: %v", err)
			}
		}

		// agree to terms
		if interactive {
			if !iss.isAgreed() {
				var termsURL string
				dir, err := client.GetDirectory(ctx)
				if err != nil {
					return nil, fmt.Errorf("getting directory: %w", err)
				}
				if dir.Meta != nil {
					termsURL = dir.Meta.TermsOfService
				}
				if termsURL != "" {
					agreed := iss.askUserAgreement(termsURL)
					if !agreed {
						return nil, fmt.Errorf("user must agree to CA terms")
					}
					iss.mu.Lock()
					iss.agreed = agreed
					iss.mu.Unlock()
				}
			}
		} else {
			// can't prompt a user who isn't there; they should
			// have reviewed the terms beforehand
			iss.mu.Lock()
			iss.agreed = true
			iss.mu.Unlock()
		}
		account.TermsOfServiceAgreed = iss.isAgreed()

		// associate account with external binding, if configured
		if iss.ExternalAccount != nil {
			err := account.SetExternalAccountBinding(ctx, client.Client, *iss.ExternalAccount)
			if err != nil {
				return nil, err
			}
		}

		// create account
		account, err = client.NewAccount(ctx, account)
		if err != nil {
			return nil, fmt.Errorf("registering account %v with server: %w", account.Contact, err)
		}

		// persist the account to storage
		err = iss.saveAccount(ctx, client.Directory, account)
		if err != nil {
			return nil, fmt.Errorf("could not save account %v: %v", account.Contact, err)
		}
	}

	c := &acmeClient{
		iss:        iss,
		acmeClient: client,
		account:    account,
	}

	return c, nil
}

// newACMEClient creates a new underlying ACME client using the settings in am,
// independent of any particular ACME account. If useTestCA is true, am.TestCA
// will be used if it is set; otherwise, the primary CA will be used.
func (iss *ACMEIssuer) newACMEClient(useTestCA bool) (*acmez.Client, error) {
	// ensure defaults are filled in
	var caURL string
	if useTestCA {
		caURL = iss.TestCA
	}
	if caURL == "" {
		caURL = iss.CA
	}
	if caURL == "" {
		caURL = DefaultACME.CA
	}
	certObtainTimeout := iss.CertObtainTimeout
	if certObtainTimeout == 0 {
		certObtainTimeout = DefaultACME.CertObtainTimeout
	}

	// ensure endpoint is secure (assume HTTPS if scheme is missing)
	if !strings.Contains(caURL, "://") {
		caURL = "https://" + caURL
	}
	u, err := url.Parse(caURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && !isLoopback(u.Host) && !isInternal(u.Host) {
		return nil, fmt.Errorf("%s: insecure CA URL (HTTPS required)", caURL)
	}

	client := &acmez.Client{
		Client: &acme.Client{
			Directory:   caURL,
			PollTimeout: certObtainTimeout,
			UserAgent:   buildUAString(),
			HTTPClient:  iss.httpClient,
		},
		ChallengeSolvers: make(map[string]acmez.Solver),
	}
	client.Logger = iss.Logger.Named("acme_client")

	// configure challenges (most of the time, DNS challenge is
	// exclusive of other ones because it is usually only used
	// in situations where the default challenges would fail)
	if iss.DNS01Solver == nil {
		// enable HTTP-01 challenge
		if !iss.DisableHTTPChallenge {
			useHTTPPort := HTTPChallengePort
			if HTTPPort > 0 && HTTPPort != HTTPChallengePort {
				useHTTPPort = HTTPPort
			}
			if iss.AltHTTPPort > 0 {
				useHTTPPort = iss.AltHTTPPort
			}
			client.ChallengeSolvers[acme.ChallengeTypeHTTP01] = distributedSolver{
				storage:                iss.config.Storage,
				storageKeyIssuerPrefix: iss.storageKeyCAPrefix(client.Directory),
				solver: &httpSolver{
					acmeIssuer: iss,
					address:    net.JoinHostPort(iss.ListenHost, strconv.Itoa(useHTTPPort)),
				},
			}
		}

		// enable TLS-ALPN-01 challenge
		if !iss.DisableTLSALPNChallenge {
			useTLSALPNPort := TLSALPNChallengePort
			if HTTPSPort > 0 && HTTPSPort != TLSALPNChallengePort {
				useTLSALPNPort = HTTPSPort
			}
			if iss.AltTLSALPNPort > 0 {
				useTLSALPNPort = iss.AltTLSALPNPort
			}
			client.ChallengeSolvers[acme.ChallengeTypeTLSALPN01] = distributedSolver{
				storage:                iss.config.Storage,
				storageKeyIssuerPrefix: iss.storageKeyCAPrefix(client.Directory),
				solver: &tlsALPNSolver{
					config:  iss.config,
					address: net.JoinHostPort(iss.ListenHost, strconv.Itoa(useTLSALPNPort)),
				},
			}
		}
	} else {
		// use DNS challenge exclusively
		client.ChallengeSolvers[acme.ChallengeTypeDNS01] = iss.DNS01Solver
	}

	// wrap solvers in our wrapper so that we can keep track of challenge
	// info: this is useful for solving challenges globally as a process;
	// for example, usually there is only one process that can solve the
	// HTTP and TLS-ALPN challenges, and only one server in that process
	// that can bind the necessary port(s), so if a server listening on
	// a different port needed a certificate, it would have to know about
	// the other server listening on that port, and somehow convey its
	// challenge info or share its config, but this isn't always feasible;
	// what the wrapper does is it accesses a global challenge memory so
	// that unrelated servers in this process can all solve each others'
	// challenges without having to know about each other - Caddy's admin
	// endpoint uses this functionality since it and the HTTP/TLS modules
	// do not know about each other
	// (doing this here in a separate loop ensures that even if we expose
	// solver config to users later, we will even wrap their own solvers)
	for name, solver := range client.ChallengeSolvers {
		client.ChallengeSolvers[name] = solverWrapper{solver}
	}

	return client, nil
}

func (c *acmeClient) throttle(ctx context.Context, names []string) error {
	email := c.iss.getEmail()

	// throttling is scoped to CA + account email
	rateLimiterKey := c.acmeClient.Directory + "," + email
	rateLimitersMu.Lock()
	rl, ok := rateLimiters[rateLimiterKey]
	if !ok {
		rl = NewRateLimiter(RateLimitEvents, RateLimitEventsWindow)
		rateLimiters[rateLimiterKey] = rl
		// TODO: stop rate limiter when it is garbage-collected...
	}
	rateLimitersMu.Unlock()
	c.iss.Logger.Info("waiting on internal rate limiter",
		zap.Strings("identifiers", names),
		zap.String("ca", c.acmeClient.Directory),
		zap.String("account", email),
	)
	err := rl.Wait(ctx)
	if err != nil {
		return err
	}
	c.iss.Logger.Info("done waiting on internal rate limiter",
		zap.Strings("identifiers", names),
		zap.String("ca", c.acmeClient.Directory),
		zap.String("account", email),
	)
	return nil
}

func (c *acmeClient) usingTestCA() bool {
	return c.iss.TestCA != "" && c.acmeClient.Directory == c.iss.TestCA
}

func (c *acmeClient) revoke(ctx context.Context, cert *x509.Certificate, reason int) error {
	return c.acmeClient.RevokeCertificate(ctx, c.account,
		cert, c.account.PrivateKey, reason)
}

func buildUAString() string {
	ua := "CertMagic"
	if UserAgent != "" {
		ua = UserAgent + " " + ua
	}
	return ua
}

// These internal rate limits are designed to prevent accidentally
// firehosing a CA's ACME endpoints. They are not intended to
// replace or replicate the CA's actual rate limits.
//
// Let's Encrypt's rate limits can be found here:
// https://letsencrypt.org/docs/rate-limits/
//
// Currently (as of December 2019), Let's Encrypt's most relevant
// rate limit for large deployments is 300 new orders per account
// per 3 hours (on average, or best case, that's about 1 every 36
// seconds, or 2 every 72 seconds, etc.); but it's not reasonable
// to try to assume that our internal state is the same as the CA's
// (due to process restarts, config changes, failed validations,
// etc.) and ultimately, only the CA's actual rate limiter is the
// authority. Thus, our own rate limiters do not attempt to enforce
// external rate limits. Doing so causes problems when the domains
// are not in our control (i.e. serving customer sites) and/or lots
// of domains fail validation: they clog our internal rate limiter
// and nearly starve out (or at least slow down) the other domains
// that need certificates. Failed transactions are already retried
// with exponential backoff, so adding in rate limiting can slow
// things down even more.
//
// Instead, the point of our internal rate limiter is to avoid
// hammering the CA's endpoint when there are thousands or even
// millions of certificates under management. Our goal is to
// allow small bursts in a relatively short timeframe so as to
// not block any one domain for too long, without unleashing
// thousands of requests to the CA at once.
var (
	rateLimiters   = make(map[string]*RingBufferRateLimiter)
	rateLimitersMu sync.RWMutex

	// RateLimitEvents is how many new events can be allowed
	// in RateLimitEventsWindow.
	RateLimitEvents = 10

	// RateLimitEventsWindow is the size of the sliding
	// window that throttles events.
	RateLimitEventsWindow = 10 * time.Second
)

// Some default values passed down to the underlying ACME client.
var (
	UserAgent   string
	HTTPTimeout = 30 * time.Second
)

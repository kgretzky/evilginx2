package certmagic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// ACMEIssuer gets certificates using ACME. It implements the PreChecker,
// Issuer, and Revoker interfaces.
//
// It is NOT VALID to use an ACMEIssuer without calling NewACMEIssuer().
// It fills in any default values from DefaultACME as well as setting up
// internal state that is necessary for valid use. Always call
// NewACMEIssuer() to get a valid ACMEIssuer value.
type ACMEIssuer struct {
	// The endpoint of the directory for the ACME
	// CA we are to use
	CA string

	// TestCA is the endpoint of the directory for
	// an ACME CA to use to test domain validation,
	// but any certs obtained from this CA are
	// discarded
	TestCA string

	// The email address to use when creating or
	// selecting an existing ACME server account
	Email string

	// The PEM-encoded private key of the ACME
	// account to use; only needed if the account
	// is already created on the server and
	// can be looked up with the ACME protocol
	AccountKeyPEM string

	// Set to true if agreed to the CA's
	// subscriber agreement
	Agreed bool

	// An optional external account to associate
	// with this ACME account
	ExternalAccount *acme.EAB

	// Disable all HTTP challenges
	DisableHTTPChallenge bool

	// Disable all TLS-ALPN challenges
	DisableTLSALPNChallenge bool

	// The host (ONLY the host, not port) to listen
	// on if necessary to start a listener to solve
	// an ACME challenge
	ListenHost string

	// The alternate port to use for the ACME HTTP
	// challenge; if non-empty, this port will be
	// used instead of HTTPChallengePort to spin up
	// a listener for the HTTP challenge
	AltHTTPPort int

	// The alternate port to use for the ACME
	// TLS-ALPN challenge; the system must forward
	// TLSALPNChallengePort to this port for
	// challenge to succeed
	AltTLSALPNPort int

	// The solver for the dns-01 challenge;
	// usually this is a DNS01Solver value
	// from this package
	DNS01Solver acmez.Solver

	// TrustedRoots specifies a pool of root CA
	// certificates to trust when communicating
	// over a network to a peer.
	TrustedRoots *x509.CertPool

	// The maximum amount of time to allow for
	// obtaining a certificate. If empty, the
	// default from the underlying ACME lib is
	// used. If set, it must not be too low so
	// as to cancel challenges too early.
	CertObtainTimeout time.Duration

	// Address of custom DNS resolver to be used
	// when communicating with ACME server
	Resolver string

	// Callback function that is called before a
	// new ACME account is registered with the CA;
	// it allows for last-second config changes
	// of the ACMEIssuer and the Account.
	// (TODO: this feature is still EXPERIMENTAL and subject to change)
	NewAccountFunc func(context.Context, *ACMEIssuer, acme.Account) (acme.Account, error)

	// Preferences for selecting alternate
	// certificate chains
	PreferredChains ChainPreference

	// Set a logger to configure logging; a default
	// logger must always be set; if no logging is
	// desired, set this to zap.NewNop().
	Logger *zap.Logger

	// Set a http proxy to use when issuing a certificate.
	// Default is http.ProxyFromEnvironment
	HTTPProxy func(*http.Request) (*url.URL, error)

	config     *Config
	httpClient *http.Client

	// Some fields are changed on-the-fly during
	// certificate management. For example, the
	// email might be implicitly discovered if not
	// explicitly configured, and agreement might
	// happen during the flow. Changing the exported
	// fields field is racey (issue #195) so we
	// control unexported fields that we can
	// synchronize properly.
	email  string
	agreed bool
	mu     *sync.Mutex // protects the above grouped fields, as well as entire struct during NewAccountFunc calls
}

// NewACMEIssuer constructs a valid ACMEIssuer based on a template
// configuration; any empty values will be filled in by defaults in
// DefaultACME, and if any required values are still empty, sensible
// defaults will be used.
//
// Typically, you'll create the Config first with New() or NewDefault(),
// then call NewACMEIssuer(), then assign the return value to the Issuers
// field of the Config.
func NewACMEIssuer(cfg *Config, template ACMEIssuer) *ACMEIssuer {
	if cfg == nil {
		panic("cannot make valid ACMEIssuer without an associated CertMagic config")
	}
	if template.CA == "" {
		template.CA = DefaultACME.CA
	}
	if template.TestCA == "" && template.CA == DefaultACME.CA {
		// only use the default test CA if the CA is also
		// the default CA; no point in testing against
		// Let's Encrypt's staging server if we are not
		// using their production server too
		template.TestCA = DefaultACME.TestCA
	}
	if template.Email == "" {
		template.Email = DefaultACME.Email
	}
	if template.AccountKeyPEM == "" {
		template.AccountKeyPEM = DefaultACME.AccountKeyPEM
	}
	if !template.Agreed {
		template.Agreed = DefaultACME.Agreed
	}
	if template.ExternalAccount == nil {
		template.ExternalAccount = DefaultACME.ExternalAccount
	}
	if !template.DisableHTTPChallenge {
		template.DisableHTTPChallenge = DefaultACME.DisableHTTPChallenge
	}
	if !template.DisableTLSALPNChallenge {
		template.DisableTLSALPNChallenge = DefaultACME.DisableTLSALPNChallenge
	}
	if template.ListenHost == "" {
		template.ListenHost = DefaultACME.ListenHost
	}
	if template.AltHTTPPort == 0 {
		template.AltHTTPPort = DefaultACME.AltHTTPPort
	}
	if template.AltTLSALPNPort == 0 {
		template.AltTLSALPNPort = DefaultACME.AltTLSALPNPort
	}
	if template.DNS01Solver == nil {
		template.DNS01Solver = DefaultACME.DNS01Solver
	}
	if template.TrustedRoots == nil {
		template.TrustedRoots = DefaultACME.TrustedRoots
	}
	if template.CertObtainTimeout == 0 {
		template.CertObtainTimeout = DefaultACME.CertObtainTimeout
	}
	if template.Resolver == "" {
		template.Resolver = DefaultACME.Resolver
	}
	if template.NewAccountFunc == nil {
		template.NewAccountFunc = DefaultACME.NewAccountFunc
	}
	if template.Logger == nil {
		template.Logger = DefaultACME.Logger
	}

	// absolutely do not allow a nil logger; that would panic
	if template.Logger == nil {
		template.Logger = defaultLogger
	}

	if template.HTTPProxy == nil {
		template.HTTPProxy = DefaultACME.HTTPProxy
	}
	if template.HTTPProxy == nil {
		template.HTTPProxy = http.ProxyFromEnvironment
	}

	template.config = cfg
	template.mu = new(sync.Mutex)

	// set up the dialer and transport / HTTP client
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 2 * time.Minute,
	}
	if template.Resolver != "" {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{
					Timeout: 15 * time.Second,
				}).DialContext(ctx, network, template.Resolver)
			},
		}
	}
	transport := &http.Transport{
		Proxy:                 template.HTTPProxy,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   30 * time.Second, // increase to 30s requested in #175
		ResponseHeaderTimeout: 30 * time.Second, // increase to 30s requested in #175
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if template.TrustedRoots != nil {
		transport.TLSClientConfig = &tls.Config{
			RootCAs: template.TrustedRoots,
		}
	}
	template.httpClient = &http.Client{
		Transport: transport,
		Timeout:   HTTPTimeout,
	}

	return &template
}

// IssuerKey returns the unique issuer key for the
// confgured CA endpoint.
func (am *ACMEIssuer) IssuerKey() string {
	return am.issuerKey(am.CA)
}

func (*ACMEIssuer) issuerKey(ca string) string {
	key := ca
	if caURL, err := url.Parse(key); err == nil {
		key = caURL.Host
		if caURL.Path != "" {
			// keep the path, but make sure it's a single
			// component (i.e. no forward slashes, and for
			// good measure, no backward slashes either)
			const hyphen = "-"
			repl := strings.NewReplacer(
				"/", hyphen,
				"\\", hyphen,
			)
			path := strings.Trim(repl.Replace(caURL.Path), hyphen)
			if path != "" {
				key += hyphen + path
			}
		}
	}
	return key
}

func (iss *ACMEIssuer) getEmail() string {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return iss.email
}

func (iss *ACMEIssuer) isAgreed() bool {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return iss.agreed
}

// PreCheck performs a few simple checks before obtaining or
// renewing a certificate with ACME, and returns whether this
// batch is eligible for certificates if using Let's Encrypt.
// It also ensures that an email address is available.
func (am *ACMEIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	publicCA := strings.Contains(am.CA, "api.letsencrypt.org") || strings.Contains(am.CA, "acme.zerossl.com") || strings.Contains(am.CA, "api.pki.goog")
	if publicCA {
		for _, name := range names {
			if !SubjectQualifiesForPublicCert(name) {
				return fmt.Errorf("subject does not qualify for a public certificate: %s", name)
			}
		}
	}
	return am.setEmail(ctx, interactive)
}

// Issue implements the Issuer interface. It obtains a certificate for the given csr using
// the ACME configuration am.
func (am *ACMEIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	if am.config == nil {
		panic("missing config pointer (must use NewACMEIssuer)")
	}

	var isRetry bool
	if attempts, ok := ctx.Value(AttemptsCtxKey).(*int); ok {
		isRetry = *attempts > 0
	}

	cert, usedTestCA, err := am.doIssue(ctx, csr, isRetry)
	if err != nil {
		return nil, err
	}

	// important to note that usedTestCA is not necessarily the same as isRetry
	// (usedTestCA can be true if the main CA and the test CA happen to be the same)
	if isRetry && usedTestCA && am.CA != am.TestCA {
		// succeeded with testing endpoint, so try again with production endpoint
		// (only if the production endpoint is different from the testing endpoint)
		// TODO: This logic is imperfect and could benefit from some refinement.
		// The two CA endpoints likely have different states, which could cause one
		// to succeed and the other to fail, even if it's not a validation error.
		// Two common cases would be:
		// 1) Rate limiter state. This is more likely to cause prod to fail while
		// staging succeeds, since prod usually has tighter rate limits. Thus, if
		// initial attempt failed in prod due to rate limit, first retry (on staging)
		// might succeed, and then trying prod again right way would probably still
		// fail; normally this would terminate retries but the right thing to do in
		// this case is to back off and retry again later. We could refine this logic
		// to stick with the production endpoint on retries unless the error changes.
		// 2) Cached authorizations state. If a domain validates successfully with
		// one endpoint, but then the other endpoint is used, it might fail, e.g. if
		// DNS was just changed or is still propagating. In this case, the second CA
		// should continue to be retried with backoff, without switching back to the
		// other endpoint. This is more likely to happen if a user is testing with
		// the staging CA as the main CA, then changes their configuration once they
		// think they are ready for the production endpoint.
		cert, _, err = am.doIssue(ctx, csr, false)
		if err != nil {
			// succeeded with test CA but failed just now with the production CA;
			// either we are observing differing internal states of each CA that will
			// work out with time, or there is a bug/misconfiguration somewhere
			// externally; it is hard to tell which! one easy cue is whether the
			// error is specifically a 429 (Too Many Requests); if so, we should
			// probably keep retrying
			var problem acme.Problem
			if errors.As(err, &problem) {
				if problem.Status == http.StatusTooManyRequests {
					// DON'T abort retries; the test CA succeeded (even
					// if it's cached, it recently succeeded!) so we just
					// need to keep trying (with backoff) until this CA's
					// rate limits expire...
					// TODO: as mentioned in comment above, we would benefit
					// by pinning the main CA at this point instead of
					// needlessly retrying with the test CA first each time
					return nil, err
				}
			}
			return nil, ErrNoRetry{err}
		}
	}

	return cert, err
}

func (am *ACMEIssuer) doIssue(ctx context.Context, csr *x509.CertificateRequest, useTestCA bool) (*IssuedCertificate, bool, error) {
	client, err := am.newACMEClientWithAccount(ctx, useTestCA, false)
	if err != nil {
		return nil, false, err
	}
	usingTestCA := client.usingTestCA()

	nameSet := namesFromCSR(csr)

	if !useTestCA {
		if err := client.throttle(ctx, nameSet); err != nil {
			return nil, usingTestCA, err
		}
	}

	certChains, err := client.acmeClient.ObtainCertificateUsingCSR(ctx, client.account, csr)
	if err != nil {
		return nil, usingTestCA, fmt.Errorf("%v %w (ca=%s)", nameSet, err, client.acmeClient.Directory)
	}
	if len(certChains) == 0 {
		return nil, usingTestCA, fmt.Errorf("no certificate chains")
	}

	preferredChain := am.selectPreferredChain(certChains)

	ic := &IssuedCertificate{
		Certificate: preferredChain.ChainPEM,
		Metadata:    preferredChain,
	}

	return ic, usingTestCA, nil
}

// selectPreferredChain sorts and then filters the certificate chains to find the optimal
// chain preferred by the client. If there's only one chain, that is returned without any
// processing. If there are no matches, the first chain is returned.
func (am *ACMEIssuer) selectPreferredChain(certChains []acme.Certificate) acme.Certificate {
	if len(certChains) == 1 {
		if len(am.PreferredChains.AnyCommonName) > 0 || len(am.PreferredChains.RootCommonName) > 0 {
			am.Logger.Debug("there is only one chain offered; selecting it regardless of preferences",
				zap.String("chain_url", certChains[0].URL))
		}
		return certChains[0]
	}

	if am.PreferredChains.Smallest != nil {
		if *am.PreferredChains.Smallest {
			sort.Slice(certChains, func(i, j int) bool {
				return len(certChains[i].ChainPEM) < len(certChains[j].ChainPEM)
			})
		} else {
			sort.Slice(certChains, func(i, j int) bool {
				return len(certChains[i].ChainPEM) > len(certChains[j].ChainPEM)
			})
		}
	}

	if len(am.PreferredChains.AnyCommonName) > 0 || len(am.PreferredChains.RootCommonName) > 0 {
		// in order to inspect, we need to decode their PEM contents
		decodedChains := make([][]*x509.Certificate, len(certChains))
		for i, chain := range certChains {
			certs, err := parseCertsFromPEMBundle(chain.ChainPEM)
			if err != nil {
				am.Logger.Error("unable to parse PEM certificate chain",
					zap.Int("chain", i),
					zap.Error(err))
				continue
			}
			decodedChains[i] = certs
		}

		if len(am.PreferredChains.AnyCommonName) > 0 {
			for _, prefAnyCN := range am.PreferredChains.AnyCommonName {
				for i, chain := range decodedChains {
					for _, cert := range chain {
						if cert.Issuer.CommonName == prefAnyCN {
							am.Logger.Debug("found preferred certificate chain by issuer common name",
								zap.String("preference", prefAnyCN),
								zap.Int("chain", i))
							return certChains[i]
						}
					}
				}
			}
		}

		if len(am.PreferredChains.RootCommonName) > 0 {
			for _, prefRootCN := range am.PreferredChains.RootCommonName {
				for i, chain := range decodedChains {
					if chain[len(chain)-1].Issuer.CommonName == prefRootCN {
						am.Logger.Debug("found preferred certificate chain by root common name",
							zap.String("preference", prefRootCN),
							zap.Int("chain", i))
						return certChains[i]
					}
				}
			}
		}

		am.Logger.Warn("did not find chain matching preferences; using first")
	}

	return certChains[0]
}

// Revoke implements the Revoker interface. It revokes the given certificate.
func (am *ACMEIssuer) Revoke(ctx context.Context, cert CertificateResource, reason int) error {
	client, err := am.newACMEClientWithAccount(ctx, false, false)
	if err != nil {
		return err
	}

	certs, err := parseCertsFromPEMBundle(cert.CertificatePEM)
	if err != nil {
		return err
	}

	return client.revoke(ctx, certs[0], reason)
}

// ChainPreference describes the client's preferred certificate chain,
// useful if the CA offers alternate chains. The first matching chain
// will be selected.
type ChainPreference struct {
	// Prefer chains with the fewest number of bytes.
	Smallest *bool

	// Select first chain having a root with one of
	// these common names.
	RootCommonName []string

	// Select first chain that has any issuer with one
	// of these common names.
	AnyCommonName []string
}

// DefaultACME specifies default settings to use for ACMEIssuers.
// Using this value is optional but can be convenient.
var DefaultACME = ACMEIssuer{
	CA:        LetsEncryptProductionCA,
	TestCA:    LetsEncryptStagingCA,
	Logger:    defaultLogger,
	HTTPProxy: http.ProxyFromEnvironment,
}

// Some well-known CA endpoints available to use.
const (
	LetsEncryptStagingCA    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	LetsEncryptProductionCA = "https://acme-v02.api.letsencrypt.org/directory"
	ZeroSSLProductionCA     = "https://acme.zerossl.com/v2/DV90"
)

// prefixACME is the storage key prefix used for ACME-specific assets.
const prefixACME = "acme"

// Interface guards
var (
	_ PreChecker = (*ACMEIssuer)(nil)
	_ Issuer     = (*ACMEIssuer)(nil)
	_ Revoker    = (*ACMEIssuer)(nil)
)

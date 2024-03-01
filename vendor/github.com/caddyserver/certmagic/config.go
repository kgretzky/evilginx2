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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	weakrand "math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/idna"
)

// Config configures a certificate manager instance.
// An empty Config is not valid: use New() to obtain
// a valid Config.
type Config struct {
	// How much of a certificate's lifetime becomes the
	// renewal window, which is the span of time at the
	// end of the certificate's validity period in which
	// it should be renewed; for most certificates, the
	// global default is good, but for extremely short-
	// lived certs, you may want to raise this to ~0.5.
	RenewalWindowRatio float64

	// An optional event callback clients can set
	// to subscribe to certain things happening
	// internally by this config; invocations are
	// synchronous, so make them return quickly!
	// Functions should honor context cancellation.
	//
	// An error should only be returned to advise
	// the emitter to abort or cancel an upcoming
	// event. Some events, especially those that have
	// already happened, cannot be aborted. For example,
	// cert_obtaining can be canceled, but
	// cert_obtained cannot. Emitters may choose to
	// ignore returned errors.
	OnEvent func(ctx context.Context, event string, data map[string]any) error

	// DefaultServerName specifies a server name
	// to use when choosing a certificate if the
	// ClientHello's ServerName field is empty.
	DefaultServerName string

	// FallbackServerName specifies a server name
	// to use when choosing a certificate if the
	// ClientHello's ServerName field doesn't match
	// any available certificate.
	// EXPERIMENTAL: Subject to change or removal.
	FallbackServerName string

	// The state needed to operate on-demand TLS;
	// if non-nil, on-demand TLS is enabled and
	// certificate operations are deferred to
	// TLS handshakes (or as-needed).
	// TODO: Can we call this feature "Reactive/Lazy/Passive TLS" instead?
	OnDemand *OnDemandConfig

	// Adds the must staple TLS extension to the CSR.
	MustStaple bool

	// Sources for getting new, managed certificates;
	// the default Issuer is ACMEIssuer. If multiple
	// issuers are specified, they will be tried in
	// turn until one succeeds.
	Issuers []Issuer

	// How to select which issuer to use.
	// Default: UseFirstIssuer (subject to change).
	IssuerPolicy IssuerPolicy

	// If true, private keys already existing in storage
	// will be reused. Otherwise, a new key will be
	// created for every new certificate to mitigate
	// pinning and reduce the scope of key compromise.
	// Default: false (do not reuse keys).
	ReusePrivateKeys bool

	// The source of new private keys for certificates;
	// the default KeySource is StandardKeyGenerator.
	KeySource KeyGenerator

	// CertSelection chooses one of the certificates
	// with which the ClientHello will be completed;
	// if not set, DefaultCertificateSelector will
	// be used.
	CertSelection CertificateSelector

	// OCSP configures how OCSP is handled. By default,
	// OCSP responses are fetched for every certificate
	// with a responder URL, and cached on disk. Changing
	// these defaults is STRONGLY discouraged unless you
	// have a compelling reason to put clients at greater
	// risk and reduce their privacy.
	OCSP OCSPConfig

	// The storage to access when storing or loading
	// TLS assets. Default is the local file system.
	Storage Storage

	// CertMagic will verify the storage configuration
	// is acceptable before obtaining a certificate
	// to avoid information loss after an expensive
	// operation. If you are absolutely 100% sure your
	// storage is properly configured and has sufficient
	// space, you can disable this check to reduce I/O
	// if that is expensive for you.
	// EXPERIMENTAL: Option subject to change or removal.
	DisableStorageCheck bool

	// Set a logger to enable logging. If not set,
	// a default logger will be created.
	Logger *zap.Logger

	// required pointer to the in-memory cert cache
	certCache *Cache
}

// NewDefault makes a valid config based on the package
// Default config. Most users will call this function
// instead of New() since most use cases require only a
// single config for any and all certificates.
//
// If your requirements are more advanced (for example,
// multiple configs depending on the certificate), then use
// New() instead. (You will need to make your own Cache
// first.) If you only need a single Config to manage your
// certs (even if that config changes, as long as it is the
// only one), customize the Default package variable before
// calling NewDefault().
//
// All calls to NewDefault() will return configs that use the
// same, default certificate cache. All configs returned
// by NewDefault() are based on the values of the fields of
// Default at the time it is called.
//
// This is the only way to get a config that uses the
// default certificate cache.
func NewDefault() *Config {
	defaultCacheMu.Lock()
	if defaultCache == nil {
		defaultCache = NewCache(CacheOptions{
			// the cache will likely need to renew certificates,
			// so it will need to know how to do that, which
			// depends on the certificate being managed and which
			// can change during the lifetime of the cache; this
			// callback makes it possible to get the latest and
			// correct config with which to manage the cert,
			// but if the user does not provide one, we can only
			// assume that we are to use the default config
			GetConfigForCert: func(Certificate) (*Config, error) {
				return NewDefault(), nil
			},
			Logger: Default.Logger,
		})
	}
	certCache := defaultCache
	defaultCacheMu.Unlock()

	return newWithCache(certCache, Default)
}

// New makes a new, valid config based on cfg and
// uses the provided certificate cache. certCache
// MUST NOT be nil or this function will panic.
//
// Use this method when you have an advanced use case
// that requires a custom certificate cache and config
// that may differ from the Default. For example, if
// not all certificates are managed/renewed the same
// way, you need to make your own Cache value with a
// GetConfigForCert callback that returns the correct
// configuration for each certificate. However, for
// the vast majority of cases, there will be only a
// single Config, thus the default cache (which always
// uses the default Config) and default config will
// suffice, and you should use NewDefault() instead.
func New(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("a certificate cache is required")
	}
	certCache.optionsMu.RLock()
	getConfigForCert := certCache.options.GetConfigForCert
	defer certCache.optionsMu.RUnlock()
	if getConfigForCert == nil {
		panic("cache must have GetConfigForCert set in its options")
	}
	return newWithCache(certCache, cfg)
}

// newWithCache ensures that cfg is a valid config by populating
// zero-value fields from the Default Config. If certCache is
// nil, this function panics.
func newWithCache(certCache *Cache, cfg Config) *Config {
	if certCache == nil {
		panic("cannot make a valid config without a pointer to a certificate cache")
	}

	if cfg.OnDemand == nil {
		cfg.OnDemand = Default.OnDemand
	}
	if !cfg.MustStaple {
		cfg.MustStaple = Default.MustStaple
	}
	if cfg.Issuers == nil {
		cfg.Issuers = Default.Issuers
		if cfg.Issuers == nil {
			// at least one issuer is absolutely required if not nil
			cfg.Issuers = []Issuer{NewACMEIssuer(&cfg, DefaultACME)}
		}
	}
	if cfg.RenewalWindowRatio == 0 {
		cfg.RenewalWindowRatio = Default.RenewalWindowRatio
	}
	if cfg.OnEvent == nil {
		cfg.OnEvent = Default.OnEvent
	}
	if cfg.KeySource == nil {
		cfg.KeySource = Default.KeySource
	}
	if cfg.DefaultServerName == "" {
		cfg.DefaultServerName = Default.DefaultServerName
	}
	if cfg.FallbackServerName == "" {
		cfg.FallbackServerName = Default.FallbackServerName
	}
	if cfg.Storage == nil {
		cfg.Storage = Default.Storage
	}
	if cfg.Logger == nil {
		cfg.Logger = Default.Logger
	}

	// absolutely don't allow a nil storage,
	// because that would make almost anything
	// a config can do pointless
	if cfg.Storage == nil {
		cfg.Storage = defaultFileStorage
	}

	// absolutely don't allow a nil logger either,
	// because that would result in panics
	if cfg.Logger == nil {
		cfg.Logger = defaultLogger
	}

	cfg.certCache = certCache

	return &cfg
}

// ManageSync causes the certificates for domainNames to be managed
// according to cfg. If cfg.OnDemand is not nil, then this simply
// allowlists the domain names and defers the certificate operations
// to when they are needed. Otherwise, the certificates for each
// name are loaded from storage or obtained from the CA if not already
// in the cache associated with the Config. If loaded from storage,
// they are renewed if they are expiring or expired. It then caches
// the certificate in memory and is prepared to serve them up during
// TLS handshakes. To change how an already-loaded certificate is
// managed, update the cache options relating to getting a config for
// a cert.
//
// Note that name allowlisting for on-demand management only takes
// effect if cfg.OnDemand.DecisionFunc is not set (is nil); it will
// not overwrite an existing DecisionFunc, nor will it overwrite
// its decision; i.e. the implicit allowlist is only used if no
// DecisionFunc is set.
//
// This method is synchronous, meaning that certificates for all
// domainNames must be successfully obtained (or renewed) before
// it returns. It returns immediately on the first error for any
// of the given domainNames. This behavior is recommended for
// interactive use (i.e. when an administrator is present) so
// that errors can be reported and fixed immediately.
func (cfg *Config) ManageSync(ctx context.Context, domainNames []string) error {
	return cfg.manageAll(ctx, domainNames, false)
}

// ManageAsync is the same as ManageSync, except that ACME
// operations are performed asynchronously (in the background).
// This method returns before certificates are ready. It is
// crucial that the administrator monitors the logs and is
// notified of any errors so that corrective action can be
// taken as soon as possible. Any errors returned from this
// method occurred before ACME transactions started.
//
// As long as logs are monitored, this method is typically
// recommended for non-interactive environments.
//
// If there are failures loading, obtaining, or renewing a
// certificate, it will be retried with exponential backoff
// for up to about 30 days, with a maximum interval of about
// 24 hours. Cancelling ctx will cancel retries and shut down
// any goroutines spawned by ManageAsync.
func (cfg *Config) ManageAsync(ctx context.Context, domainNames []string) error {
	return cfg.manageAll(ctx, domainNames, true)
}

// ClientCredentials returns a list of TLS client certificate chains for the given identifiers.
// The return value can be used in a tls.Config to enable client authentication using managed certificates.
// Any certificates that need to be obtained or renewed for these identifiers will be managed accordingly.
func (cfg *Config) ClientCredentials(ctx context.Context, identifiers []string) ([]tls.Certificate, error) {
	err := cfg.manageAll(ctx, identifiers, false)
	if err != nil {
		return nil, err
	}
	var chains []tls.Certificate
	for _, id := range identifiers {
		certRes, err := cfg.loadCertResourceAnyIssuer(ctx, id)
		if err != nil {
			return chains, err
		}
		chain, err := tls.X509KeyPair(certRes.CertificatePEM, certRes.PrivateKeyPEM)
		if err != nil {
			return chains, err
		}
		chains = append(chains, chain)
	}
	return chains, nil
}

func (cfg *Config) manageAll(ctx context.Context, domainNames []string, async bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.OnDemand != nil && cfg.OnDemand.hostAllowlist == nil {
		cfg.OnDemand.hostAllowlist = make(map[string]struct{})
	}

	for _, domainName := range domainNames {
		// if on-demand is configured, defer obtain and renew operations
		if cfg.OnDemand != nil {
			cfg.OnDemand.hostAllowlist[normalizedName(domainName)] = struct{}{}
			continue
		}

		// TODO: consider doing this in a goroutine if async, to utilize multiple cores while loading certs
		// otherwise, begin management immediately
		err := cfg.manageOne(ctx, domainName, async)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cfg *Config) manageOne(ctx context.Context, domainName string, async bool) error {
	// if certificate is already being managed, nothing to do; maintenance will continue
	certs := cfg.certCache.getAllMatchingCerts(domainName)
	for _, cert := range certs {
		if cert.managed {
			return nil
		}
	}

	// first try loading existing certificate from storage
	cert, err := cfg.CacheManagedCertificate(ctx, domainName)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: caching certificate: %v", domainName, err)
		}
		// if we don't have one in storage, obtain one
		obtain := func() error {
			var err error
			if async {
				err = cfg.ObtainCertAsync(ctx, domainName)
			} else {
				err = cfg.ObtainCertSync(ctx, domainName)
			}
			if err != nil {
				return fmt.Errorf("%s: obtaining certificate: %w", domainName, err)
			}
			cert, err = cfg.CacheManagedCertificate(ctx, domainName)
			if err != nil {
				return fmt.Errorf("%s: caching certificate after obtaining it: %v", domainName, err)
			}
			return nil
		}
		if async {
			// Leave the job name empty so as to allow duplicate 'obtain'
			// jobs; this is because Caddy calls ManageAsync() before the
			// previous config is stopped (and before its context is
			// canceled), which means that if an obtain job is still
			// running for the same domain, Submit() would not queue the
			// new one because it is still running, even though it is
			// (probably) about to be canceled (it might not if the new
			// config fails to finish loading, however). In any case, we
			// presume it is safe to enqueue a duplicate obtain job because
			// either the old one (or sometimes the new one) is about to be
			// canceled. This seems like reasonable logic for any consumer
			// of this lib. See https://github.com/caddyserver/caddy/issues/3202
			jm.Submit(cfg.Logger, "", obtain)
			return nil
		}
		return obtain()
	}

	// for an existing certificate, make sure it is renewed; or if it is revoked,
	// force a renewal even if it's not expiring
	renew := func() error {
		// first, ensure status is not revoked (it was just refreshed in CacheManagedCertificate above)
		if !cert.Expired() && cert.ocsp != nil && cert.ocsp.Status == ocsp.Revoked {
			_, err = cfg.forceRenew(ctx, cfg.Logger, cert)
			return err
		}

		// otherwise, simply renew the certificate if needed
		if cert.NeedsRenewal(cfg) {
			var err error
			if async {
				err = cfg.RenewCertAsync(ctx, domainName, false)
			} else {
				err = cfg.RenewCertSync(ctx, domainName, false)
			}
			if err != nil {
				return fmt.Errorf("%s: renewing certificate: %w", domainName, err)
			}
			// successful renewal, so update in-memory cache
			_, err = cfg.reloadManagedCertificate(ctx, cert)
			if err != nil {
				return fmt.Errorf("%s: reloading renewed certificate into memory: %v", domainName, err)
			}
		}

		return nil
	}

	if async {
		jm.Submit(cfg.Logger, "renew_"+domainName, renew)
		return nil
	}
	return renew()
}

// ObtainCertSync generates a new private key and obtains a certificate for
// name using cfg in the foreground; i.e. interactively and without retries.
// It stows the renewed certificate and its assets in storage if successful.
// It DOES NOT load the certificate into the in-memory cache. This method
// is a no-op if storage already has a certificate for name.
func (cfg *Config) ObtainCertSync(ctx context.Context, name string) error {
	return cfg.obtainCert(ctx, name, true)
}

// ObtainCertAsync is the same as ObtainCertSync(), except it runs in the
// background; i.e. non-interactively, and with retries if it fails.
func (cfg *Config) ObtainCertAsync(ctx context.Context, name string) error {
	return cfg.obtainCert(ctx, name, false)
}

func (cfg *Config) obtainCert(ctx context.Context, name string, interactive bool) error {
	if len(cfg.Issuers) == 0 {
		return fmt.Errorf("no issuers configured; impossible to obtain or check for existing certificate in storage")
	}

	// if storage has all resources for this certificate, obtain is a no-op
	if cfg.storageHasCertResourcesAnyIssuer(ctx, name) {
		return nil
	}

	// ensure storage is writeable and readable
	// TODO: this is not necessary every time; should only perform check once every so often for each storage, which may require some global state...
	err := cfg.checkStorage(ctx)
	if err != nil {
		return fmt.Errorf("failed storage check: %v - storage is probably misconfigured", err)
	}

	log := cfg.Logger.Named("obtain")

	log.Info("acquiring lock", zap.String("identifier", name))

	// ensure idempotency of the obtain operation for this name
	lockKey := cfg.lockKey(certIssueLockOp, name)
	err = acquireLock(ctx, cfg.Storage, lockKey)
	if err != nil {
		return fmt.Errorf("unable to acquire lock '%s': %v", lockKey, err)
	}
	defer func() {
		log.Info("releasing lock", zap.String("identifier", name))
		if err := releaseLock(ctx, cfg.Storage, lockKey); err != nil {
			log.Error("unable to unlock",
				zap.String("identifier", name),
				zap.String("lock_key", lockKey),
				zap.Error(err))
		}
	}()
	log.Info("lock acquired", zap.String("identifier", name))

	f := func(ctx context.Context) error {
		// check if obtain is still needed -- might have been obtained during lock
		if cfg.storageHasCertResourcesAnyIssuer(ctx, name) {
			log.Info("certificate already exists in storage", zap.String("identifier", name))
			return nil
		}

		log.Info("obtaining certificate", zap.String("identifier", name))

		if err := cfg.emit(ctx, "cert_obtaining", map[string]any{"identifier": name}); err != nil {
			return fmt.Errorf("obtaining certificate aborted by event handler: %w", err)
		}

		// If storage has a private key already, use it; otherwise we'll generate our own.
		// Also create the slice of issuers we will try using according to any issuer
		// selection policy (it must be a copy of the slice so we don't mutate original).
		var privKey crypto.PrivateKey
		var privKeyPEM []byte
		var issuers []Issuer
		if cfg.ReusePrivateKeys {
			privKey, privKeyPEM, issuers, err = cfg.reusePrivateKey(ctx, name)
			if err != nil {
				return err
			}
		} else {
			issuers = make([]Issuer, len(cfg.Issuers))
			copy(issuers, cfg.Issuers)
		}
		if cfg.IssuerPolicy == UseFirstRandomIssuer {
			weakrand.Shuffle(len(issuers), func(i, j int) {
				issuers[i], issuers[j] = issuers[j], issuers[i]
			})
		}
		if privKey == nil {
			privKey, err = cfg.KeySource.GenerateKey()
			if err != nil {
				return err
			}
			privKeyPEM, err = PEMEncodePrivateKey(privKey)
			if err != nil {
				return err
			}
		}

		csr, err := cfg.generateCSR(privKey, []string{name})
		if err != nil {
			return err
		}

		// try to obtain from each issuer until we succeed
		var issuedCert *IssuedCertificate
		var issuerUsed Issuer
		var issuerKeys []string
		for i, issuer := range issuers {
			issuerKeys = append(issuerKeys, issuer.IssuerKey())

			log.Debug(fmt.Sprintf("trying issuer %d/%d", i+1, len(cfg.Issuers)),
				zap.String("issuer", issuer.IssuerKey()))

			if prechecker, ok := issuer.(PreChecker); ok {
				err = prechecker.PreCheck(ctx, []string{name}, interactive)
				if err != nil {
					continue
				}
			}

			issuedCert, err = issuer.Issue(ctx, csr)
			if err == nil {
				issuerUsed = issuer
				break
			}

			// err is usually wrapped, which is nice for simply printing it, but
			// with our structured error logs we only need the problem string
			errToLog := err
			var problem acme.Problem
			if errors.As(err, &problem) {
				errToLog = problem
			}
			log.Error("could not get certificate from issuer",
				zap.String("identifier", name),
				zap.String("issuer", issuer.IssuerKey()),
				zap.Error(errToLog))
		}
		if err != nil {
			cfg.emit(ctx, "cert_failed", map[string]any{
				"renewal":    false,
				"identifier": name,
				"issuers":    issuerKeys,
				"error":      err,
			})

			// only the error from the last issuer will be returned, but we logged the others
			return fmt.Errorf("[%s] Obtain: %w", name, err)
		}
		issuerKey := issuerUsed.IssuerKey()

		// success - immediately save the certificate resource
		certRes := CertificateResource{
			SANs:           namesFromCSR(csr),
			CertificatePEM: issuedCert.Certificate,
			PrivateKeyPEM:  privKeyPEM,
			IssuerData:     issuedCert.Metadata,
			issuerKey:      issuerUsed.IssuerKey(),
		}
		err = cfg.saveCertResource(ctx, issuerUsed, certRes)
		if err != nil {
			return fmt.Errorf("[%s] Obtain: saving assets: %v", name, err)
		}

		log.Info("certificate obtained successfully", zap.String("identifier", name))

		certKey := certRes.NamesKey()

		cfg.emit(ctx, "cert_obtained", map[string]any{
			"renewal":          false,
			"identifier":       name,
			"issuer":           issuerUsed.IssuerKey(),
			"storage_path":     StorageKeys.CertsSitePrefix(issuerKey, certKey),
			"private_key_path": StorageKeys.SitePrivateKey(issuerKey, certKey),
			"certificate_path": StorageKeys.SiteCert(issuerKey, certKey),
			"metadata_path":    StorageKeys.SiteMeta(issuerKey, certKey),
		})

		return nil
	}

	if interactive {
		err = f(ctx)
	} else {
		err = doWithRetry(ctx, log, f)
	}

	return err
}

// reusePrivateKey looks for a private key for domain in storage in the configured issuers
// paths. For the first private key it finds, it returns that key both decoded and PEM-encoded,
// as well as the reordered list of issuers to use instead of cfg.Issuers (because if a key
// is found, that issuer should be tried first, so it is moved to the front in a copy of
// cfg.Issuers).
func (cfg *Config) reusePrivateKey(ctx context.Context, domain string) (privKey crypto.PrivateKey, privKeyPEM []byte, issuers []Issuer, err error) {
	// make a copy of cfg.Issuers so that if we have to reorder elements, we don't
	// inadvertently mutate the configured issuers (see append calls below)
	issuers = make([]Issuer, len(cfg.Issuers))
	copy(issuers, cfg.Issuers)

	for i, issuer := range issuers {
		// see if this issuer location in storage has a private key for the domain
		privateKeyStorageKey := StorageKeys.SitePrivateKey(issuer.IssuerKey(), domain)
		privKeyPEM, err = cfg.Storage.Load(ctx, privateKeyStorageKey)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil // obviously, it's OK to not have a private key; so don't prevent obtaining a cert
			continue
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("loading existing private key for reuse with issuer %s: %v", issuer.IssuerKey(), err)
		}

		// we loaded a private key; try decoding it so we can use it
		privKey, err = PEMDecodePrivateKey(privKeyPEM)
		if err != nil {
			return nil, nil, nil, err
		}

		// since the private key was found in storage for this issuer, move it
		// to the front of the list so we prefer this issuer first
		issuers = append([]Issuer{issuer}, append(issuers[:i], issuers[i+1:]...)...)
		break
	}

	return
}

// storageHasCertResourcesAnyIssuer returns true if storage has all the
// certificate resources in storage from any configured issuer. It checks
// all configured issuers in order.
func (cfg *Config) storageHasCertResourcesAnyIssuer(ctx context.Context, name string) bool {
	for _, iss := range cfg.Issuers {
		if cfg.storageHasCertResources(ctx, iss, name) {
			return true
		}
	}
	return false
}

// RenewCertSync renews the certificate for name using cfg in the foreground;
// i.e. interactively and without retries. It stows the renewed certificate
// and its assets in storage if successful. It DOES NOT update the in-memory
// cache with the new certificate. The certificate will not be renewed if it
// is not close to expiring unless force is true.
func (cfg *Config) RenewCertSync(ctx context.Context, name string, force bool) error {
	return cfg.renewCert(ctx, name, force, true)
}

// RenewCertAsync is the same as RenewCertSync(), except it runs in the
// background; i.e. non-interactively, and with retries if it fails.
func (cfg *Config) RenewCertAsync(ctx context.Context, name string, force bool) error {
	return cfg.renewCert(ctx, name, force, false)
}

func (cfg *Config) renewCert(ctx context.Context, name string, force, interactive bool) error {
	if len(cfg.Issuers) == 0 {
		return fmt.Errorf("no issuers configured; impossible to renew or check existing certificate in storage")
	}

	// ensure storage is writeable and readable
	// TODO: this is not necessary every time; should only perform check once every so often for each storage, which may require some global state...
	err := cfg.checkStorage(ctx)
	if err != nil {
		return fmt.Errorf("failed storage check: %v - storage is probably misconfigured", err)
	}

	log := cfg.Logger.Named("renew")

	log.Info("acquiring lock", zap.String("identifier", name))

	// ensure idempotency of the renew operation for this name
	lockKey := cfg.lockKey(certIssueLockOp, name)
	err = acquireLock(ctx, cfg.Storage, lockKey)
	if err != nil {
		return fmt.Errorf("unable to acquire lock '%s': %v", lockKey, err)
	}
	defer func() {
		log.Info("releasing lock", zap.String("identifier", name))

		if err := releaseLock(ctx, cfg.Storage, lockKey); err != nil {
			log.Error("unable to unlock",
				zap.String("identifier", name),
				zap.String("lock_key", lockKey),
				zap.Error(err))
		}
	}()
	log.Info("lock acquired", zap.String("identifier", name))

	f := func(ctx context.Context) error {
		// prepare for renewal (load PEM cert, key, and meta)
		certRes, err := cfg.loadCertResourceAnyIssuer(ctx, name)
		if err != nil {
			return err
		}

		// check if renew is still needed - might have been renewed while waiting for lock
		timeLeft, needsRenew := cfg.managedCertNeedsRenewal(certRes)
		if !needsRenew {
			if force {
				log.Info("certificate does not need to be renewed, but renewal is being forced",
					zap.String("identifier", name),
					zap.Duration("remaining", timeLeft))
			} else {
				log.Info("certificate appears to have been renewed already",
					zap.String("identifier", name),
					zap.Duration("remaining", timeLeft))
				return nil
			}
		}

		log.Info("renewing certificate",
			zap.String("identifier", name),
			zap.Duration("remaining", timeLeft))

		if err := cfg.emit(ctx, "cert_obtaining", map[string]any{
			"renewal":    true,
			"identifier": name,
			"forced":     force,
			"remaining":  timeLeft,
			"issuer":     certRes.issuerKey, // previous/current issuer
		}); err != nil {
			return fmt.Errorf("renewing certificate aborted by event handler: %w", err)
		}

		// reuse or generate new private key for CSR
		var privateKey crypto.PrivateKey
		if cfg.ReusePrivateKeys {
			privateKey, err = PEMDecodePrivateKey(certRes.PrivateKeyPEM)
		} else {
			privateKey, err = cfg.KeySource.GenerateKey()
		}
		if err != nil {
			return err
		}

		// if we generated a new key, make sure to replace its PEM encoding too!
		if !cfg.ReusePrivateKeys {
			certRes.PrivateKeyPEM, err = PEMEncodePrivateKey(privateKey)
			if err != nil {
				return err
			}
		}

		csr, err := cfg.generateCSR(privateKey, []string{name})
		if err != nil {
			return err
		}

		// try to obtain from each issuer until we succeed
		var issuedCert *IssuedCertificate
		var issuerUsed Issuer
		var issuerKeys []string
		for _, issuer := range cfg.Issuers {
			issuerKeys = append(issuerKeys, issuer.IssuerKey())
			if prechecker, ok := issuer.(PreChecker); ok {
				err = prechecker.PreCheck(ctx, []string{name}, interactive)
				if err != nil {
					continue
				}
			}

			issuedCert, err = issuer.Issue(ctx, csr)
			if err == nil {
				issuerUsed = issuer
				break
			}

			// err is usually wrapped, which is nice for simply printing it, but
			// with our structured error logs we only need the problem string
			errToLog := err
			var problem acme.Problem
			if errors.As(err, &problem) {
				errToLog = problem
			}
			log.Error("could not get certificate from issuer",
				zap.String("identifier", name),
				zap.String("issuer", issuer.IssuerKey()),
				zap.Error(errToLog))
		}
		if err != nil {
			cfg.emit(ctx, "cert_failed", map[string]any{
				"renewal":    true,
				"identifier": name,
				"remaining":  timeLeft,
				"issuers":    issuerKeys,
				"error":      err,
			})

			// only the error from the last issuer will be returned, but we logged the others
			return fmt.Errorf("[%s] Renew: %w", name, err)
		}
		issuerKey := issuerUsed.IssuerKey()

		// success - immediately save the renewed certificate resource
		newCertRes := CertificateResource{
			SANs:           namesFromCSR(csr),
			CertificatePEM: issuedCert.Certificate,
			PrivateKeyPEM:  certRes.PrivateKeyPEM,
			IssuerData:     issuedCert.Metadata,
			issuerKey:      issuerKey,
		}
		err = cfg.saveCertResource(ctx, issuerUsed, newCertRes)
		if err != nil {
			return fmt.Errorf("[%s] Renew: saving assets: %v", name, err)
		}

		log.Info("certificate renewed successfully", zap.String("identifier", name))

		certKey := newCertRes.NamesKey()

		cfg.emit(ctx, "cert_obtained", map[string]any{
			"renewal":          true,
			"remaining":        timeLeft,
			"identifier":       name,
			"issuer":           issuerKey,
			"storage_path":     StorageKeys.CertsSitePrefix(issuerKey, certKey),
			"private_key_path": StorageKeys.SitePrivateKey(issuerKey, certKey),
			"certificate_path": StorageKeys.SiteCert(issuerKey, certKey),
			"metadata_path":    StorageKeys.SiteMeta(issuerKey, certKey),
		})

		return nil
	}

	if interactive {
		err = f(ctx)
	} else {
		err = doWithRetry(ctx, log, f)
	}

	return err
}

func (cfg *Config) generateCSR(privateKey crypto.PrivateKey, sans []string) (*x509.CertificateRequest, error) {
	csrTemplate := new(x509.CertificateRequest)

	for _, name := range sans {
		if ip := net.ParseIP(name); ip != nil {
			csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
		} else if strings.Contains(name, "@") {
			csrTemplate.EmailAddresses = append(csrTemplate.EmailAddresses, name)
		} else if u, err := url.Parse(name); err == nil && strings.Contains(name, "/") {
			csrTemplate.URIs = append(csrTemplate.URIs, u)
		} else {
			// convert IDNs to ASCII according to RFC 5280 section 7
			normalizedName, err := idna.ToASCII(name)
			if err != nil {
				return nil, fmt.Errorf("converting identifier '%s' to ASCII: %v", name, err)
			}
			csrTemplate.DNSNames = append(csrTemplate.DNSNames, normalizedName)
		}
	}

	if cfg.MustStaple {
		csrTemplate.ExtraExtensions = append(csrTemplate.ExtraExtensions, mustStapleExtension)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(csrDER)
}

// RevokeCert revokes the certificate for domain via ACME protocol. It requires
// that cfg.Issuers is properly configured with the same issuer that issued the
// certificate being revoked. See RFC 5280 §5.3.1 for reason codes.
//
// The certificate assets are deleted from storage after successful revocation
// to prevent reuse.
func (cfg *Config) RevokeCert(ctx context.Context, domain string, reason int, interactive bool) error {
	for i, issuer := range cfg.Issuers {
		issuerKey := issuer.IssuerKey()

		rev, ok := issuer.(Revoker)
		if !ok {
			return fmt.Errorf("issuer %d (%s) is not a Revoker", i, issuerKey)
		}

		certRes, err := cfg.loadCertResource(ctx, issuer, domain)
		if err != nil {
			return err
		}

		if !cfg.Storage.Exists(ctx, StorageKeys.SitePrivateKey(issuerKey, domain)) {
			return fmt.Errorf("private key not found for %s", certRes.SANs)
		}

		err = rev.Revoke(ctx, certRes, reason)
		if err != nil {
			return fmt.Errorf("issuer %d (%s): %v", i, issuerKey, err)
		}

		err = cfg.deleteSiteAssets(ctx, issuerKey, domain)
		if err != nil {
			return fmt.Errorf("certificate revoked, but unable to fully clean up assets from issuer %s: %v", issuerKey, err)
		}
	}

	return nil
}

// TLSConfig is an opinionated method that returns a recommended, modern
// TLS configuration that can be used to configure TLS listeners. Aside
// from safe, modern defaults, this method sets two critical fields on the
// TLS config which are required to enable automatic certificate
// management: GetCertificate and NextProtos.
//
// The GetCertificate field is necessary to get certificates from memory
// or storage, including both manual and automated certificates. You
// should only change this field if you know what you are doing.
//
// The NextProtos field is pre-populated with a special value to enable
// solving the TLS-ALPN ACME challenge. Because this method does not
// assume any particular protocols after the TLS handshake is completed,
// you will likely need to customize the NextProtos field by prepending
// your application's protocols to the slice. For example, to serve
// HTTP, you will need to prepend "h2" and "http/1.1" values. Be sure to
// leave the acmez.ACMETLS1Protocol value intact, however, or TLS-ALPN
// challenges will fail (which may be acceptable if you are not using
// ACME, or specifically, the TLS-ALPN challenge).
//
// Unlike the package TLS() function, this method does not, by itself,
// enable certificate management for any domain names.
func (cfg *Config) TLSConfig() *tls.Config {
	return &tls.Config{
		// these two fields necessary for TLS-ALPN challenge
		GetCertificate: cfg.GetCertificate,
		NextProtos:     []string{acmez.ACMETLS1Protocol},

		// the rest recommended for modern TLS servers
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites:             preferredDefaultCipherSuites(),
		PreferServerCipherSuites: true,
	}
}

// getChallengeInfo loads the challenge info from either the internal challenge memory
// or the external storage (implying distributed solving). The second return value
// indicates whether challenge info was loaded from external storage. If true, the
// challenge is being solved in a distributed fashion; if false, from internal memory.
// If no matching challenge information can be found, an error is returned.
func (cfg *Config) getChallengeInfo(ctx context.Context, identifier string) (Challenge, bool, error) {
	// first, check if our process initiated this challenge; if so, just return it
	chalData, ok := GetACMEChallenge(identifier)
	if ok {
		return chalData, false, nil
	}

	// otherwise, perhaps another instance in the cluster initiated it; check
	// the configured storage to retrieve challenge data

	var chalInfo acme.Challenge
	var chalInfoBytes []byte
	var tokenKey string
	for _, issuer := range cfg.Issuers {
		ds := distributedSolver{
			storage:                cfg.Storage,
			storageKeyIssuerPrefix: storageKeyACMECAPrefix(issuer.IssuerKey()),
		}
		tokenKey = ds.challengeTokensKey(identifier)
		var err error
		chalInfoBytes, err = cfg.Storage.Load(ctx, tokenKey)
		if err == nil {
			break
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return Challenge{}, false, fmt.Errorf("opening distributed challenge token file %s: %v", tokenKey, err)
	}
	if len(chalInfoBytes) == 0 {
		return Challenge{}, false, fmt.Errorf("no information found to solve challenge for identifier: %s", identifier)
	}

	err := json.Unmarshal(chalInfoBytes, &chalInfo)
	if err != nil {
		return Challenge{}, false, fmt.Errorf("decoding challenge token file %s (corrupted?): %v", tokenKey, err)
	}

	return Challenge{Challenge: chalInfo}, true, nil
}

// checkStorage tests the storage by writing random bytes
// to a random key, and then loading those bytes and
// comparing the loaded value. If this fails, the provided
// cfg.Storage mechanism should not be used.
func (cfg *Config) checkStorage(ctx context.Context) error {
	if cfg.DisableStorageCheck {
		return nil
	}
	key := fmt.Sprintf("rw_test_%d", weakrand.Int())
	contents := make([]byte, 1024*10) // size sufficient for one or two ACME resources
	_, err := weakrand.Read(contents)
	if err != nil {
		return err
	}
	err = cfg.Storage.Store(ctx, key, contents)
	if err != nil {
		return err
	}
	defer func() {
		deleteErr := cfg.Storage.Delete(ctx, key)
		if deleteErr != nil {
			cfg.Logger.Error("deleting test key from storage",
				zap.String("key", key), zap.Error(err))
		}
		// if there was no other error, make sure
		// to return any error returned from Delete
		if err == nil {
			err = deleteErr
		}
	}()
	loaded, err := cfg.Storage.Load(ctx, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(contents, loaded) {
		return fmt.Errorf("load yielded different value than was stored; expected %d bytes, got %d bytes of differing elements", len(contents), len(loaded))
	}
	return nil
}

// storageHasCertResources returns true if the storage
// associated with cfg's certificate cache has all the
// resources related to the certificate for domain: the
// certificate, the private key, and the metadata.
func (cfg *Config) storageHasCertResources(ctx context.Context, issuer Issuer, domain string) bool {
	issuerKey := issuer.IssuerKey()
	certKey := StorageKeys.SiteCert(issuerKey, domain)
	keyKey := StorageKeys.SitePrivateKey(issuerKey, domain)
	metaKey := StorageKeys.SiteMeta(issuerKey, domain)
	return cfg.Storage.Exists(ctx, certKey) &&
		cfg.Storage.Exists(ctx, keyKey) &&
		cfg.Storage.Exists(ctx, metaKey)
}

// deleteSiteAssets deletes the folder in storage containing the
// certificate, private key, and metadata file for domain from the
// issuer with the given issuer key.
func (cfg *Config) deleteSiteAssets(ctx context.Context, issuerKey, domain string) error {
	err := cfg.Storage.Delete(ctx, StorageKeys.SiteCert(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("deleting certificate file: %v", err)
	}
	err = cfg.Storage.Delete(ctx, StorageKeys.SitePrivateKey(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("deleting private key: %v", err)
	}
	err = cfg.Storage.Delete(ctx, StorageKeys.SiteMeta(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("deleting metadata file: %v", err)
	}
	err = cfg.Storage.Delete(ctx, StorageKeys.CertsSitePrefix(issuerKey, domain))
	if err != nil {
		return fmt.Errorf("deleting site asset folder: %v", err)
	}
	return nil
}

// lockKey returns a key for a lock that is specific to the operation
// named op being performed related to domainName and this config's CA.
func (cfg *Config) lockKey(op, domainName string) string {
	return fmt.Sprintf("%s_%s", op, domainName)
}

// managedCertNeedsRenewal returns true if certRes is expiring soon or already expired,
// or if the process of decoding the cert and checking its expiration returned an error.
func (cfg *Config) managedCertNeedsRenewal(certRes CertificateResource) (time.Duration, bool) {
	certChain, err := parseCertsFromPEMBundle(certRes.CertificatePEM)
	if err != nil {
		return 0, true
	}
	remaining := time.Until(expiresAt(certChain[0]))
	needsRenew := currentlyInRenewalWindow(certChain[0].NotBefore, expiresAt(certChain[0]), cfg.RenewalWindowRatio)
	return remaining, needsRenew
}

func (cfg *Config) emit(ctx context.Context, eventName string, data map[string]any) error {
	if cfg.OnEvent == nil {
		return nil
	}
	return cfg.OnEvent(ctx, eventName, data)
}

// CertificateSelector is a type which can select a certificate to use given multiple choices.
type CertificateSelector interface {
	SelectCertificate(*tls.ClientHelloInfo, []Certificate) (Certificate, error)
}

// OCSPConfig configures how OCSP is handled.
type OCSPConfig struct {
	// Disable automatic OCSP stapling; strongly
	// discouraged unless you have a good reason.
	// Disabling this puts clients at greater risk
	// and reduces their privacy.
	DisableStapling bool

	// A map of OCSP responder domains to replacement
	// domains for querying OCSP servers. Used for
	// overriding the OCSP responder URL that is
	// embedded in certificates. Mapping to an empty
	// URL will disable OCSP from that responder.
	ResponderOverrides map[string]string
}

// certIssueLockOp is the name of the operation used
// when naming a lock to make it mutually exclusive
// with other certificate issuance operations for a
// certain name.
const certIssueLockOp = "issue_cert"

// Constants for PKIX MustStaple extension.
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	mustStapleExtension    = pkix.Extension{
		Id:    tlsFeatureExtensionOID,
		Value: ocspMustStapleFeature,
	}
)

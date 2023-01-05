package certcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Constants for all key types we support.
const (
	EC256   = KeyType("P256")
	EC384   = KeyType("P384")
	RSA2048 = KeyType("2048")
	RSA4096 = KeyType("4096")
	RSA8192 = KeyType("8192")
)

const (
	// OCSPGood means that the certificate is valid.
	OCSPGood = ocsp.Good
	// OCSPRevoked means that the certificate has been deliberately revoked.
	OCSPRevoked = ocsp.Revoked
	// OCSPUnknown means that the OCSP responder doesn't know about the certificate.
	OCSPUnknown = ocsp.Unknown
	// OCSPServerFailed means that the OCSP responder failed to process the request.
	OCSPServerFailed = ocsp.ServerFailed
)

// Constants for OCSP must staple.
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

// KeyType represents the key algo as well as the key size or curve to use.
type KeyType string

type DERCertificateBytes []byte

// ParsePEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func ParsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}

// ParsePEMPrivateKey parses a private key from key, which is a PEM block.
// Borrowed from Go standard library, to handle various private key and PEM block types.
// https://github.com/golang/go/blob/693748e9fa385f1e2c3b91ca9acbb6c0ad2d133d/src/crypto/tls/tls.go#L291-L308
// https://github.com/golang/go/blob/693748e9fa385f1e2c3b91ca9acbb6c0ad2d133d/src/crypto/tls/tls.go#L238)
func ParsePEMPrivateKey(key []byte) (crypto.PrivateKey, error) {
	keyBlockDER, _ := pem.Decode(key)

	if keyBlockDER.Type != "PRIVATE KEY" && !strings.HasSuffix(keyBlockDER.Type, " PRIVATE KEY") {
		return nil, fmt.Errorf("unknown PEM header %q", keyBlockDER.Type)
	}

	if key, err := x509.ParsePKCS1PrivateKey(keyBlockDER.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(keyBlockDER.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping: %T", key)
		}
	}

	if key, err := x509.ParseECPrivateKey(keyBlockDER.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func GeneratePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case RSA8192:
		return rsa.GenerateKey(rand.Reader, 8192)
	}

	return nil, fmt.Errorf("invalid KeyType: %s", keyType)
}

func GenerateCSR(privateKey crypto.PrivateKey, domain string, san []string, mustStaple bool) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: san,
	}

	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
}

func PEMEncode(data interface{}) []byte {
	return pem.EncodeToMemory(PEMBlock(data))
}

func PEMBlock(data interface{}) *pem.Block {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *x509.CertificateRequest:
		pemBlock = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.Raw}
	case DERCertificateBytes:
		pemBlock = &pem.Block{Type: "CERTIFICATE", Bytes: []byte(data.(DERCertificateBytes))}
	}

	return pemBlock
}

func pemDecode(data []byte) (*pem.Block, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode did not yield a valid block. Is the certificate in the right format?")
	}

	return pemBlock, nil
}

func PemDecodeTox509CSR(pem []byte) (*x509.CertificateRequest, error) {
	pemBlock, err := pemDecode(pem)
	if pemBlock == nil {
		return nil, err
	}

	if pemBlock.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block is not a certificate request")
	}

	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

// ParsePEMCertificate returns Certificate from a PEM encoded certificate.
// The certificate has to be PEM encoded. Any other encodings like DER will fail.
func ParsePEMCertificate(cert []byte) (*x509.Certificate, error) {
	pemBlock, err := pemDecode(cert)
	if pemBlock == nil {
		return nil, err
	}

	// from a DER encoded certificate
	return x509.ParseCertificate(pemBlock.Bytes)
}

func ExtractDomains(cert *x509.Certificate) []string {
	var domains []string
	if cert.Subject.CommonName != "" {
		domains = append(domains, cert.Subject.CommonName)
	}

	// Check for SAN certificate
	for _, sanDomain := range cert.DNSNames {
		if sanDomain == cert.Subject.CommonName {
			continue
		}
		domains = append(domains, sanDomain)
	}

	return domains
}

func ExtractDomainsCSR(csr *x509.CertificateRequest) []string {
	var domains []string
	if csr.Subject.CommonName != "" {
		domains = append(domains, csr.Subject.CommonName)
	}

	// loop over the SubjectAltName DNS names
	for _, sanName := range csr.DNSNames {
		if containsSAN(domains, sanName) {
			// Duplicate; skip this name
			continue
		}

		// Name is unique
		domains = append(domains, sanName)
	}

	return domains
}

func containsSAN(domains []string, sanName string) bool {
	for _, existingName := range domains {
		if existingName == sanName {
			return true
		}
	}
	return false
}

func GeneratePemCert(privateKey *rsa.PrivateKey, domain string, extensions []pkix.Extension) ([]byte, error) {
	derBytes, err := generateDerCert(privateKey, time.Time{}, domain, extensions)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func generateDerCert(privateKey *rsa.PrivateKey, expiration time.Time, domain string, extensions []pkix.Extension) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		expiration = time.Now().Add(365)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ACME Challenge TEMP",
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
		ExtraExtensions:       extensions,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
}

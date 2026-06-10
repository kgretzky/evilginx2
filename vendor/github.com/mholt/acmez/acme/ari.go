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

package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// RenewalInfo "is a new resource type introduced to ACME protocol.
// This new resource both allows clients to query the server for
// suggestions on when they should renew certificates, and allows
// clients to inform the server when they have completed renewal
// (or otherwise replaced the certificate to their satisfaction)."
//
// ACME Renewal Information (ARI):
// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/
//
// This is a DRAFT specification and the API is subject to change.
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL"`

	// This field is not part of the specified structure, but is
	// important for proper conformance to the specification,
	// so the Retry-After response header will be read and this
	// field will be populated for ACME client consideration.
	// Polling again for renewal info should not occur before
	// this time.
	RetryAfter time.Time `json:"-"`
}

// GetRenewalInfo returns the ACME Renewal Information (ARI) for the certificate represented by the
// "base64url-encoded [RFC4648] bytes of a DER-encoded CertID ASN.1 sequence [RFC6960]" without padding
// (call `CertIDSequence()` to get this value). It tacks on the Retry-After value if present.
func (c *Client) GetRenewalInfo(ctx context.Context, b64CertIDSeq string) (RenewalInfo, error) {
	if err := c.provision(ctx); err != nil {
		return RenewalInfo{}, err
	}

	endpoint := c.dir.RenewalInfo + b64CertIDSeq

	var ari RenewalInfo
	resp, err := c.httpReq(ctx, http.MethodGet, endpoint, nil, &ari)
	if err != nil {
		return RenewalInfo{}, err
	}

	ra, err := retryAfterTime(resp)
	if err != nil && c.Logger != nil {
		c.Logger.Error("setting Retry-After value", zap.Error(err))
	}
	ari.RetryAfter = ra

	return ari, nil
}

// UpdateRenewalInfo notifies the ACME server that the certificate represented by b64CertIDSeq
// has been replaced. The b64CertIDSeq string can be obtained by calling `CertIDSequence()`.
func (c *Client) UpdateRenewalInfo(ctx context.Context, account Account, b64CertIDSeq string) error {
	if err := c.provision(ctx); err != nil {
		return err
	}

	payload := struct {
		CertID   string `json:"certID"`
		Replaced bool   `json:"replaced"`
	}{
		CertID:   b64CertIDSeq,
		Replaced: true,
	}

	resp, err := c.httpPostJWS(ctx, account.PrivateKey, account.Location, c.dir.RenewalInfo, payload, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("updating renewal status: HTTP %d", resp.StatusCode)
	}

	return nil
}

// CertIDSequence returns the "base64url-encoded [RFC4648] bytes of a DER-encoded CertID ASN.1 sequence [RFC6960]"
// without padding for the given certificate chain. It is used primarily for requests to OCSP and ARI.
//
// The certificate chain must contain at least two elements: an end-entity certificate first, followed by an issuer
// certificate second. Of the end-entity certificate, only the SerialNumber field is required; and of the issuer
// certificate, only the RawSubjectPublicKeyInfo and RawSubject fields are required. If the issuer certificate is
// not provided, then it will be downloaded if the end-entity certificate contains the IssuingCertificateURL.
//
// As the return value may be used often during a certificate's lifetime, and in bulk with potentially tens of
// thousands of other certificates, it may be preferable to store or cache this value so that ASN.1 documents do
// not need to be repeatedly decoded and re-encoded.
func CertIDSequence(_ context.Context, certChain []*x509.Certificate, hash crypto.Hash, client *http.Client) (string, error) {
	endEntityCert := certChain[0]

	// if no chain was provided, we'll need to download the issuer cert
	if len(certChain) == 1 {
		if len(endEntityCert.IssuingCertificateURL) == 0 {
			return "", fmt.Errorf("no URL to issuing certificate")
		}

		if client == nil {
			client = http.DefaultClient
		}
		resp, err := client.Get(endEntityCert.IssuingCertificateURL[0])
		if err != nil {
			return "", fmt.Errorf("getting issuer certificate: %v", err)
		}
		defer resp.Body.Close()

		issuerBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return "", fmt.Errorf("reading issuer certificate: %v", err)
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return "", fmt.Errorf("parsing issuer certificate: %v", err)
		}

		certChain = append(certChain, issuerCert)
	}

	issuerCert := certChain[1]

	hashAlg, ok := hashOIDs[hash]
	if !ok {
		return "", x509.ErrUnsupportedAlgorithm
	}
	if !hash.Available() {
		return "", x509.ErrUnsupportedAlgorithm
	}
	h := hash.New()

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuerCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return "", err
	}

	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(issuerCert.RawSubject)
	issuerNameHash := h.Sum(nil)

	val, err := asn1.Marshal(certID{
		HashAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: hashAlg,
		},
		NameHash:      issuerNameHash,
		IssuerKeyHash: issuerKeyHash,
		SerialNumber:  endEntityCert.SerialNumber,
	})
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(val), nil
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

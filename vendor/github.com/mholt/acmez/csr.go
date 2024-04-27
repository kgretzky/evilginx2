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

package acmez

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/mholt/acmez/acme"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
	oidPermanentIdentifier     = []int{1, 3, 6, 1, 5, 5, 7, 8, 3}
	oidHardwareModuleName      = []int{1, 3, 6, 1, 5, 5, 7, 8, 4}
)

// RFC 5280 - https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
//
//	OtherName ::= SEQUENCE {
//	  type-id    OBJECT IDENTIFIER,
//	  value      [0] EXPLICIT ANY DEFINED BY type-id }
type otherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue
}

// permanentIdentifier is defined in RFC 4043 as an optional feature that can be
// used by a CA to indicate that two or more certificates relate to the same
// entity.
//
// The OID defined for this SAN is "1.3.6.1.5.5.7.8.3".
//
// See https://www.rfc-editor.org/rfc/rfc4043
//
//	PermanentIdentifier ::= SEQUENCE {
//	  identifierValue    UTF8String OPTIONAL,
//	  assigner           OBJECT IDENTIFIER OPTIONAL
//	}
type permanentIdentifier struct {
	IdentifierValue string                `asn1:"utf8,optional"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

// hardwareModuleName is defined in RFC 4108 as an optional feature that can be
// used to identify a hardware module.
//
// The OID defined for this SAN is "1.3.6.1.5.5.7.8.4".
//
// See https://www.rfc-editor.org/rfc/rfc4108#section-5
//
//	HardwareModuleName ::= SEQUENCE {
//	  hwType OBJECT IDENTIFIER,
//	  hwSerialNum OCTET STRING
//	}
type hardwareModuleName struct {
	Type         asn1.ObjectIdentifier
	SerialNumber []byte `asn1:"tag:4"`
}

func forEachSAN(der cryptobyte.String, callback func(tag int, data []byte) error) error {
	if !der.ReadASN1(&der, cryptobyte_asn1.SEQUENCE) {
		return errors.New("invalid subject alternative name extension")
	}
	for !der.Empty() {
		var san cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !der.ReadAnyASN1Element(&san, &tag) {
			return errors.New("invalid subject alternative name extension")
		}
		if err := callback(int(tag^0x80), san); err != nil {
			return err
		}
	}

	return nil
}

// createIdentifiersUsingCSR extracts the list of ACME identifiers from the
// given Certificate Signing Request.
func createIdentifiersUsingCSR(csr *x509.CertificateRequest) ([]acme.Identifier, error) {
	var ids []acme.Identifier
	for _, name := range csr.DNSNames {
		ids = append(ids, acme.Identifier{
			Type:  "dns", // RFC 8555 §9.7.7
			Value: name,
		})
	}
	for _, ip := range csr.IPAddresses {
		ids = append(ids, acme.Identifier{
			Type:  "ip", // RFC 8738
			Value: ip.String(),
		})
	}

	// Extract permanent identifiers and hardware module values.
	// This block will ignore errors.
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			err := forEachSAN(ext.Value, func(tag int, data []byte) error {
				var on otherName
				if rest, err := asn1.UnmarshalWithParams(data, &on, "tag:0"); err != nil || len(rest) > 0 {
					return nil
				}

				switch {
				case on.TypeID.Equal(oidPermanentIdentifier):
					var pi permanentIdentifier
					if _, err := asn1.Unmarshal(on.Value.Bytes, &pi); err == nil {
						ids = append(ids, acme.Identifier{
							Type:  "permanent-identifier", // draft-acme-device-attest-00 §3
							Value: pi.IdentifierValue,
						})
					}
				case on.TypeID.Equal(oidHardwareModuleName):
					var hmn hardwareModuleName
					if _, err := asn1.Unmarshal(on.Value.Bytes, &hmn); err == nil {
						ids = append(ids, acme.Identifier{
							Type:  "hardware-module", // draft-acme-device-attest-00 §4
							Value: string(hmn.SerialNumber),
						})
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			break
		}
	}

	return ids, nil
}

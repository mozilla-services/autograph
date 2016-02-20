// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int // fields must be exported for ASN.1 marshalling
}

// A signer provides the configuration and key material to
// allow an authorized user to sign data with a private key
type signer struct {
	ID           string
	PrivateKey   string
	PublicKey    string
	X5U          string
	ecdsaPrivKey *ecdsa.PrivateKey
}

func (s *signer) init() error {
	if s.ID == "" {
		return fmt.Errorf("missing signer ID in signer configuration")
	}
	if s.PrivateKey == "" {
		return fmt.Errorf("missing private key in signer configuration")
	}
	rawkey, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil {
		return err
	}
	s.ecdsaPrivKey, err = x509.ParseECPrivateKey(rawkey)
	if err != nil {
		return err
	}
	pubkeybytes, err := x509.MarshalPKIXPublicKey(s.ecdsaPrivKey.Public())
	if err != nil {
		return err
	}
	s.PublicKey = base64.StdEncoding.EncodeToString(pubkeybytes)
	return nil
}

// sign takes input data and returns an ecdsa signature
func (s *signer) sign(data []byte) (sig *ecdsaSignature, err error) {
	sig = new(ecdsaSignature)
	sig.R, sig.S, err = ecdsa.Sign(rand.Reader, s.ecdsaPrivKey, data)
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	return
}

// ContentSignatureString returns a content-signature header string
func (s *signer) ContentSignature(ecdsaSig *ecdsaSignature) (string, error) {
	encodedsig, err := encode(ecdsaSig, "rs_base64url")
	if err != nil {
		return "", err
	}
	var csid string
	switch s.ecdsaPrivKey.Curve.Params().Name {
	case "P-256":
		csid = "p256ecdsa"
	case "P-384":
		csid = "p384ecdsa"
	default:
		return "", fmt.Errorf("unknown curve name %q", s.ecdsaPrivKey.Curve.Params().Name)
	}
	if s.X5U != "" {
		return fmt.Sprintf("x5u=%s; %s=%s", s.X5U, csid, encodedsig), nil
	}
	return fmt.Sprintf("keyid=%s; %s=%s", s.ID, csid, encodedsig), nil
}

// getInputHash returns a hash of the signature input data. Templating is applied if necessary.
func getInputHash(sigreq signaturerequest) (hash []byte, err error) {
	hashinput, err := fromBase64URL(sigreq.Input)
	if sigreq.Template != "" {
		hashinput, err = applyTemplate(hashinput, sigreq.Template)
		if err != nil {
			return
		}
	}
	if sigreq.HashWith == "" {
		// take the input data as is
		hash = hashinput
	} else {
		// hash the input data with the provided algorithm
		hash, err = digest(hashinput, sigreq.HashWith)
		if err != nil {
			return
		}
	}
	return
}

// applyTemplate returns a templated input using custom rules. This is used when requesting a
// Content-Signature without having to specify the header ahead of time.
func applyTemplate(input []byte, template string) (templated []byte, err error) {
	switch template {
	case "content-signature":
		templated = make([]byte, len("Content-Signature:\x00")+len(input))
		copy(templated[:len("Content-Signature:\x00")], []byte("Content-Signature:\x00"))
		copy(templated[len("Content-Signature:\x00"):], input)
	default:
		return nil, fmt.Errorf("unknown template %q", template)
	}
	return
}

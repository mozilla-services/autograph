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
)

// A signer provides the configuration and key material to
// allow an authorized user to sign data with a private key
type signer struct {
	ID           string
	PrivateKey   string
	PublicKey    string
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

func (s *signer) sign(data []byte) (sig signature, err error) {
	R, S, err := ecdsa.Sign(rand.Reader, s.ecdsaPrivKey, data)
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	// sig = r||s
	sig = make([]byte, len(R.Bytes())+len(S.Bytes()))
	copy(sig[:len(R.Bytes())], R.Bytes())
	copy(sig[len(R.Bytes()):], S.Bytes())
	return
}

type signature []byte

func (s *signature) toBase64Url() string {
	return toBase64URL([]byte(*s))
}

func (s *signature) fromBase64Url(b64 string) error {
	data, err := fromBase64URL(b64)
	if err != nil {
		return err
	}
	*s = signature(data)
	return nil
}

type signaturerequest struct {
	Template string `json:"template"`
	HashWith string `json:"hashwith"`
	Input    string `json:"input"`
	KeyID    string `json:"keyid"`
}

type signatureresponse struct {
	Ref         string          `json:"ref"`
	Certificate certificate     `json:"certificate"`
	Signatures  []signaturedata `json:"signatures"`
}
type certificate struct {
	X5u           string `json:"x5u,omitempty"`
	EncryptionKey string `json:"encryptionkey,omitempty"`
}
type signaturedata struct {
	Encoding  string `json:"encoding,omitempty"`
	Signature string `json:"signature,omitempty"`
	Hash      string `json:"hashalgorithm,omitempty"`
}

// getCertificate return the certificate data (x5u and/or encryption)
// associated with a given signer
func (s *signer) getCertificate() (c certificate, err error) {
	pubKey := s.ecdsaPrivKey.Public().(*ecdsa.PublicKey)
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	c.EncryptionKey = toBase64URL(pubKeyDER)
	return
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

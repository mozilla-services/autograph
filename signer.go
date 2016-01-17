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
	"strings"
)

// A Signer provides the configuration and key material to
// allow an authorized user to sign data with a private key
type Signer struct {
	PrivateKey      string
	AuthorizedUsers []string
	ecdsaPrivKey    *ecdsa.PrivateKey
}

func (s *Signer) init() {
	rawkey, err := base64.StdEncoding.DecodeString(s.PrivateKey)
	if err != nil {
		panic(err)
	}
	s.ecdsaPrivKey, err = x509.ParseECPrivateKey(rawkey)
	if err != nil {
		panic(err)
	}
	return
}

func (s *Signer) sign(data []byte) (sig signature, err error) {
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

func toBase64URL(b []byte) string {
	return b64Tob64url(base64.StdEncoding.EncodeToString(b))
}

func b64Tob64url(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "+", "-", -1)
	s = strings.Replace(s, "/", "_", -1)
	s = strings.TrimRight(s, "=")
	return s
}

func (s *signature) fromBase64Url(b64 string) {
	*s = signature(fromBase64URL(b64))
	return
}

func fromBase64URL(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(b64urlTob64(s))
	if err != nil {
		panic(err)
	}
	return b
}

func b64urlTob64(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return s
}

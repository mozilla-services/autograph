// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer // import "go.mozilla.org/autograph/signer"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/ThalesIgnite/crypto11"
)

// Configuration defines the parameters of a signer
type Configuration struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	PrivateKey  string `json:"privatekey,omitempty"`
	PublicKey   string `json:"publickey,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	X5U         string `json:"x5u,omitempty"`

	isHsmAvailable bool
}

// HSMIsAvailable indicates that an HSM has been initialized
func (cfg *Configuration) HSMIsAvailable() {
	cfg.isHsmAvailable = true
}

// Signer is an interface to a configurable issuer of digital signatures
type Signer interface {
	Config() Configuration
}

// HashSigner is an interface to a signer able to sign hashes
type HashSigner interface {
	SignHash(data []byte, options interface{}) (Signature, error)
	GetDefaultOptions() interface{}
}

// DataSigner is an interface to a signer able to sign raw data
type DataSigner interface {
	SignData(data []byte, options interface{}) (Signature, error)
	GetDefaultOptions() interface{}
}

// FileSigner is an interface to a signer able to sign files
type FileSigner interface {
	SignFile(file []byte, options interface{}) (SignedFile, error)
	GetDefaultOptions() interface{}
}

// Signature is an interface to a digital signature
type Signature interface {
	Marshal() (signature string, err error)
}

// SignedFile is an []bytes that contains file data
type SignedFile []byte

// GetPrivateKey uses a signer configuration to determine where a private
// key should be accessed from. If it is in local configuration, it will
// be parsed and loaded in the signer. If it is in an HSM, it will be
// used via a PKCS11 interface. This is completely transparent to the
// caller, who should simply assume that the privatekey implements a
// crypto.Sign interface
//
// Note that we assume the PKCS11 library has been previously initialized
func (cfg *Configuration) GetPrivateKey() (crypto.PrivateKey, error) {
	// if a private key in the config starts with a PEM header, it is
	// defined locally and is parsed and returned
	if strings.HasPrefix(cfg.PrivateKey, "-----BEGIN") {
		return ParsePrivateKey([]byte(cfg.PrivateKey))
	}
	// otherwise, we assume the privatekey represents a label in the HSM
	if cfg.isHsmAvailable {
		key, err := crypto11.FindKeyPair(nil, []byte(cfg.PrivateKey))
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	return nil, fmt.Errorf("no suitable key found")
}

// ParsePrivateKey takes a PEM blocks are returns a crypto.PrivateKey
func ParsePrivateKey(keyPEMBlock []byte) (crypto.PrivateKey, error) {
	var (
		keyDERBlock       *pem.Block
		skippedBlockTypes []string
	)
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return nil, errors.New("signer: found a certificate rather than a key in the PEM for the private key")
			}
			return nil, fmt.Errorf("signer: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes)

		}
		if strings.HasSuffix(keyDERBlock.Type, "PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}
	// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
	// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
	// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
	// Code taken from the crypto/tls standard library.
	if key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("failed to parse private key")
}

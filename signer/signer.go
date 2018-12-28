// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package signer // import "go.mozilla.org/autograph/signer"

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// RSACacheConfig is a config for the RSAKeyCache
type RSACacheConfig struct {
	// NumKeys is the number of RSA keys matching the issuer size
	// to cache
	NumKeys uint64

	// NumGenerators is the number of key generator workers to run
	// that populate the RSA key cache
	NumGenerators uint8

	// GeneratorSleepDuration is how frequently each cache key
	// generator tries to add a key to the cache chan
	GeneratorSleepDuration time.Duration

	// FetchTimeout is how long a consumer waits for the cache
	// before generating its own key
	FetchTimeout time.Duration

	// StatsSampleRate is how frequently the monitor reports the
	// cache size and capacity
	StatsSampleRate time.Duration
}

// Configuration defines the parameters of a signer
type Configuration struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	PrivateKey  string `json:"privatekey,omitempty"`
	PublicKey   string `json:"publickey,omitempty"`
	Certificate string `json:"certificate,omitempty"`

	// X5U (X.509 URL) is a URL that points to an X.509 public key
	// certificate chain to validate a content signature
	X5U string `json:"x5u,omitempty"`

	// RSACacheConfig for XPI signers this specifies config for an
	// RSA cache
	RSACacheConfig RSACacheConfig `json:"rsacacheconfig,omitempty"`
	// NoPKCS7SignedAttributes for signing legacy APKs don't sign
	// attributes and use a legacy PKCS7 digest
	NoPKCS7SignedAttributes bool `json:"nopkcs7signedattributes,omitempty"`

	// KeyID is the fingerprint of the gpg key or subkey to use
	// e.g. 0xA2B637F535A86009 for the gpg2 signer type
	KeyID string `json:"keyid,omitempty"`

	// Passphrase is the optional passphrase to use decrypt the
	// gpg secret key for the gpg2 signer type
	Passphrase string `json:"passphrase,omitempty"`

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

// StatefulSigner is an interface to an issuer of digital signatures
// that stores out of memory state (files, HSM or DB connections,
// etc.) to clean up at exit
type StatefulSigner interface {
	AtExit() error
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

// GetKeysAndRand parses a configuration to retrieve the private and public key
// of a signer, as well as a RNG and a marshalled public key. It knows to handle
// HSMs as needed, and thus removes that complexity from individual signers.
func (cfg *Configuration) GetKeysAndRand() (priv crypto.PrivateKey, pub crypto.PublicKey, rng io.Reader, publicKey string, err error) {
	priv, err = cfg.GetPrivateKey()
	if err != nil {
		return
	}

	var publicKeyBytes []byte
	switch priv.(type) {
	case *rsa.PrivateKey:
		pub = priv.(*rsa.PrivateKey).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(&priv.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			err = errors.Wrap(err, "failed to asn1 marshal rsa public key")
			return
		}
		rng = rand.Reader

	case *ecdsa.PrivateKey:
		pub = priv.(*ecdsa.PrivateKey).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(&priv.(*ecdsa.PrivateKey).PublicKey)
		if err != nil {
			err = errors.Wrap(err, "failed to asn1 marshal ecdsa public key")
			return
		}
		rng = rand.Reader

	case *crypto11.PKCS11PrivateKeyECDSA:
		pub = priv.(*crypto11.PKCS11PrivateKeyECDSA).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(priv.(*crypto11.PKCS11PrivateKeyECDSA).PubKey.(*ecdsa.PublicKey))
		if err != nil {
			err = errors.Wrap(err, "failed to asn1 marshal crypto11 ecdsa public key")
			return
		}
		rng = new(crypto11.PKCS11RandReader)

	case *crypto11.PKCS11PrivateKeyRSA:
		pub = priv.(*crypto11.PKCS11PrivateKeyRSA).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(priv.(*crypto11.PKCS11PrivateKeyRSA).PubKey.(*rsa.PublicKey))
		if err != nil {
			err = errors.Wrap(err, "failed to asn1 marshal crypto11 rsa public key")
			return
		}
		rng = new(crypto11.PKCS11RandReader)

	default:
		err = errors.Errorf("unsupported private key type %T", priv)
		return
	}
	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes)

	return
}

// GetPrivateKey uses a signer configuration to determine where a private
// key should be accessed from. If it is in local configuration, it will
// be parsed and loaded in the signer. If it is in an HSM, it will be
// used via a PKCS11 interface. This is completely transparent to the
// caller, who should simply assume that the privatekey implements a
// crypto.Sign interface
//
// Note that we assume the PKCS11 library has been previously initialized
func (cfg *Configuration) GetPrivateKey() (crypto.PrivateKey, error) {
	// make sure heading newlines are removed
	removeNewlines := regexp.MustCompile(`^(\r?\n)`)
	cfg.PrivateKey = removeNewlines.ReplaceAllString(cfg.PrivateKey, "")
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
// It tries to parse as many known key types as possible before failing and
// returning all the errors it encountered.
func ParsePrivateKey(keyPEMBlock []byte) (key crypto.PrivateKey, err error) {
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
	if key, err = x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	var savedErr []string
	savedErr = append(savedErr, "pkcs1: "+err.Error())
	if key, err = x509.ParsePKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		}
	}
	savedErr = append(savedErr, "pkcs8: "+err.Error())

	if key, err = x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	savedErr = append(savedErr, "ecdsa: "+err.Error())

	if key, err = parseDSAPKCS8PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	savedErr = append(savedErr, "dsa: "+err.Error())

	return nil, errors.New("failed to parse private key, make sure to use PKCS1 for RSA and PKCS8 for (EC)DSA. errors: " + strings.Join(savedErr, ";;; "))
}

// parseDSAPKCS8PrivateKey returns a DSA private key from its ASN.1 DER encoding
func parseDSAPKCS8PrivateKey(der []byte) (*dsa.PrivateKey, error) {
	var k struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Priv    []byte
	}
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("garbage after DSA key")
	}
	var params dsa.Parameters
	_, err = asn1.Unmarshal(k.Algo.Parameters.FullBytes, &params)
	if err != nil {
		return nil, err
	}
	// FIXME: couldn't get asn1.Unmarshal to properly parse the OCTET STRING
	// tag in front of the X value of the DSA key, but doing it manually by
	// stripping off the first two bytes and loading it as a bigint works
	if len(k.Priv) < 22 {
		return nil, errors.New("DSA key is too short")
	}
	x := new(big.Int).SetBytes(k.Priv[2:])
	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
		},
		X: x,
	}, nil
}

// StatsClient is a helper for sending statsd stats with the relevant
// tags for the signer and error handling
type StatsClient struct {
	// signerTags is the
	signerTags []string

	// stats is the statsd client for reporting metrics
	stats *statsd.Client
}

// NewStatsClient makes a new stats client
func NewStatsClient(signerConfig Configuration, stats *statsd.Client) (*StatsClient, error) {
	if stats == nil {
		return nil, errors.Errorf("xpi: statsd client is nil. Could not create StatsClient for signer %s", signerConfig.ID)
	}
	return &StatsClient{
		stats: stats,
		signerTags: []string{
			fmt.Sprintf("autograph-signer-id:%s", signerConfig.ID),
			fmt.Sprintf("autograph-signer-type:%s", signerConfig.Type),
			fmt.Sprintf("autograph-signer-mode:%s", signerConfig.Mode),
		},
	}, nil
}

// SendGauge checks for a statsd client and when one is present sends
// a statsd gauge with the given name, int value cast to float64, tags
// for the signer, and sampling rate of 1
func (s *StatsClient) SendGauge(name string, value int) {
	if s.stats == nil {
		log.Warnf("xpi: statsd client is nil. Could not send gauge %s with value %v", name, value)
		return
	}
	err := s.stats.Gauge(name, float64(value), s.signerTags, 1)
	if err != nil {
		log.Warnf("Error sending gauge %s: %s", name, err)
	}
}

// SendHistogram checks for a statsd client and when one is present
// sends a statsd histogram with the given name, time.Duration value
// converted to ms, cast to float64, tags for the signer, and sampling
// rate of 1
func (s *StatsClient) SendHistogram(name string, value time.Duration) {
	if s.stats == nil {
		log.Warnf("xpi: statsd client is nil. Could not send histogram %s with value %s", name, value)
		return
	}
	err := s.stats.Histogram(name, float64(value/time.Millisecond), s.signerTags, 1)
	if err != nil {
		log.Warnf("Error sending histogram %s: %s", name, err)
	}
}

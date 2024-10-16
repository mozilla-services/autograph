package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
	"github.com/mozilla-services/autograph/crypto11"
)

type HSM interface {
	GetPrivateKey(label []byte) (crypto.PrivateKey, error)
	// MakeKey generates a new keypair of type `keyTpl` and returns the new key structs.
	MakeKey(keyTpl interface{}, keyName string) (crypto.PrivateKey, crypto.PublicKey, error)
	GetRand() io.Reader
}

type GenericHSM struct {
	ctx crypto11.PKCS11Context
}

// GetPrivateKey locates the keypair given by `label` in the HSM.
func (hsm *GenericHSM) GetPrivateKey(label []byte) (crypto.PrivateKey, error) {
	return crypto11.FindKeyPair(nil, label)
}

type AWSHSM struct {
	GenericHSM
}

func (hsm *AWSHSM) GetRand() io.Reader {
	return new(crypto11.PKCS11RandReader)
}

func (hsm *AWSHSM) MakeKey(keyTpl interface{}, keyName string) (crypto.PrivateKey, crypto.PublicKey, error) {
	var slots []uint
	slots, err := hsm.ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list PKCS#11 Slots: %w", err)
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("failed to find a usable slot in hsm context")
	}
	keyNameBytes := []byte(keyName)
	switch keyTplType := keyTpl.(type) {
	case *ecdsa.PublicKey:
		priv, err := crypto11.GenerateECDSAKeyPairOnSlot(slots[0], keyNameBytes, keyNameBytes, keyTplType)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ecdsa key in hsm: %w", err)
		}
		pub := priv.PubKey.(*ecdsa.PublicKey)
		return priv, pub, nil
	case *rsa.PublicKey:
		keySize := keyTplType.Size()
		priv, err := crypto11.GenerateRSAKeyPairOnSlot(slots[0], keyNameBytes, keyNameBytes, keySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate rsa key in hsm: %w", err)
		}
		pub := priv.PubKey.(*rsa.PublicKey)
		return priv, pub, nil
	default:
		return nil, nil, fmt.Errorf("making key of type %T is not supported", keyTpl)
	}
}

func NewAWSHSM(ctx crypto11.PKCS11Context) *AWSHSM {
	return &AWSHSM{
		GenericHSM{
			ctx,
		},
	}
}

// Constants from https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/kmsp11.h
// that are needed when generating ECDSA or RSA keys in GCP KMS.

// A marker for a PKCS #11 attribute or flag defined by Google.
// (Note that 0x80000000UL is CKA_VENDOR_DEFINED).
const CKA_GOOGLE_DEFINED = 0x80000000 | 0x1E100

// An attribute that indicates the backing CryptoKeyVersionAlgorithm in Cloud
// KMS.
const CKA_KMS_ALGORITHM = CKA_GOOGLE_DEFINED | 0x01

// ECDSA on the NIST P-256 curve with a SHA256 digest.
const KMS_ALGORITHM_EC_SIGN_P256_SHA256 = 12

// ECDSA on the NIST P-384 curve with a SHA384 digest.
const KMS_ALGORITHM_EC_SIGN_P384_SHA384 = 13

// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
const KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256 = 5

// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
const KMS_ALGORITHM_RSA_SIGN_PKCS1_3072_SHA256 = 6

// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
const KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA256 = 7

// Our own constant; simply a shortcut for a combination we use in a few places
const CKA_GOOGLE_DEFINED_KMS_ALGORITHM = CKA_GOOGLE_DEFINED | CKA_KMS_ALGORITHM

type GCPHSM struct {
	GenericHSM
}

type unlimitedBytesRandReader struct {
	rr crypto11.PKCS11RandReader
}

func (ubrr *unlimitedBytesRandReader) Read(data []byte) (int, error) {
	var n int
	var err error
	need := len(data)
	for need > 0 {
		var bytesRead int
		next := min(need, 1024)
		bytesRead, err = ubrr.rr.Read(data[n : n+next])
		n += bytesRead
		if err != nil {
			return n, err
		}
		need -= bytesRead
	}
	return n, err
}

// GCPHSM.GetRand returns an io.Reader that can generate an unlimited
// number of bytes from a crypto11.PKCS11RandReader. This is needed because
// GCP KMS can generate a maximum of 1024 bytes per call.
// https://cloud.google.com/kms/docs/generate-random#known_limitations
func (hsm *GCPHSM) GetRand() io.Reader {
	return new(unlimitedBytesRandReader)
}

func (hsm *GCPHSM) MakeKey(keyTpl interface{}, keyName string) (crypto.PrivateKey, crypto.PublicKey, error) {
	var slots []uint
	slots, err := hsm.ctx.GetSlotList(true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list PKCS#11 Slots: %w", err)
	}
	if len(slots) < 1 {
		return nil, nil, fmt.Errorf("failed to find a usable slot in hsm context")
	}
	publicKeyTemplate := []*pkcs11.Attribute{}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(keyName)),
	}
	switch keyTplType := keyTpl.(type) {
	case *ecdsa.PublicKey:
		size := keyTplType.Params().BitSize
		switch size {
		case 256:
			privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_EC_SIGN_P256_SHA256))
		case 384:
			privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_EC_SIGN_P384_SHA384))
		default:
			return nil, nil, fmt.Errorf("invalid elliptic curve: must be p256 or p384")
		}

		priv, err := crypto11.GenerateECDSAKeyPairOnSlotWithProvidedAttributes(slots[0], publicKeyTemplate, privateKeyTemplate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ecdsa key in hsm: %w", err)
		}
		pub := priv.PubKey.(*ecdsa.PublicKey)
		return priv, pub, nil

	case *rsa.PublicKey:
		keySizeBytes := keyTplType.Size()
		switch keySizeBytes {
		case 256:
			privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256))
		case 384:
			privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_RSA_SIGN_PKCS1_3072_SHA256))
		case 512:
			privateKeyTemplate = append(privateKeyTemplate, pkcs11.NewAttribute(CKA_GOOGLE_DEFINED_KMS_ALGORITHM, KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA256))
		default:
			return nil, nil, fmt.Errorf("invalid rsa key size: got: %d", keySizeBytes)
		}

		priv, err := crypto11.GenerateRSAKeyPairOnSlotWithProvidedAttributes(slots[0], publicKeyTemplate, privateKeyTemplate)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate rsa key in hsm: %w", err)
		}
		pub := priv.PubKey.(*rsa.PublicKey)
		return priv, pub, nil
	}

	return nil, nil, fmt.Errorf("making key of type %T is not supported", keyTpl)
}

func NewGCPHSM(ctx crypto11.PKCS11Context) *GCPHSM {
	return &GCPHSM{
		GenericHSM{
			ctx,
		},
	}
}

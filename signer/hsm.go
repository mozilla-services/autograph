package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/mozilla-services/autograph/crypto11"
)

type HSM interface {
	GetPrivateKey(label []byte) (crypto.PrivateKey, error)
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

func (hsm *GenericHSM) GetRand() io.Reader {
	return new(crypto11.PKCS11RandReader)
}

type AWSHSM struct {
	GenericHSM
}

// MakeKey generates a new keypair of type `keyTpl` and returns the new key structs.
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

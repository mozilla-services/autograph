package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"

	margo "go.mozilla.org/mar"
)

func verifyMARSignature(b64Sig, b64Key string) error {
	sig, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return err
	}
	rawKey, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return err
	}
	key, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return err
	}
	sigalg := margo.SigAlgRsaPkcs1Sha384
	switch pubKey := key.(type) {
	case *ecdsa.PublicKey:
		switch pubKey.Params().Name {
		case elliptic.P256().Params().Name:
			sigalg = margo.SigAlgEcdsaP256Sha256
		case elliptic.P384().Params().Name:
			sigalg = margo.SigAlgEcdsaP384Sha384
		}
	}
	return margo.VerifySignature([]byte(inputdata), sig, uint32(sigalg), key)
}

// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fakekms

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// algDef contains details about a KMS algorithm
type algDef struct {
	Purpose    kmspb.CryptoKey_CryptoKeyPurpose
	KeyFactory keyFactory
	Opts       interface{}
}

func (a algDef) Asymmetric() bool {
	switch a.Purpose {
	case kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ASYMMETRIC_SIGN:
		return true
	default:
		return false
	}
}

// algorithms maps KMS algorithms to their definitions
var algorithms = map[kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm]algDef{
	// ENCRYPT_DECRYPT
	kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION: {
		Purpose:    kmspb.CryptoKey_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(256),
	},

	// RAW_ENCRYPT_DECRYPT
	kmspb.CryptoKeyVersion_AES_128_GCM: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(128),
	},
	kmspb.CryptoKeyVersion_AES_256_GCM: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(256),
	},
	kmspb.CryptoKeyVersion_AES_128_CTR: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(128),
	},
	kmspb.CryptoKeyVersion_AES_256_CTR: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(256),
	},
	kmspb.CryptoKeyVersion_AES_128_CBC: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(128),
	},
	kmspb.CryptoKeyVersion_AES_256_CBC: {
		Purpose:    kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
		KeyFactory: symmetricKeyFactory(256),
	},

	// ASYMMETRIC_DECRYPT
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		KeyFactory: rsaKeyFactory(2048),
		Opts:       &rsa.OAEPOptions{Hash: crypto.SHA256},
	},
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		KeyFactory: rsaKeyFactory(3072),
		Opts:       &rsa.OAEPOptions{Hash: crypto.SHA256},
	},
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       &rsa.OAEPOptions{Hash: crypto.SHA256},
	},
	kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       &rsa.OAEPOptions{Hash: crypto.SHA512},
	},

	// ASYMMETRIC_SIGN

	// ECDSA
	kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(11): // EC_SIGN_P224_SHA256
	{
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: &ecKeyFactory{elliptic.P224()},
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: &ecKeyFactory{elliptic.P256()},
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: &ecKeyFactory{elliptic.P384()},
		Opts:       crypto.SHA384,
	},
	kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm(14): // EC_SIGN_P521_SHA512
	{
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: &ecKeyFactory{elliptic.P521()},
		Opts:       crypto.SHA512,
	},

	// RSASSA-PKCS1-v1_5
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(2048),
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(3072),
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       crypto.SHA512,
	},

	// RSASSA-PSS
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(2048),
		Opts:       &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(3072),
		Opts:       &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash},
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       &rsa.PSSOptions{Hash: crypto.SHA512, SaltLength: rsa.PSSSaltLengthEqualsHash},
	},

	// RSASSA-PKCS1-v1_5 (Raw)
	kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(2048),
		Opts:       crypto.Hash(0),
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(3072),
		Opts:       crypto.Hash(0),
	},
	kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096: {
		Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
		KeyFactory: rsaKeyFactory(4096),
		Opts:       crypto.Hash(0),
	},

	// MAC

	kmspb.CryptoKeyVersion_HMAC_SHA1: {
		Purpose:    kmspb.CryptoKey_MAC,
		KeyFactory: symmetricKeyFactory(160),
		Opts:       crypto.SHA1,
	},
	kmspb.CryptoKeyVersion_HMAC_SHA224: {
		Purpose:    kmspb.CryptoKey_MAC,
		KeyFactory: symmetricKeyFactory(224),
		Opts:       crypto.SHA224,
	},
	kmspb.CryptoKeyVersion_HMAC_SHA256: {
		Purpose:    kmspb.CryptoKey_MAC,
		KeyFactory: symmetricKeyFactory(256),
		Opts:       crypto.SHA256,
	},
	kmspb.CryptoKeyVersion_HMAC_SHA384: {
		Purpose:    kmspb.CryptoKey_MAC,
		KeyFactory: symmetricKeyFactory(384),
		Opts:       crypto.SHA384,
	},
	kmspb.CryptoKeyVersion_HMAC_SHA512: {
		Purpose:    kmspb.CryptoKey_MAC,
		KeyFactory: symmetricKeyFactory(512),
		Opts:       crypto.SHA512,
	},
}

// nameForValue retrieves the mapped name corresponding to value, or a string representation
// of the numeric value if the value is unknown.
func nameForValue(names map[int32]string, value int32) string {
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprintf("%d", value)
}

// validateProtectionLevel returns nil on success, or Unimplemented if the supplied protection
// level is not supported. Note that PROTECTION_LEVEL_UNSPECIFIED is not a supported level.
func validateProtectionLevel(pl kmspb.ProtectionLevel) error {
	switch pl {
	case kmspb.ProtectionLevel_SOFTWARE, kmspb.ProtectionLevel_HSM,
		kmspb.ProtectionLevel_HSM_SINGLE_TENANT:
		return nil
	default:
		return errUnimplemented("unsupported protection level: %s",
			nameForValue(kmspb.ProtectionLevel_name, int32(pl)))
	}
}

// algorithmDef returns an algDef corresponding to the supplied algorithm, or Unimplemented
// if the algorithm is not supported.
func algorithmDef(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) (algDef, error) {
	def, ok := algorithms[alg]
	if !ok {
		return algDef{}, errUnimplemented("unsupported algorithm: %s",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(alg)))
	}
	return def, nil
}

// validateAlgorithm returns nil on success, Unimplemented if the supplied algorithm is not
// supported, or InvalidArgument if the algorithm is inconsistent with the supplied purpose.
// Note that CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED is not a supported algorithm.
func validateAlgorithm(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm, purpose kmspb.CryptoKey_CryptoKeyPurpose) error {
	def, err := algorithmDef(alg)
	if err != nil {
		return err
	}
	if purpose != def.Purpose {
		return errInvalidArgument("algorithm %s is not valid for purpose %s",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(alg)),
			nameForValue(kmspb.CryptoKey_CryptoKeyPurpose_name, int32(purpose)))
	}
	return nil
}

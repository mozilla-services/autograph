// COSE Algorithms
//

package cose

import (
	"crypto"
	"crypto/elliptic"
)

// KeyType is the type to use in keyOptions to tell MakeDEREndEntity
// which type of crypto.PrivateKey to generate
type KeyType int
const (
	// KeyTypeUnsupported is the type to not generate a key
	KeyTypeUnsupported KeyType = iota

	// KeyTypeRSA is the type to generate an rsa.PrivateKey
	KeyTypeRSA KeyType = iota

	// KeyTypeECDSA is the type to generate an ecdsa.PrivateKey
	KeyTypeECDSA KeyType = iota
)

// Algorithm represents an IANA algorithm's parameters (Name,
// Value/ID, and optional extra data)
//
// From the spec:
//
// NOTE: The assignment of algorithm identifiers in this document was
// done so that positive numbers were used for the first layer objects
// (COSE_Sign, COSE_Sign1, COSE_Encrypt, COSE_Encrypt0, COSE_Mac, and
// COSE_Mac0).  Negative numbers were used for second layer objects
// (COSE_Signature and COSE_recipient).
//
// https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters
//
// https://tools.ietf.org/html/rfc8152#section-16.4
//
type Algorithm struct {
	Name               string
	Value              int

	// optional fields
	HashFunc           crypto.Hash    // hash function for SignMessages
	privateKeyType     KeyType        // private key type to generate for new Signers

	minRSAKeyBitLen    int            // minimimum RSA key size to generate in bits

	privateKeyECDSACurve    elliptic.Curve // ecdsa private key curve type
}

// algorithms is an array/slice of IANA algorithms
var algorithms = []Algorithm{
	Algorithm{
		Name:  "RSAES-OAEP w/ SHA-512", // RSAES-OAEP w/ SHA-512 from [RFC8230]
		Value: -42,
	},
	Algorithm{
		Name:  "RSAES-OAEP w/ SHA-256", // RSAES-OAEP w/ SHA-256 from [RFC8230]
		Value: -41,
	},
	Algorithm{
		Name:  "RSAES-OAEP w/ RFC 8017 default parameters", // RSAES-OAEP w/ SHA-1 from [RFC8230]
		Value: -40,
	},
	Algorithm{
		Name:  "PS512", // RSASSA-PSS w/ SHA-512 from [RFC8230]
		Value: -39,
	},
	Algorithm{
		Name:  "PS384", // RSASSA-PSS w/ SHA-384 from [RFC8230]
		Value: -38,
	},
	Algorithm{
		Name:            "PS256", // RSASSA-PSS w/ SHA-256 from [RFC8230]
		Value:           -37,
		HashFunc:        crypto.SHA256,
		privateKeyType:  KeyTypeRSA,
		minRSAKeyBitLen: 2048,
	},
	Algorithm{
		Name:               "ES512", // ECDSA w/ SHA-512 from [RFC8152]
		Value:              -36,
		HashFunc:           crypto.SHA512,
		privateKeyType:     KeyTypeECDSA,
		privateKeyECDSACurve:    elliptic.P521(),
	},
	Algorithm{
		Name:               "ES384", // ECDSA w/ SHA-384 from [RFC8152]
		Value:              -35,
		HashFunc:           crypto.SHA384,
		privateKeyType:     KeyTypeECDSA,
		privateKeyECDSACurve:    elliptic.P384(),
	},
	Algorithm{
		Name:  "ECDH-SS + A256KW", // ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -34,
	},
	Algorithm{
		Name:  "ECDH-SS + A192KW", // ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -33,
	},
	Algorithm{
		Name:  "ECDH-SS + A128KW", // ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -32,
	},
	Algorithm{
		Name:  "ECDH-ES + A256KW", // ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -31,
	},
	Algorithm{
		Name:  "ECDH-ES + A192KW", // ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -30,
	},
	Algorithm{
		Name:  "ECDH-ES + A128KW", // ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -29,
	},
	Algorithm{
		Name:  "ECDH-SS + HKDF-512", // ECDH SS w/ HKDF - generate key directly from [RFC8152]
		Value: -28,
	},
	Algorithm{
		Name:  "ECDH-SS + HKDF-256", // ECDH SS w/ HKDF - generate key directly from [RFC8152]
		Value: -27,
	},
	Algorithm{
		Name:  "ECDH-ES + HKDF-512", // ECDH ES w/ HKDF - generate key directly from [RFC8152]
		Value: -26,
	},
	Algorithm{
		Name:  "ECDH-ES + HKDF-256", // ECDH ES w/ HKDF - generate key directly from [RFC8152]
		Value: -25,
	},
	Algorithm{
		Name:  "direct+HKDF-AES-256", // Shared secret w/ AES-MAC 256-bit key from [RFC8152]
		Value: -13,
	},
	Algorithm{
		Name:  "direct+HKDF-AES-128", // Shared secret w/ AES-MAC 128-bit key from [RFC8152]
		Value: -12,
	},
	Algorithm{
		Name:  "direct+HKDF-SHA-512", // Shared secret w/ HKDF and SHA-512 from [RFC8152]
		Value: -11,
	},
	Algorithm{
		Name:  "direct+HKDF-SHA-256", // Shared secret w/ HKDF and SHA-256 from [RFC8152]
		Value: -10,
	},
	Algorithm{
		Name:  "EdDSA", // EdDSA from [RFC8152]
		Value: -8,
	},
	Algorithm{
		Name:               "ES256", // ECDSA w/ SHA-256 from [RFC8152]
		Value:              -7,
		HashFunc:           crypto.SHA256,
		privateKeyType:     KeyTypeECDSA,
		privateKeyECDSACurve:    elliptic.P256(),
	},
	Algorithm{
		Name:  "direct", // Direct use of CEK from [RFC8152]
		Value: -6,
	},
	Algorithm{
		Name:  "A256KW", // AES Key Wrap w/ 256-bit key from [RFC8152]
		Value: -5,
	},
	Algorithm{
		Name:  "A192KW", // AES Key Wrap w/ 192-bit key from [RFC8152]
		Value: -4,
	},
	Algorithm{
		Name:  "A128KW", // AES Key Wrap w/ 128-bit key from [RFC8152]
		Value: -3,
	},
	Algorithm{
		Name:  "A128GCM", // AES-GCM mode w/ 128-bit key, 128-bit tag from [RFC8152]
		Value: 1,
	},
	Algorithm{
		Name:  "A192GCM", // AES-GCM mode w/ 192-bit key, 128-bit tag from [RFC8152]
		Value: 2,
	},
	Algorithm{
		Name:  "A256GCM", // AES-GCM mode w/ 256-bit key, 128-bit tag from [RFC8152]
		Value: 3,
	},
	Algorithm{
		Name:  "HMAC 256/64", // HMAC w/ SHA-256 truncated to 64 bits from [RFC8152]
		Value: 4,
	},
	Algorithm{
		Name:  "HMAC 256/256", // HMAC w/ SHA-256 from [RFC8152]
		Value: 5,
	},
	Algorithm{
		Name:  "HMAC 384/384", // HMAC w/ SHA-384 from [RFC8152]
		Value: 6,
	},
	Algorithm{
		Name:  "HMAC 512/512", // HMAC w/ SHA-512 from [RFC8152]
		Value: 7,
	},
	Algorithm{
		Name:  "AES-CCM-16-64-128", // AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce from [RFC8152]
		Value: 10,
	},
	Algorithm{
		Name:  "AES-CCM-16-64-256", // AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce from [RFC8152]
		Value: 11,
	},
	Algorithm{
		Name:  "AES-CCM-64-64-128", // AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce from [RFC8152]
		Value: 12,
	},
	Algorithm{
		Name:  "AES-CCM-64-64-256", // AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce from [RFC8152]
		Value: 13,
	},
	Algorithm{
		Name:  "AES-MAC 128/64", // AES-MAC 128-bit key, 64-bit tag from [RFC8152]
		Value: 14,
	},
	Algorithm{
		Name:  "AES-MAC 256/64", // AES-MAC 256-bit key, 64-bit tag from [RFC8152]
		Value: 15,
	},
	Algorithm{
		Name:  "ChaCha20/Poly1305", // ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag from [RFC8152]
		Value: 24,
	},
	Algorithm{
		Name:  "AES-MAC 128/128", // AES-MAC 128-bit key, 128-bit tag from [RFC8152]
		Value: 25,
	},
	Algorithm{
		Name:  "AES-MAC 256/128", // AES-MAC 256-bit key, 128-bit tag from [RFC8152]
		Value: 26,
	},
	Algorithm{
		Name:  "AES-CCM-16-128-128", // AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce from [RFC8152]
		Value: 30,
	},
	Algorithm{
		Name:  "AES-CCM-16-128-256", // AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce from [RFC8152]
		Value: 31,
	},
	Algorithm{
		Name:  "AES-CCM-64-128-128", // AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce from [RFC8152]
		Value: 32,
	},
	Algorithm{
		Name:  "AES-CCM-64-128-256", // AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce from [RFC8152]
		Value: 33,
	},
}

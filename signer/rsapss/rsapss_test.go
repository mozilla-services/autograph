package rsapss

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"

	"encoding/base64"
	"testing"

	"go.mozilla.org/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *RSAPSSSigner {
	s, err := New(rsapsssignerconf)
	if s == nil {
		t.Fatal("expected non-nil signer for valid conf, but got nil signer")
	}
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	return s
}

func assertNewSignerWithConfErrs(t *testing.T, invalidConf signer.Configuration) {
	s, err := New(invalidConf)
	if s != nil {
		t.Fatalf("expected nil signer for invalid conf, but got non-nil signer %v", s)
	}
	if err == nil {
		t.Fatal("signer initialization did not fail")
	}
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		_ = assertNewSignerWithConfOK(t, rsapsssignerconf)
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PublicKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.PublicKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PEM PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.PrivateKey = "NOT VALID PEM"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("non-RSA PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsapsssignerconf
		invalidConf.PrivateKey = nonRSAPrivateKey
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, rsapsssignerconf)

	if s.Config().Type != rsapsssignerconf.Type {
		t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, rsapsssignerconf.Type)
	}
	if s.Config().ID != rsapsssignerconf.ID {
		t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, rsapsssignerconf.ID)
	}
	if s.Config().PrivateKey != rsapsssignerconf.PrivateKey {
		t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, rsapsssignerconf.PrivateKey)
	}

	// decode public key
	keyBytes, err := base64.StdEncoding.DecodeString(s.Config().PublicKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key DER: %v", err)
	}
	_, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed public key was not rsa")
	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, rsapsssignerconf)
	defaultOpts := s.GetDefaultOptions()
	expectedOpts := Options{}
	if defaultOpts != expectedOpts {
		t.Fatalf("signer returned unexpected default options: %v", defaultOpts)
	}
}

func TestUnmarshal(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal("invalid!base64")
	if err == nil {
		t.Fatalf("Signature Unmarshal did not faile for invalid base64 bytes")
	}
}

func TestSignHash(t *testing.T) {
	input := []byte("this is the sha1 input")
	shasum := sha1.Sum(input)
	digest := shasum[:]

	// initialize a signer
	s := assertNewSignerWithConfOK(t, rsapsssignerconf)

	// sign input data
	sig, err := s.SignHash(digest, s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// convert signature to string format
	sigstr, err := sig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	t.Run("Rejects invalid input length", func(t *testing.T) {
		t.Parallel()

		_, err := s.SignHash([]byte("too short"), s.GetDefaultOptions())
		if err == nil {
			t.Fatalf("failed to throw error for invalid data length")
		}
	})

	t.Run("MarshalRoundTrip", func(t *testing.T) {
		t.Parallel()

		// convert string format back to signature
		sig2, err := Unmarshal(sigstr)
		if err != nil {
			t.Fatalf("failed to unmarshal signature: %v", err)
		}

		if !bytes.Equal(sig.(*Signature).Data, sig2.(*Signature).Data) {
			t.Fatalf("marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
				sig.(*Signature).Data, sig2.(*Signature).Data)
		}
	})

	t.Run("Verifies", func(t *testing.T) {
		t.Parallel()

		rsaKey := s.key.(*rsa.PrivateKey)
		pubKey := rsaKey.Public()
		err := VerifySignature(pubKey.(*rsa.PublicKey), digest, sig.(*Signature).Data)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	})
}

func TestSignData(t *testing.T) {
	input := []byte("this is the sha1 input")
	shasum := sha1.Sum(input)
	digest := shasum[:]

	// initialize a signer
	s := assertNewSignerWithConfOK(t, rsapsssignerconf)

	// sign input data
	sig, err := s.SignData(input, s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// convert signature to string format
	_, err = sig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	t.Run("Verifies", func(t *testing.T) {
		t.Parallel()

		rsaKey := s.key.(*rsa.PrivateKey)
		pubKey := rsaKey.Public()
		err := VerifySignature(pubKey.(*rsa.PublicKey), digest, sig.(*Signature).Data)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	})
}

func TestVerifySignatureFromB64(t *testing.T) {
	t.Parallel()

	// initialize a signer and compute base64 args
	var (
		_input  = []byte("this is the sha1 input")
		_shasum = sha1.Sum(_input)
		_digest = _shasum[:]
		_s      = assertNewSignerWithConfOK(t, rsapsssignerconf)
		_b64Sig string
	)

	_sig, err := _s.SignData(_input, _s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// convert signature to base64 string
	_b64Sig, err = _sig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	// args to VerifySignatureFromB64
	var (
		b64Digest = base64.StdEncoding.EncodeToString(_digest)
		b64PubKey = _s.PublicKey // base64 encoded in signer GetKeys
		b64Sig    = _b64Sig
	)

	t.Run("verifies valid input", func(t *testing.T) {
		t.Parallel()

		// unencoded verification should pass
		rsaKey := _s.key.(*rsa.PrivateKey)
		pubKey := rsaKey.Public()
		err := VerifySignature(pubKey.(*rsa.PublicKey), _digest, _sig.(*Signature).Data)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}

		err = VerifySignatureFromB64(b64Digest, b64Sig, b64PubKey)
		if err != nil {
			t.Fatalf("failed to verify valid input: %s", err)
		}
	})

	t.Run("fails for invalid b64 input", func(t *testing.T) {
		t.Parallel()

		err := VerifySignatureFromB64("aieeee", b64Sig, b64PubKey)
		if err == nil {
			t.Fatal("did not to fail for invalid input")
		}
	})

	t.Run("fails for invalid b64 sig", func(t *testing.T) {
		t.Parallel()

		err := VerifySignatureFromB64(b64Digest, "aieeee", b64PubKey)
		if err == nil {
			t.Fatal("did not to fail for invalid sig")
		}
	})

	t.Run("fails for invalid b64 pubkey", func(t *testing.T) {
		t.Parallel()

		err := VerifySignatureFromB64(b64Digest, b64Sig, "aieeee")
		if err == nil {
			t.Fatal("did not to fail for invalid pubkey")
		}
	})

	t.Run("fails for invalid pubkey pem", func(t *testing.T) {
		t.Parallel()

		err := VerifySignatureFromB64(b64Digest, b64Sig, "")
		if err == nil {
			t.Fatal("did not to fail for invalid pub key PEM block")
		}
	})

	t.Run("fails for invalid pubkey type", func(t *testing.T) {
		t.Parallel()

		err := VerifySignatureFromB64(b64Digest, b64Sig, base64.StdEncoding.EncodeToString([]byte(nonRSAPrivateKey)))
		if err == nil {
			t.Fatal("did not to fail for bad pem key type")
		}
	})
}

const nonRSAPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`

var rsapsssignerconf = signer.Configuration{
	ID:   "rsapsstest",
	Type: Type,
	PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtEM/Vdfd4Vl9wmeVdCYuWYnQl0Zc9RW5hLE4hFA+c277qanE
8XCK+ap/c5so87XngLLfacB3zZhGxIOut/4SlEBOAUmVNCfnTO+YkRk3A8OyJ4XN
qdn+/ov78ZbssGf+0zws2BcwZYwhtuTvro3yi62FQ7T1TpT5VjljH7sHW/iZnS/R
KiY4DwqAN799gkB+Gwovtroabh2w5OX0P+PYyUbJLFQeo5uiAQ8cAXTlHqCkj11G
YgU4ttVDuFGotKRyaRn1F+yKxE4LQcAULx7s0KzvS35mNU+MoywLWjy9a4TcjK0n
q+BjspKX4UkNwVstvH18hQWun7E+dxTi59cRmwIDAQABAoIBAEKpi8aHKfqoSaWX
AOIPLJzYJleLId1Qx2aW0zu7IR03McIwkjBnWj2yG6f4/VADOTWS8KP/FU7mvWT2
/an1P5Grpi07tP2wtAzzngwqsvmlaUDMbp4di/s+cVGKasVh8A7V9g+Do9Yp2F32
k9yNieC1rs63IPCKjxqf5lRZqgMMcL1QYSlJI98riSVGm0m29u1v3pN6qDVNto2d
l6m6D8UT6vx1lfVZFV+Td3FmYHnuYyVwbgJ8dFRBQFpe2tsccK955+lapFe9MA/o
Xa5VfAWJ7YoLcgfssxF7atpHt2wcpvEj6NfIHfeDdExQ+Vd9T8vQGh88wd32QcTa
w1RiQUECgYEA7OFpsduOHqgqVSf1nIH6RPLytzzoXXd8Bs1aXWCxy45xg7lkKG+x
8Fa4aUFDII9RR4N7YFfUh8LwKF56BwFePbP4wwCuhz9v2E24I6/EfLD2GuRSv+B/
gNRG+suE5yCmeGlRC0uhASLr3ZzmGs16Mus/ytL5XPl8CJCmsVMjPHMCgYEAws/1
Sm2KOoYFY1+7ACMF89FyesOpTpqLvND79soNPC4Tl1PrPw4bsNA6p2BD1N2SPFiH
0yo7msNqh5o90wdnYA7i1uDWhcvrFnbg4e8+RhghcG/dJW33Lm5d5knST4NQxnAO
z/0zXgB9PSnsgFzNgm6LE++/KBZs/CbxQUPb9DkCgYEAk58eiVK0TPKr/wm6DOEL
oLBvBjaU8Lqntm1/ZTX/V0XcBCUi//grwgWpQx8CwGXQV2rfFnll331iwSWvknIN
0xI3cv8XxP2JrBkzKjo9jx+RH80urJkxnI2t9lmi5473b47ijNGC8vxaVW+UDxwC
jX0B8lpsQL7Rx1yuJVAUY3UCgYEAtG8gZZsnWCUhgHT+IpZNwRHQ0lu+yIrjujJl
7KIfuAmFI7gaPwC2LQHwEW5b5SCDfVkSFEcdha5RUN9PO9GzsYiYGSWOC8ZfKyNY
DmskZo+bCSTS0wQS2PJoDg95tyONAP5w+bsuhHY3iRr3bbyGq7PvJLv9dQewUatP
8H8FjiECgYBt93fZADyyOoqeYxMc8b38F8sf1FLTOAUfB1ik5R4yNVKDaCanYhYc
poTajMUVdoBcEV1g5Vds8objUIeNNlMPKyUnf/lCiPvp43wYbC3y60JqzXX3bfAS
TDd4Me4PP+sTZeJ3RKvArDiMzEncDeMGZZnd4dBdi3LjzCNGTANAGw==
-----END RSA PRIVATE KEY-----`,
	PublicKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEM/Vdfd4Vl9wmeVdCYu
WYnQl0Zc9RW5hLE4hFA+c277qanE8XCK+ap/c5so87XngLLfacB3zZhGxIOut/4S
lEBOAUmVNCfnTO+YkRk3A8OyJ4XNqdn+/ov78ZbssGf+0zws2BcwZYwhtuTvro3y
i62FQ7T1TpT5VjljH7sHW/iZnS/RKiY4DwqAN799gkB+Gwovtroabh2w5OX0P+PY
yUbJLFQeo5uiAQ8cAXTlHqCkj11GYgU4ttVDuFGotKRyaRn1F+yKxE4LQcAULx7s
0KzvS35mNU+MoywLWjy9a4TcjK0nq+BjspKX4UkNwVstvH18hQWun7E+dxTi59cR
mwIDAQAB
-----END PUBLIC KEY-----`,
}

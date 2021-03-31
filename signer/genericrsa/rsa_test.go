package genericrsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"hash"

	"github.com/mozilla-services/autograph/formats"

	"encoding/base64"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *RSASigner {
	s, err := New(conf)
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

		_ = assertNewSignerWithConfOK(t, rsaSignerConfs[0])
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PublicKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.PublicKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PEM PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.PrivateKey = "NOT VALID PEM"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("non-RSA PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := rsaSignerConfs[0]
		invalidConf.PrivateKey = nonRSAPrivateKey
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()

	for i, conf := range rsaSignerConfs {
		s := assertNewSignerWithConfOK(t, conf)

		if s.Config().Type != conf.Type {
			t.Fatalf("in config %d %q, signer type %q does not match configuration %q", i, conf.ID, s.Config().Type, conf.Type)
		}
		if s.Config().ID != conf.ID {
			t.Fatalf("in config %d %q, signer id %q does not match configuration %q", i, conf.ID, s.Config().ID, conf.ID)
		}
		if s.Config().PrivateKey != conf.PrivateKey {
			t.Fatalf("in config %d %q, signer private key %q does not match configuration %q", i, conf.ID, s.Config().PrivateKey, conf.PrivateKey)
		}

		// decode public key
		keyBytes, err := base64.StdEncoding.DecodeString(s.Config().PublicKey)
		if err != nil {
			t.Fatalf("in config %d %q, failed to parse public key: %v", i, conf.ID, err)
		}
		keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			t.Fatalf("in config %d %q, failed to parse public key DER: %v", i, conf.ID, err)
		}
		_, ok := keyInterface.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("in config %d %q, parsed public key was not rsa", i, conf.ID)
		}
	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, rsaSignerConfs[0])
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
	input := []byte("this is the hash input")
	for i, conf := range rsaSignerConfs {
		// initialize a signer
		s := assertNewSignerWithConfOK(t, conf)

		var h hash.Hash
		switch s.Hash {
		case "sha1":
			h = sha1.New()
		case "sha256":
			h = sha256.New()
		}
		h.Write(input)
		digest := h.Sum(nil)

		// sign input data
		sig, err := s.SignHash(digest, s.GetDefaultOptions())
		if err != nil {
			t.Fatalf("in config %d %q, failed to sign data: %v", i, conf.ID, err)
		}

		// convert signature to string format
		sigstr, err := sig.Marshal()
		if err != nil {
			t.Fatalf("in config %d %q, failed to marshal signature: %v", i, conf.ID, err)
		}

		t.Run("Rejects invalid input length", func(t *testing.T) {
			t.Parallel()

			_, err := s.SignHash([]byte("too short"), s.GetDefaultOptions())
			if err == nil {
				t.Fatalf("in config %d %q, failed to throw error for invalid data length", i, conf.ID)
			}
		})

		t.Run("MarshalRoundTrip", func(t *testing.T) {
			t.Parallel()

			// convert string format back to signature
			sig2, err := Unmarshal(sigstr)
			if err != nil {
				t.Fatalf("in config %d %q, failed to unmarshal signature: %v", i, conf.ID, err)
			}

			if !bytes.Equal(sig.(*Signature).Data, sig2.(*Signature).Data) {
				t.Fatalf("in config %d %q, marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
					i, conf.ID, sig.(*Signature).Data, sig2.(*Signature).Data)
			}
		})

		t.Run("Verifies", func(t *testing.T) {
			t.Parallel()

			rsaKey := s.key.(*rsa.PrivateKey)
			pubKey := rsaKey.Public()
			err := VerifySignature(input, sig.(*Signature).Data, pubKey.(*rsa.PublicKey), s.sigOpts, s.Mode)
			if err != nil {
				t.Fatalf("in config %d %q, failed to verify signature: %v", i, conf.ID, err)
			}
		})
	}
}

func TestSignData(t *testing.T) {
	input := []byte("this is the input")

	for i, conf := range rsaSignerConfs {

		// initialize a signer
		s := assertNewSignerWithConfOK(t, conf)

		// sign input data
		sig, err := s.SignData(input, s.GetDefaultOptions())
		if err != nil {
			t.Fatalf("in config %d %q, failed to sign data: %v", i, conf.ID, err)
		}

		// convert signature to string format
		_, err = sig.Marshal()
		if err != nil {
			t.Fatalf("in config %d %q, failed to marshal signature: %v", i, conf.ID, err)
		}

		t.Run("Verifies", func(t *testing.T) {
			t.Parallel()

			rsaKey := s.key.(*rsa.PrivateKey)
			pubKey := rsaKey.Public()
			err := VerifySignature(input, sig.(*Signature).Data, pubKey.(*rsa.PublicKey), s.sigOpts, s.Mode)
			if err != nil {
				t.Fatalf("in config %d %q, failed to verify signature: %v", i, conf.ID, err)
			}
		})
	}
}

func TestVerifySignatureFromB64(t *testing.T) {
	t.Parallel()

	for i, conf := range rsaSignerConfs {

		// initialize a signer and compute base64 args
		var (
			_input  = []byte("this is the input")
			_s      = assertNewSignerWithConfOK(t, conf)
			_b64Sig string
		)

		_sig, err := _s.SignData(_input, _s.GetDefaultOptions())
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}

		// convert signature to base64 string
		_b64Sig, err = _sig.Marshal()
		if err != nil {
			t.Fatalf("in config %d %q, failed to marshal signature: %v", i, conf.ID, err)
		}

		sr := formats.SignatureResponse{
			Type:       _s.Config().Type,
			Mode:       _s.Config().Mode,
			SignerID:   _s.Config().ID,
			PublicKey:  _s.Config().PublicKey,
			Signature:  _b64Sig,
			SignerOpts: _s.Config().SignerOpts,
		}

		t.Run("verifies valid input", func(t *testing.T) {
			t.Parallel()

			// unencoded verification should pass
			rsaKey := _s.key.(*rsa.PrivateKey)
			pubKey := rsaKey.Public()
			err := VerifySignature(_input, _sig.(*Signature).Data, pubKey.(*rsa.PublicKey), _s.sigOpts, _s.Mode)
			if err != nil {
				t.Fatalf("in config %d %q, failed to verify signature: %v", i, conf.ID, err)
			}

			err = VerifyGenericRsaSignatureResponse(_input, sr)
			if err != nil {
				t.Fatalf("in config %d %q, failed to verify valid input: %s", i, conf.ID, err)
			}
		})

		t.Run("fails for invalid b64 input", func(t *testing.T) {
			t.Parallel()
			err = VerifyGenericRsaSignatureResponse([]byte("aieeee"), sr)
			if err == nil {
				t.Fatalf("in config %d %q, did not to fail for invalid input", i, conf.ID)
			}
		})

		t.Run("fails for invalid b64 sig", func(t *testing.T) {
			t.Parallel()
			_sr := sr
			_sr.Signature = "aieeee"
			err = VerifyGenericRsaSignatureResponse(_input, _sr)
			if err == nil {
				t.Fatalf("in config %d %q, did not to fail for invalid sig", i, conf.ID)
			}
		})

		t.Run("fails for invalid b64 pubkey", func(t *testing.T) {
			t.Parallel()
			_sr := sr
			_sr.PublicKey = "aieeee"
			err = VerifyGenericRsaSignatureResponse(_input, _sr)
			if err == nil {
				t.Fatalf("in config %d %q, did not to fail for invalid pubkey", i, conf.ID)
			}
		})

		t.Run("fails for invalid pubkey pem", func(t *testing.T) {
			t.Parallel()
			_sr := sr
			_sr.PublicKey = ""
			err = VerifyGenericRsaSignatureResponse(_input, _sr)
			if err == nil {
				t.Fatalf("in config %d %q, did not to fail for invalid pub key PEM block", i, conf.ID)
			}
		})

		t.Run("fails for invalid pubkey type", func(t *testing.T) {
			t.Parallel()
			_sr := sr
			_sr.PublicKey = base64.StdEncoding.EncodeToString([]byte(nonRSAPrivateKey))
			err = VerifyGenericRsaSignatureResponse(_input, _sr)
			if err == nil {
				t.Fatalf("in config %d %q, did not to fail for bad pem key type", i, conf.ID)
			}
		})
	}
}

const nonRSAPrivateKey = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`

var rsaSignerConfs = []signer.Configuration{
	signer.Configuration{
		ID:         "rsa-pss-sha1-length-equal-hash",
		Type:       Type,
		Mode:       ModePSS,
		Hash:       "sha1",
		SaltLength: -1,
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
	signer.Configuration{
		ID:         "rsa-pss-sha256-length-equal-hash",
		Type:       Type,
		Mode:       ModePSS,
		Hash:       "sha256",
		SaltLength: -1,
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
	signer.Configuration{
		ID:         "rsa-pss-sha1-length-auto",
		Type:       Type,
		Mode:       ModePSS,
		Hash:       "sha1",
		SaltLength: 0,
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
	signer.Configuration{
		ID:         "rsa-pss-sha256-length-auto",
		Type:       Type,
		Mode:       ModePSS,
		Hash:       "sha256",
		SaltLength: 0,
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
	signer.Configuration{
		ID:         "rsa-pkcs15-sha1",
		Type:       Type,
		Mode:       ModePKCS15,
		Hash:       "sha1",
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
	signer.Configuration{
		ID:         "rsa-pkcs15-sha256",
		Type:       Type,
		Mode:       ModePKCS15,
		Hash:       "sha256",
		PrivateKey: standardPrivateKey,
		PublicKey:  standardPublicKey,
	},
}

var standardPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

var standardPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEM/Vdfd4Vl9wmeVdCYu
WYnQl0Zc9RW5hLE4hFA+c277qanE8XCK+ap/c5so87XngLLfacB3zZhGxIOut/4S
lEBOAUmVNCfnTO+YkRk3A8OyJ4XNqdn+/ov78ZbssGf+0zws2BcwZYwhtuTvro3y
i62FQ7T1TpT5VjljH7sHW/iZnS/RKiY4DwqAN799gkB+Gwovtroabh2w5OX0P+PY
yUbJLFQeo5uiAQ8cAXTlHqCkj11GYgU4ttVDuFGotKRyaRn1F+yKxE4LQcAULx7s
0KzvS35mNU+MoywLWjy9a4TcjK0nq+BjspKX4UkNwVstvH18hQWun7E+dxTi59cR
mwIDAQAB
-----END PUBLIC KEY-----`

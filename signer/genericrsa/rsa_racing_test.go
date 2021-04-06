// +build !race

package genericrsa

import (
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/mozilla-services/autograph/formats"
)

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

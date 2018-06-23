package mar

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"go.mozilla.org/autograph/signer"
	margo "go.mozilla.org/mar"
)

func TestSignFile(t *testing.T) {
	for i, marsignerconf := range marsignerconfs {
		// initialize a signer
		s, err := New(marsignerconf)
		if err != nil {
			t.Fatalf("failed to initialize signer %d: %v", i, err)
		}
		t.Logf("testing signer %d %q", i, s.ID)
		if s.Config().Type != marsignerconf.Type {
			t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, marsignerconf.Type)
		}
		if s.Config().ID != marsignerconf.ID {
			t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, marsignerconf.ID)
		}
		if s.Config().PrivateKey != marsignerconf.PrivateKey {
			t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, marsignerconf.PrivateKey)
		}
		// sign input file
		signedMAR, err := s.SignFile(miniMarB, Options{SigAlg: s.defaultSigAlg})
		if err != nil {
			t.Fatalf("failed to sign file: %v", err)
		}
		var parsedMar margo.File
		err = margo.Unmarshal(signedMAR, &parsedMar)
		if err != nil {
			t.Fatalf("failed to parse file: %v", err)
		}
		err = parsedMar.VerifySignature(s.publicKey)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	}
}

func TestSignData(t *testing.T) {
	for i, marsignerconf := range marsignerconfs {
		s, err := New(marsignerconf)
		if err != nil {
			t.Fatalf("failed to initialize signer %d: %v", i, err)
		}
		t.Logf("testing signer %d %q", i, s.ID)
		sig, err := s.SignData([]byte("foo"), Options{SigAlg: s.defaultSigAlg})
		if err != nil {
			t.Fatalf("failed to sign file: %v", err)
		}
		b64Sig, err := sig.Marshal()
		if err != nil {
			t.Fatalf("failed to marshal signature: %v", err)
		}
		sigData, err := base64.StdEncoding.DecodeString(b64Sig)
		if err != nil {
			t.Fatalf("failed to decode base64 signature: %v", err)
		}
		err = margo.VerifySignature([]byte("foo"), sigData, s.defaultSigAlg, s.publicKey)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	}
}

func TestSignHash(t *testing.T) {
	for i, marsignerconf := range marsignerconfs {
		s, err := New(marsignerconf)
		if err != nil {
			t.Fatalf("failed to initialize signer %d: %v", i, err)
		}
		t.Logf("testing signer %d %q", i, s.ID)
		var digest []byte
		switch s.defaultSigAlg {
		case margo.SigAlgRsaPkcs1Sha1:
			d := sha1.Sum([]byte("foo"))
			digest = d[:]
		case margo.SigAlgRsaPkcs1Sha384, margo.SigAlgEcdsaP384Sha384:
			d := sha512.Sum384([]byte("foo"))
			digest = d[:]
		case margo.SigAlgEcdsaP256Sha256:
			d := sha256.Sum256([]byte("foo"))
			digest = d[:]
		}
		sig, err := s.SignHash(digest, Options{SigAlg: s.defaultSigAlg})
		if err != nil {
			t.Fatalf("failed to sign hash: %v", err)
		}
		err = margo.VerifyHashSignature(sig.(*Signature).Data, digest, crypto.SHA384, s.publicKey)
		if err != nil {
			t.Fatalf("failed to verify signature: %v", err)
		}
	}
}

var marsignerconfs = []signer.Configuration{
	signer.Configuration{
		ID:   "unittestmar",
		Type: Type,
		PrivateKey: `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCAUrUDTS86CuqV
ctCo8jG8SSd4W/m/A4UF0J8T+la/pnJsZt2HhQ+Ma/+HmXF8QSeVax0LfrOaRmLy
OnfwOakP7QIGYtFsBQoLV5TWJzOr2ieonQS3h9xF865lNv+i9YPRGQT+ijjtKc49
mnb1vek+6/o8vfCMe7/5CE+fq2c/+yRjCJIstimDPfCTo5YHqXr2GaebQ006Vak2
sXhmp1sScGC/HYOuyris/AgmYHXGpNR4PLNWftoljp8m+PKwe8fy4zN83RqEEYnj
LzR0zOPad9Z4gD+89E/3tOsvxsRSjR2v6UTD+fVNeHs03fNsw8TeMcJfeMlKbO9a
72ZCZcdNAgMBAAECggEAN3iJOxYgdizF3zi0rnOTwFq3LzZDLakt1aerPI2Y9lvT
VrzYwn5ojEEbQti30AiyPcsB0ThCF0yZ9TAFLNkgFfxURcJt2Q4Mm36Onkxv77fs
MN0/br7SH4MJPkOaGi2bf8Ya/JVvqkXKG6MsDWq86zBDCgLpezD7eYF4OgN0LJmc
5aCmqipDWpmQ+EFRiQBrKIAalZLMPvdEFzD6U5jMch+gNiA09tUuJnI60sYvrbul
eJOwr8yv+CPSo8FA40Hwooy5Ab4kkkXxb3ypzVDas5QU7QVoaSrQYaQ6oKaCeKaH
YCKsPD3RIUilMHDhOOn4S/R5DlkYJNoXNHFq0hE3wQKBgQC+7KZVoalALOiZ5vNa
EUrWAUIGug2xIxtHIhGBz1oHjIOqowYaZSpa9jbFe0LbWiEveGn2j54MWUsQVtPy
MhHuI/1zsbFs29d44s1xP7tuggqcBGUwMMf5w36MavmnbTdxv5T29DNALz3xg/ax
IaiZiI4fswciDMXpFXfsL8SO+QKBgQCsD7LbMjbz9Mleia3QeyZ9sbV2EYFaps1X
RNntQqOow4itBXqMYBuKcoGoMR2eAMVT9ZDCtZaU00KJ608NI9yYb0xxPtNaqdlF
hqSn9C5khAwQmvDiV63QUTIMYqf2m3sCdwZaXSiYUXwjNXvyO63opZqgR9TwuZfO
h8B2DBZL9QKBgHAvhAl7JYWFHeQY9dNtp8iaEp77QkJcu5GPrjPVkDQxV8izZEms
OjgaxtJBfGaBzlAjdDgh6Z+d9GKUcpO04h5JXYtW1Ud+4lyxAEDUTyE/HlbQqlin
wUm8mqaN0UaVAWhAR5rYoSjM2ZwJi7JHcddNix2LR9y1HrG4ILBS3S+ZAoGAfVme
gsRtdoNSJNaG04i0fQP3YEHWjDVTCY32ejx/QJbbPrnsEtJ9nfpX7TGDEzYajFUt
ljx2rIvQQOw2FiuXLVKATUxo6/cre9Rgpp9lIQN2Sq6maS9ZSJeur4k8NpQFJMGT
1kdiKL3Mg1YWq13BD+l94eETCCEdsHADzbx2jfUCgYAjJk016W+hugkU7rtAHIaP
Q9+gIrgtjJrWCw6SHF3pIB749A1J4NMlQ+0XjPhcwSMrxxkMTwmLhgSEHZcVl3C6
zw097oFSo1ZF/8Qpe3cb3252I9MOWKSXWTJ1BP2iVlCp0jRteFCJj8SB2CAnay9F
1KDtwVd+U8cK/z6UQxo8YQ==
-----END PRIVATE KEY-----`,
	},
	signer.Configuration{
		ID:   "unittestmarecdsa",
		Type: Type,
		PrivateKey: `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`,
	},
	signer.Configuration{
		ID:   "unittestmarecdsap256",
		Type: Type,
		PrivateKey: `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJ6lcYV4MypMWFLWPqDAU6VNuJG7bqbY3FBhOIZTDzZQoAoGCCqGSM49
AwEHoUQDQgAEaJbTKOjMsN+dPU9/TFb1EyB/eR7TlSXmHjcfynJlcVBLssUsLgWU
Xj/AFnqLs7TSSCqG4pcnkXK8oHt5bg+qkw==
-----END EC PRIVATE KEY-----`,
	},
	signer.Configuration{
		ID:   "unittestmarrsa4096",
		Type: Type,
		PrivateKey: `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`,
	},
}

var miniMarB = []byte("\x4D\x41\x52\x31\x00\x00\x01\x7D\x00\x00\x00\x00\x00\x00\x01\x96" +
	"\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x01\x00\x20\xC4\xC6\xB2" +
	"\xE0\x4F\x52\xDC\xD5\x36\xCB\x52\x22\x9B\x21\x5C\x50\x97\xAD\x0B" +
	"\xE8\x04\xEF\x61\xEE\x8B\xE8\x9C\x1E\xC0\x06\xD5\x4A\x38\x44\x50" +
	"\x21\x8C\x43\x43\x8A\xD5\x39\x8A\x8B\x5F\x06\x1A\x28\xCD\xC5\xA7" +
	"\xFF\xB9\x4E\xCB\x9B\xF4\x53\xCA\xF9\xB4\x54\xBE\xE0\x70\xE0\xE6" +
	"\xFE\x9A\x20\x0E\x64\x6D\xB5\xFF\xAB\x73\x65\x1F\x5F\xB9\xED\x84" +
	"\xFC\x42\x80\x1F\xE8\x3A\x3E\xDF\x5E\xA0\xF0\x62\x98\x81\x3C\xD4" +
	"\x92\x1C\xC2\x00\x4D\x46\xFB\x7E\x74\x51\x1E\xA5\x53\x76\xA8\x64" +
	"\x41\x9D\x91\xA9\x0B\x32\x28\xBE\xCE\xE8\x3F\xDB\x37\xAD\x84\x1E" +
	"\x65\x53\x9E\x7E\x4B\x6D\x8A\x98\x9C\x32\xE1\xA7\xE6\xC4\x54\x63" +
	"\xE8\xF4\x44\xEC\x52\x94\xA4\xED\x79\x45\xAB\x7B\xFD\xE9\xB9\x4B" +
	"\x8B\x82\x1A\xCE\x6E\x0B\xC8\xF5\x17\xB5\x09\xA2\xC4\xDC\x1E\xE8" +
	"\xE3\x86\xA5\x2F\x99\xAA\x86\xC6\x02\xDA\x28\x7B\xB9\xCF\x3C\x2D" +
	"\x10\xFE\x4A\xAA\x28\xA4\x26\x73\x00\xB2\x4C\xFF\xFE\x94\x3D\x55" +
	"\x93\xB2\x57\x6C\x3C\x86\xCD\x88\xFD\x7F\xD0\xA5\xA2\xAF\x0F\x1F" +
	"\xB8\x32\xC4\xE9\x8D\xBF\x07\xC7\xC4\xC5\x3D\xE4\x9C\x3F\x13\x17" +
	"\x45\x50\x37\x4A\xE9\x05\xBB\x50\xF4\x53\xC7\xB0\x00\x00\x00\x03" +
	"\x00\x00\x00\x40\xC4\x87\x82\x76\x33\xF7\x92\xBC\x9A\xC4\xAF\xE9" +
	"\x80\x3A\x21\x64\x5F\x4F\xDF\x62\x83\x45\xBB\xE0\xA0\xE5\xD1\x0B" +
	"\xCC\xD1\x38\xBE\x05\x1B\xC8\xEC\x54\xA6\x8E\x3B\x78\x40\xE7\xD5" +
	"\x1D\x10\xE4\xA3\x7D\x4D\xB9\x56\xB6\xB1\x40\xA8\xFC\xF8\x9B\x6A" +
	"\xE2\xC8\xEC\x6C\x00\x00\x00\x00\x61\x61\x61\x61\x61\x61\x61\x61" +
	"\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x00\x00\x00" +
	"\x15\x00\x00\x01\x68\x00\x00\x00\x15\x00\x00\x02\x58\x2F\x66\x6F" +
	"\x6F\x2F\x62\x61\x72\x00")

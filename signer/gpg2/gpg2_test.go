package gpg2

import (
	"bytes"
	_ "embed"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *GPG2Signer {
	s, err := New(gpg2signerconf)
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

		_ = assertNewSignerWithConfOK(t, gpg2signerconf)
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PublicKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.PublicKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.KeyID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("non-alphnumeric KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := gpg2signerconf
		invalidConf.KeyID = "!?;\\"
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestConfig(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, gpg2signerconf)

	if s.Config().Type != gpg2signerconf.Type {
		t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, gpg2signerconf.Type)
	}
	if s.Config().ID != gpg2signerconf.ID {
		t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, gpg2signerconf.ID)
	}
	if s.Config().PrivateKey != gpg2signerconf.PrivateKey {
		t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, gpg2signerconf.PrivateKey)
	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	s := assertNewSignerWithConfOK(t, gpg2signerconf)
	defaultOpts := s.GetDefaultOptions()
	expectedOpts := Options{}
	if defaultOpts != expectedOpts {
		t.Fatalf("signer returned unexpected default options: %v", defaultOpts)
	}
}

func TestSignData(t *testing.T) {
	input := []byte("foobarbaz1234abcd")
	// initialize a signer
	s := assertNewSignerWithConfOK(t, gpg2signerconf)

	// sign input data
	sig, err := s.SignData(input, s.GetDefaultOptions())
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	// convert signature to string format
	sigstr, err := sig.Marshal()
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

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

	t.Run("VerifyWithGnuPG", func(t *testing.T) {
		t.Parallel()

		// write the signature to a temp file
		tmpSignatureFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_signature")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpSignatureFile.Name())
		err = ioutil.WriteFile(tmpSignatureFile.Name(), []byte(sigstr), 0755)
		if err != nil {
			t.Fatalf("error writing file %s: %q", tmpSignatureFile.Name(), err)
		}

		// write the input to a temp file
		tmpContentFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_input")
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove(tmpContentFile.Name())
		err = ioutil.WriteFile(tmpContentFile.Name(), input, 0755)
		if err != nil {
			t.Fatal(err)
		}

		// write the public key to a temp file
		tmpPublicKeyFile, err := ioutil.TempFile("", "gpg2_TestSignPGPAndVerifyWithGnuPG_publickey")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpPublicKeyFile.Name())
		// fmt.Printf("loading %s\n", s.PublicKey)
		err = ioutil.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove("/tmp/autograph_test_gpg2_keyring.gpg")
		defer os.Remove("/tmp/autograph_test_gpg2_secring.gpg")
		defer os.Remove("/tmp/autograph_test_gpg2_keyring.gpg~")

		// call gnupg to create a new keyring, load the key in it
		gnupgCreateKeyring := exec.Command("gpg", "--no-default-keyring",
			"--keyring", "/tmp/autograph_test_gpg2_keyring.gpg",
			"--secret-keyring", "/tmp/autograph_test_gpg2_secring.gpg",
			"--import", tmpPublicKeyFile.Name())
		out, err := gnupgCreateKeyring.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
		}

		// verify the signature
		gnupgVerifySig := exec.Command("gpg", "--no-default-keyring",
			"--keyring", "/tmp/autograph_test_gpg2_keyring.gpg",
			"--secret-keyring", "/tmp/autograph_test_gpg2_secring.gpg",
			"--verify", tmpSignatureFile.Name(), tmpContentFile.Name())
		out, err = gnupgVerifySig.CombinedOutput()
		if err != nil {
			t.Fatalf("error verifying sig: %s\n%s", err, out)
		}
		t.Logf("GnuPG PGP signature verification output:\n%s\n", out)
	})
}

//go:embed "test/fixtures/pgpsubkey.key"
var pgpsubkeyPrivateKey string

//go:embed "test/fixtures/pgpsubkey.pub"
var pgpsubkeyPublicKey string

var gpg2signerconf = signer.Configuration{
	ID:         "gpg2test",
	Type:       Type,
	KeyID:      "0xE09F6B4F9E6FDCCB",
	Passphrase: "abcdef123",
	PrivateKey: pgpsubkeyPrivateKey,
	PublicKey:  pgpsubkeyPublicKey,
}

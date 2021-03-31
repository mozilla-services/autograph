package pgp

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func TestSignData(t *testing.T) {
	input := []byte("foobarbaz1234abcd")
	// initialize a signer
	s, err := New(pgpsignerconf)
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}
	if s.Config().Type != pgpsignerconf.Type {
		t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, pgpsignerconf.Type)
	}
	if s.Config().ID != pgpsignerconf.ID {
		t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, pgpsignerconf.ID)
	}
	if s.Config().PrivateKey != pgpsignerconf.PrivateKey {
		t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, pgpsignerconf.PrivateKey)
	}

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

	// convert string format back to signature
	sig2, err := Unmarshal(sigstr)
	if err != nil {
		t.Fatalf("failed to unmarshal signature: %v", err)
	}

	if !bytes.Equal(sig.(*Signature).Data, sig2.(*Signature).Data) {
		t.Fatalf("marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
			sig.(*Signature).Data, sig2.(*Signature).Data)
	}
}

func TestSignAndVerifyWithGnuPG(t *testing.T) {
	input := []byte("foobarbaz1234abcd")

	// init a signer
	s, err := New(pgpsignerconf)
	if err != nil {
		t.Fatalf("failed to initialize signer: %v", err)
	}

	// sign input data
	sig, err := s.SignData(input, s.GetDefaultOptions())
	pgpSig, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// write the signature to a temp file
	tmpSignatureFile, err := ioutil.TempFile("", "TestSignPGPAndVerifyWithGnuPG_signature")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpSignatureFile.Name())
	ioutil.WriteFile(tmpSignatureFile.Name(), []byte(pgpSig), 0755)

	// write the input to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestSignPGPAndVerifyWithGnuPG_input")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpContentFile.Name())
	ioutil.WriteFile(tmpContentFile.Name(), input, 0755)

	// write the public key to a temp file
	tmpPubKeyFile, err := ioutil.TempFile("", "TestSignPGPAndVerifyWithGnuPG_pubkey")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpPubKeyFile.Name())
	fd, err := os.OpenFile(tmpPubKeyFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = s.entity.Serialize(fd)
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()

	// call gnupg to create a new keyring, load the key in it, then verify the signature
	gnupgCreateKeyring := exec.Command("gpg", "--no-default-keyring",
		"--keyring", "/tmp/autograph_pgp_keyring.gpg",
		"--secret-keyring", "/tmp/autograph_pgp_secring.gpg",
		"--import", tmpPubKeyFile.Name())
	out, err := gnupgCreateKeyring.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
	}
	gnupgVerifySig := exec.Command("gpg", "--no-default-keyring",
		"--keyring", "/tmp/autograph_pgp_keyring.gpg",
		"--secret-keyring", "/tmp/autograph_pgp_secring.gpg",
		"--verify", tmpSignatureFile.Name(), tmpContentFile.Name())
	out, err = gnupgVerifySig.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
	}
	t.Logf("GnuPG PGP signature verification output:\n%s\n", out)
}

var pgpsignerconf = signer.Configuration{
	ID:   "pgptest",
	Type: Type,
	PrivateKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
HQASoA7mirON
=vJUu
-----END PGP PRIVATE KEY BLOCK-----`,
}

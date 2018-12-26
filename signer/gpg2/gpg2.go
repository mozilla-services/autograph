package gpg2

import (
	"log"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/signer"
)

// TODO: add tools/ client support
// TODO: use signer ids in tmp file prefix

const (
	// Type of this signer is "gpg2" represents a signer that
	// shells out to gpg2 to sign artifacts since the golang "pgp"
	// signer doesn't support signing with subkeys
	// https://godoc.org/golang.org/x/crypto/openpgp#ArmoredDetachSign
	// or loading keys exported with gnu-dummy s2k encrypted
	// passphrases https://github.com/golang/go/issues/13605
	Type = "gpg2"
)

// GPG2Signer holds the configuration of the signer
type GPG2Signer struct {
	signer.Configuration

	// KeyID is the fingerprint of the gpg key or subkey to use
	// e.g. 0xA2B637F535A86009
	KeyID string

	// Passphrase is the optional passphrase to use decrypt the
	// gpg secret key
	Passphrase string
}

// New initializes a pgp signer using a configuration
func New(conf signer.Configuration) (s *GPG2Signer, err error) {
	s = new(GPG2Signer)

	if conf.Type != Type {
		return nil, errors.Errorf("gpg2: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("gpg2: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	if conf.PrivateKey == "" {
		return nil, errors.New("gpg2: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey

	if conf.PublicKey == "" {
		return nil, errors.New("gpg2: missing public key in signer configuration")
	}
	s.PublicKey = conf.PublicKey

	if conf.KeyID == "" {
		return nil, errors.New("gpg2: missing gpg key ID in signer configuration")
	}
	s.KeyID = conf.KeyID

	s.Passphrase = conf.Passphrase
	return
}

// Config returns the configuration of the current signer
func (s *GPG2Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignData takes data and returns an armored signature with pgp header and footer
func (s *GPG2Signer) SignData(data []byte, options interface{}) (signer.Signature, error) {
	// write the input to a temp file
	tmpContentFile, err := ioutil.TempFile("", "gpg2_input")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpContentFile.Name())
	ioutil.WriteFile(tmpContentFile.Name(), data, 0755)

	// write the private key to a temp file
	tmpPrivateKeyFile, err := ioutil.TempFile("", "gpg2_privatekey")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpPrivateKeyFile.Name())
	// fmt.Printf("loading %s\n", s.PrivateKey)
	ioutil.WriteFile(tmpPrivateKeyFile.Name(), []byte(s.PrivateKey), 0755)

	// call gnupg to create a new keyring, load the key in it
	gnupgCreateKeyring := exec.Command("gpg", "--no-default-keyring",
		"--keyring", "/tmp/autograph_gpg2_keyring.gpg",
		"--secret-keyring", "/tmp/autograph_gpg2_secring.gpg",
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPrivateKeyFile.Name())
	out, err := gnupgCreateKeyring.CombinedOutput()
	if err != nil {
		log.Fatalf("failed to load private key into keyring: %s\n%s", err, out)
	} else {
		log.Println(string(out))
	}

	// write the public key to a temp file
	tmpPublicKeyFile, err := ioutil.TempFile("", "gpg2_publickey")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpPublicKeyFile.Name())
	// log.Printf("loading %s\n", s.PublicKey)
	ioutil.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)

	// call gnupg to create a new keyring, load the key in it
	gnupgCreateKeyring = exec.Command("gpg",
		"--no-default-keyring",
		"--keyring", "/tmp/autograph_gpg2_keyring.gpg",
		"--secret-keyring", "/tmp/autograph_gpg2_secring.gpg",
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPublicKeyFile.Name(),
	)
	out, err = gnupgCreateKeyring.CombinedOutput()
	log.Println(string(out))
	if err != nil {
		log.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
	}

	defer os.Remove("/tmp/autograph_gpg2_keyring.gpg")
	defer os.Remove("/tmp/autograph_gpg2_keyring.gpg~")
	defer os.Remove("/tmp/autograph_gpg2_secring.gpg")

	gnupgVerifySig := exec.Command("gpg", "--no-default-keyring",
		"--keyring", "/tmp/autograph_gpg2_keyring.gpg",
		"--secret-keyring", "/tmp/autograph_gpg2_secring.gpg",
		"--armor",
		"--no-tty",
		"--batch",
		"--yes",
		"--sign-with", s.KeyID,
		"--output", "-",
		"--pinentry-mode", "loopback",
		"--passphrase-fd", "0",
		"--detach-sign", tmpContentFile.Name(),
	)
	stdin, err := gnupgVerifySig.StdinPipe()
	if err != nil {
		log.Fatalf("failed to create stdin pipe for sign cmd: %s\n", err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, s.Passphrase)
	}()
	out, err = gnupgVerifySig.CombinedOutput()
	if err != nil {
		log.Fatalf("failed to sign: %s\n%s", err, out)
	} else {
		log.Printf("signed as:\n%s\n", string(out))
	}

	sig := new(Signature)
	sig.Data = out
	return sig, nil
}

// Signature is a PGP signature
type Signature struct {
	Data []byte
}

// Marshal doesn't do much for this signer. sig.Data already contains
// an armored signature, so we simply convert it to a string and return it
func (sig *Signature) Marshal() (string, error) {
	return string(sig.Data), nil
}

// Unmarshal also does very little. It simply converts the armored signature
// from a string to an []byte, but doesn't attempt to parse it, and returns it
// as a Signature
func Unmarshal(sigstr string) (signer.Signature, error) {
	sig := new(Signature)
	sig.Data = []byte(sigstr)
	return sig, nil
}

// Options are not implemented for this signer
type Options struct {
}

// GetDefaultOptions returns default options of the signer
func (s *GPG2Signer) GetDefaultOptions() interface{} {
	return Options{}
}

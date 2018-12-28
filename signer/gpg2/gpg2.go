package gpg2

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/autograph/signer"
)

const (
	// Type of this signer is "gpg2" represents a signer that
	// shells out to gpg2 to sign artifacts since the golang "pgp"
	// signer doesn't support signing with subkeys
	// https://godoc.org/golang.org/x/crypto/openpgp#ArmoredDetachSign
	// or loading keys exported with gnu-dummy s2k encrypted
	// passphrases https://github.com/golang/go/issues/13605
	Type = "gpg2"

	keyRingFilename = "autograph_gpg2_keyring.gpg"
	secRingFilename = "autograph_gpg2_secring.gpg"
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

	// tmpDir is the signer's temporary working directory. It
	// holds the gpg sec and keyrings
	tmpDir string
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

	s.tmpDir, err = createKeyRing(s)
	if err != nil {
		return nil, errors.Wrap(err, "gpg2: error creating keyring")
	}
	s.RegisterCleanupAndExit()
	return
}

// createKeyRing creates a temporary gpg sec and keyrings, loads the
// private and public keys for the signer, and returns the temporary
// director holding the rings
func createKeyRing(s *GPG2Signer) (string, error) {
	// reuse keyring in tempdir
	prefix := fmt.Sprintf("autograph_%s_%s", s.Type, s.KeyID)

	dir, err := ioutil.TempDir("", prefix)
	if err != nil {
		return "", errors.Wrap(err, "gpg2: error creating tempdir for keyring")
	}

	// write the public key to a temp file in our signer's temp dir
	tmpPublicKeyFile, err := ioutil.TempFile(dir, "gpg2_publickey")
	if err != nil {
		return "", errors.Wrap(err, "gpg2: error creating tempfile for public key")
	}
	defer os.Remove(tmpPublicKeyFile.Name())
	err = ioutil.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)
	if err != nil {
		return "", errors.Wrap(err, "gpg2: error writing public key to tempfile")
	}

	// write the private key to a temp file in our signer's temp dir
	tmpPrivateKeyFile, err := ioutil.TempFile(dir, "gpg2_privatekey")
	if err != nil {
		return "", errors.Wrap(err, "gpg2: error creating tempfile for private key")
	}
	defer os.Remove(tmpPrivateKeyFile.Name())
	err = ioutil.WriteFile(tmpPrivateKeyFile.Name(), []byte(s.PrivateKey), 0755)
	if err != nil {
		return "", errors.Wrap(err, "gpg2: error writing private key to tempfile")
	}

	keyRingPath := filepath.Join(dir, keyRingFilename)
	secRingPath := filepath.Join(dir, secRingFilename)

	// call gpg to create a new keyring and load the public key in it
	gpgLoadPublicKey := exec.Command("gpg",
		"--no-default-keyring",
		"--keyring", keyRingPath,
		"--secret-keyring", secRingPath,
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPublicKeyFile.Name(),
	)
	out, err := gpgLoadPublicKey.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "gpg2: failed to load public key into keyring: %s\n%s", err, out)
	} else {
		log.Debugf(fmt.Sprintf("gpg2: loaded public key %s", string(out)))
	}

	// call gpg to load the private key in it
	gpgLoadPrivateKey := exec.Command("gpg", "--no-default-keyring",
		"--keyring", keyRingPath,
		"--secret-keyring", secRingPath,
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPrivateKeyFile.Name())
	out, err = gpgLoadPrivateKey.CombinedOutput()
	if err != nil {
		return "", errors.Wrapf(err, "gpg2: failed to load private key into keyring: %s\n%s", err, out)
	} else {
		log.Debugf(fmt.Sprintf("gpg2: loaded private key %s", string(out)))
	}

	return dir, nil

}

func (s *GPG2Signer) RegisterCleanupAndExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	go func() {
		sig := <-c
		os.RemoveAll(s.tmpDir)
		log.Infof("gpg2: received signal %s; cleaned up %s and exiting", sig, s.tmpDir)
		os.Exit(0)
	}()
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
	keyRingPath := filepath.Join(s.tmpDir, keyRingFilename)
	secRingPath := filepath.Join(s.tmpDir, secRingFilename)

	// write the input to a temp file
	tmpContentFile, err := ioutil.TempFile(s.tmpDir, fmt.Sprintf("gpg2_%s_input", s.ID))
	if err != nil {
		return nil, errors.Wrap(err, "gpg2: failed to create tempfile for input to sign")
	}
	defer os.Remove(tmpContentFile.Name())
	ioutil.WriteFile(tmpContentFile.Name(), data, 0755)

	gpgVerifySig := exec.Command("gpg",
		"--no-default-keyring",
		"--keyring", keyRingPath,
		"--secret-keyring", secRingPath,
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
	stdin, err := gpgVerifySig.StdinPipe()
	if err != nil {
		return nil, errors.Wrap(err, "gpg2: failed to create stdin pipe for sign cmd")
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, s.Passphrase)
	}()
	out, err := gpgVerifySig.CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "gpg2: failed to sign input %s\n%s", err, out)
	} else {
		log.Debugf("signed as:\n%s\n", string(out))
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

package gpg2

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/mozilla-services/autograph/signer"

	log "github.com/sirupsen/logrus"
)

const (
	// Type of this signer is "gpg2" represents a signer that
	// shells out to gpg2 to sign artifacts since the golang "pgp"
	// signer doesn't support signing with subkeys
	// https://godoc.org/golang.org/x/crypto/openpgp#ArmoredDetachSign
	// or loading keys exported with gnu-dummy s2k encrypted
	// passphrases https://github.com/golang/go/issues/13605
	Type = "gpg2"

	// ModeGPG2 represents a signer that signs data with gpg2
	ModeGPG2 = "gpg2"

	// ModeDebsign represents a signer that signs files with debsign
	ModeDebsign = "debsign"

	keyRingFilename = "autograph_gpg2_keyring.gpg"
	secRingFilename = "autograph_gpg2_secring.gpg"
	gpgConfFilename = "gpg.conf"

	// gpgConfContentsHead is the static part of the gpg config
	//
	// options from https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
	//
	// batch: Use batch mode. Never ask, do not allow interactive commands...
	// no-tty: Make sure that the TTY (terminal) is never used for any output. This option is needed in some cases because GnuPG sometimes prints warnings to the TTY even if --batch is used.
	// yes: Assume "yes" on most questions. Should not be used in an option file.
	//
	// more options from https://www.gnupg.org/documentation/manuals/gnupg/GPG-Esoteric-Options.html
	//
	// no-default-keyring: Do not add the default keyrings to the list of keyrings. ...
	// passphrase-fd: Read the passphrase from file descriptor n. Only the first line will be read from file descriptor n. If you use 0 for n, the passphrase will be read from STDIN. This can only be used if only one passphrase is supplied.
	// pinentry-mode: Set the pinentry mode to mode. Allowed values for mode are:
	// ...
	//     loopback - Redirect Pinentry queries to the caller. Note that in contrast to Pinentry the user is not prompted again if he enters a bad password.
	gpgConfContentsHead = `batch
no-default-keyring
no-tty
passphrase-fd 0
pinentry-mode loopback
yes`
)

var monitoringInputData = []byte(`AUTOGRAPH MONITORING`)
var isAlphanumeric = regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString

// gpg2 fails when multiple signers are called at in parallel so we serialize
// invoking this signer through a global mutex. For more info on this particular
// piece of gpg sadness, see https://answers.launchpad.net/duplicity/+question/296122
var serializeSigning sync.Mutex

// GPG2Signer holds the configuration of the signer
type GPG2Signer struct {
	signer.Configuration

	// KeyID is the fingerprint of the gpg key or subkey to use
	// e.g. 0xA2B637F535A86009
	KeyID string

	// passphrase is the optional passphrase to use decrypt the
	// gpg secret key
	passphrase string

	// tmpDir is the signer's temporary working directory. It
	// holds the gpg sec and keyrings
	tmpDir string

	// Mode is which signing command to use gpg2 or debsign
	Mode string
}

// New initializes a pgp signer using a configuration
func New(conf signer.Configuration) (s *GPG2Signer, err error) {
	s = new(GPG2Signer)

	if conf.Type != Type {
		return nil, fmt.Errorf("gpg2: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, fmt.Errorf("gpg2: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	switch conf.Mode {
	case ModeDebsign:
	case ModeGPG2:
	case "": // default to signing in gpg2 mode to preserve backwards compat with old config files
		conf.Mode = ModeGPG2
	default:
		return nil, fmt.Errorf("gpg2: unknown signer mode %q, must be 'gpg2', or 'debsign'", conf.Mode)
	}
	s.Mode = conf.Mode

	if conf.PrivateKey == "" {
		return nil, fmt.Errorf("gpg2: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey

	if conf.PublicKey == "" {
		return nil, fmt.Errorf("gpg2: missing public key in signer configuration")
	}
	s.PublicKey = conf.PublicKey

	if conf.KeyID == "" {
		return nil, fmt.Errorf("gpg2: missing gpg key ID in signer configuration")
	}
	// validate KeyID since it is injected into the temp dir
	// prefix and could be used for command injection
	if !isAlphanumeric(conf.KeyID) {
		return nil, fmt.Errorf("gpg2: non-alphanumeric key ID in signer configuration")
	}
	s.KeyID = conf.KeyID

	s.passphrase = conf.Passphrase

	s.tmpDir, err = createKeyRing(s)
	if err != nil {
		return nil, fmt.Errorf("gpg2: error creating keyring: %w", err)
	}

	// debsign lets us to specify a gpg program name (gpg or
	// gpg2), but not args. We use a config file to sent them.
	if s.Mode == ModeDebsign {
		// write gpg.conf after importing keys, so gpg doesn't try to read stdin for key imports
		if err = writeGPGConf(s.tmpDir); err != nil {
			return nil, fmt.Errorf("error writing gpg conf: %w", err)
		}
	}
	return
}

// createKeyRing creates a temporary gpg sec and keyrings, loads the
// private and public keys for the signer, and returns the temporary
// directory holding the key rings.
//
// It return errors for any failure to create the tmp dir; or write,
// import, or clean up the private and public keys.
func createKeyRing(s *GPG2Signer) (dir string, err error) {
	// reuse keyring in tempdir
	prefix := fmt.Sprintf("autograph_%s_%s_%s_", s.Type, s.KeyID, s.Mode)

	dir, err = ioutil.TempDir("", prefix)
	if err != nil {
		return "", fmt.Errorf("gpg2: error creating tempdir for keyring: %w", err)
	}

	// write the public key to a temp file in our signer's temp dir
	tmpPublicKeyFile, err := ioutil.TempFile(dir, "gpg2_publickey")
	if err != nil {
		err = fmt.Errorf("gpg2: error creating tempfile for public key: %w", err)
		return "", err
	}
	defer func() {
		cleanErr := os.Remove(tmpPublicKeyFile.Name())
		// only clobber the original error when it's nil
		if err == nil && cleanErr != nil {
			err = fmt.Errorf("gpg2: error removing temp pubkey file %q: %w", tmpPublicKeyFile.Name(), cleanErr)
		}
	}()

	err = ioutil.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)
	if err != nil {
		err = fmt.Errorf("gpg2: error writing public key to tempfile: %w", err)
		return "", err
	}

	// write the private key to a temp file in our signer's temp dir
	tmpPrivateKeyFile, err := ioutil.TempFile(dir, "gpg2_privatekey")
	if err != nil {
		err = fmt.Errorf("gpg2: error creating tempfile for private key: %w", err)
		return "", err
	}
	defer func() {
		cleanErr := os.Remove(tmpPrivateKeyFile.Name())
		// only clobber the original error when it's nil
		if err == nil && cleanErr != nil {
			err = fmt.Errorf("gpg2: error removing temp private key file %q %w", tmpPrivateKeyFile.Name(), cleanErr)
		}
	}()
	err = ioutil.WriteFile(tmpPrivateKeyFile.Name(), []byte(s.PrivateKey), 0755)
	if err != nil {
		err = fmt.Errorf("gpg2: error writing private key to tempfile: %w", err)
		return "", err
	}

	keyRingPath := filepath.Join(dir, keyRingFilename)
	secRingPath := filepath.Join(dir, secRingFilename)

	// call gpg to create a new keyring and load the public key in it
	gpgLoadPublicKey := exec.Command("gpg",
		// Shortcut for --options /dev/null. This option is detected before an attempt to open an option file. Using this option will also prevent the creation of a ~/.gnupg homedir.
		"--no-options",
		"--homedir", dir,
		"--no-default-keyring",
		"--keyring", keyRingPath,
		"--secret-keyring", secRingPath,
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPublicKeyFile.Name(),
	)
	gpgLoadPublicKey.Dir = dir
	out, err := gpgLoadPublicKey.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("gpg2: failed to load public key into keyring: %s\n%s", err, out)
		return "", err
	}
	log.Debugf("gpg2: loaded public key %s", string(out))

	// call gpg to load the private key in it
	gpgLoadPrivateKey := exec.Command("gpg", "--no-default-keyring",
		// Shortcut for --options /dev/null. This option is detected before an attempt to open an option file. Using this option will also prevent the creation of a ~/.gnupg homedir.
		"--no-options",
		"--homedir", dir,
		"--keyring", keyRingPath,
		"--secret-keyring", secRingPath,
		"--no-tty",
		"--batch",
		"--yes",
		"--import", tmpPrivateKeyFile.Name())
	gpgLoadPrivateKey.Dir = dir
	out, err = gpgLoadPrivateKey.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("gpg2: failed to load private key into keyring: %s\n%s", err, out)
		return "", err
	}
	log.Debugf("gpg2: loaded private key %s", string(out))

	return dir, nil
}

// writeGPGConf writes a GPG config files in gpgHomeDir. It appends
// keyring and homedir options.
func writeGPGConf(gpgHomeDir string) error {
	keyRingPath := filepath.Join(gpgHomeDir, keyRingFilename)

	gpgConfPath := filepath.Join(gpgHomeDir, gpgConfFilename)
	gpgConfContents := fmt.Sprintf("%s\nkeyring %s\nhomedir %s\n", gpgConfContentsHead, keyRingPath, gpgHomeDir)

	err := ioutil.WriteFile(gpgConfPath, []byte(gpgConfContents), 0600)
	if err != nil {
		return err
	}
	log.Debugf("gpg2: wrote config to %s with contents: %s", gpgConfPath, gpgConfContents)
	return nil
}

// AtExit removes the temp dir containing the signer key and sec rings
// when the app is shut down gracefully
func (s *GPG2Signer) AtExit() error {
	err := os.RemoveAll(s.tmpDir)
	if err == nil {
		log.Infof("gpg2: cleaned up %s in exit handler", s.tmpDir)
	}
	return err
}

// Config returns the configuration of the current signer
func (s *GPG2Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
		Mode:       s.Mode,
	}
}

// SignData takes data and returns an armored signature with pgp header and footer
func (s *GPG2Signer) SignData(data []byte, options interface{}) (signer.Signature, error) {
	if s.Mode != ModeGPG2 && !bytes.Equal(data, monitoringInputData) {
		return nil, fmt.Errorf("gpg2: can only sign monitor data in %s mode", ModeGPG2)
	}
	keyRingPath := filepath.Join(s.tmpDir, keyRingFilename)
	secRingPath := filepath.Join(s.tmpDir, secRingFilename)

	// write the input to a temp file
	tmpContentFile, err := ioutil.TempFile(s.tmpDir, fmt.Sprintf("gpg2_%s_input", s.ID))
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to create tempfile for input to sign: %w", err)
	}
	defer os.Remove(tmpContentFile.Name())
	err = ioutil.WriteFile(tmpContentFile.Name(), data, 0755)
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to write tempfile for input to sign: %w", err)
	}

	// take a mutex to prevent multiple invocations of gpg in parallel
	serializeSigning.Lock()
	defer serializeSigning.Unlock()

	gpgDetachSign := exec.Command("gpg",
		// Shortcut for --options /dev/null. This option is detected before an attempt to open an option file. Using this option will also prevent the creation of a ~/.gnupg homedir.
		"--no-options",
		"--homedir", s.tmpDir,
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
	gpgDetachSign.Dir = s.tmpDir
	stdin, err := gpgDetachSign.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to create stdin pipe for sign cmd: %w", err)
	}
	if _, err = io.WriteString(stdin, s.passphrase); err != nil {
		return nil, fmt.Errorf("gpg2: failed to write passphrase to stdin pipe for sign cmd: %w", err)
	}
	if err = stdin.Close(); err != nil {
		return nil, fmt.Errorf("gpg2: failed to close to stdin pipe for sign cmd: %w", err)
	}
	out, err := gpgDetachSign.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to sign input %s\n%s", err, out)
	}
	log.Debugf("signed as:\n%s\n", string(out))

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

// SignFiles uses debsign to gpg2 clearsign multiple named
// *.buildinfo, *.dsc, or *.changes files
func (s *GPG2Signer) SignFiles(inputs []signer.NamedUnsignedFile, options interface{}) (signedFiles []signer.NamedSignedFile, err error) {
	if s.Mode != ModeDebsign {
		err = fmt.Errorf("gpg2: can only sign multiple files in %s mode", ModeDebsign)
		return
	}

	// create a tmp dir outside the signer GPG home
	inputsTmpDir, err := ioutil.TempDir("", fmt.Sprintf("autograph_%s_%s_%s_sign_files", s.Type, s.KeyID, s.Mode))
	if err != nil {
		err = fmt.Errorf("gpg2: error creating tempdir for debsign: %w", err)
		return
	}
	defer os.RemoveAll(inputsTmpDir)

	// write the inputs to their tmp dir
	var inputFilePaths []string
	for i, input := range inputs {
		ext := filepath.Ext(input.Name)
		if !(ext == ".buildinfo" || ext == ".dsc" || ext == ".changes") {
			return nil, fmt.Errorf("gpg2: cannot sign file %d. Files missing extension .buildinfo, .dsc, or .changes", i)
		}
		inputFilePath := filepath.Join(inputsTmpDir, input.Name)
		err := ioutil.WriteFile(inputFilePath, input.Bytes, 0644)
		if err != nil {
			return nil, fmt.Errorf("gpg2: failed to write tempfile %d for debsign to sign: %w", i, err)
		}
		inputFilePaths = append(inputFilePaths, inputFilePath)
	}

	// take a mutex to prevent multiple invocations of gpg in parallel
	serializeSigning.Lock()
	defer serializeSigning.Unlock()

	args := append([]string{
		// "Do not read any configuration files. This can only be used as the first option given on the command-line."
		"--no-conf",
		// "Specify the key ID to be used for signing; overrides any -m and -e options."
		// debsign prefers the pub key fingerprint: https://github.com/Debian/devscripts/blob/16f9a6d24f4bd564c315f81b89e08c3b4fb76f13/scripts/debsign.sh#L389
		"-k", s.KeyID,
		// "Recreate signature"
		"--re-sign",
	}, inputFilePaths...)
	debsignCmd := exec.Command("debsign", args...)
	debsignCmd.Env = append(os.Environ(),
		fmt.Sprintf("GNUPGHOME=%s", s.tmpDir),
	)
	stdin, err := debsignCmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to create stdin pipe for debsign cmd: %w", err)
	}

	// write passphrase multiple times to stdin
	// our gpg.conf prompts for the passphrase on each gpg call
	// and debsign can call gpg multiple times per file
	passphrasesForStdin := strings.Repeat(fmt.Sprintf("%s\n", s.passphrase), len(inputFilePaths)*4)
	if _, err = io.WriteString(stdin, passphrasesForStdin); err != nil {
		return nil, fmt.Errorf("gpg2: failed to write passphrase to stdin pipe for debsign cmd: %w", err)
	}
	if err = stdin.Close(); err != nil {
		return nil, fmt.Errorf("gpg2: failed to close to stdin pipe for debsign cmd: %w", err)
	}
	out, err := debsignCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gpg2: failed to debsign inputs %s\n%s", err, out)
	}

	// read the signed tempfiles
	for i, inputFilePath := range inputFilePaths {
		signedFileBytes, err := ioutil.ReadFile(inputFilePath)
		if err != nil {
			return nil, fmt.Errorf("gpg2: failed to read %d %q signed by debsign: %w", i, inputFilePath, err)
		}
		signedFiles = append(signedFiles, signer.NamedSignedFile{
			Name:  inputs[i].Name,
			Bytes: signedFileBytes,
		})
	}
	log.Debugf("debsign output:\n%s\n", string(out))
	return signedFiles, nil
}

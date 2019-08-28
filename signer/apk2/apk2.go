package apk2

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"crypto/sha256"
	"crypto/x509"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/autograph/signer"
)

const (
	// Type of this signer is "apk2" represents a signer that
	// shells out to apksigner to sign artifacts
	Type = "apk2"
)

// APK2Signer holds the configuration of the signer
type APK2Signer struct {
	signer.Configuration

	pkcs8Key []byte
}

// New initializes an apk signer using a configuration
func New(conf signer.Configuration) (s *APK2Signer, err error) {
	s = new(APK2Signer)

	if conf.Type != Type {
		return nil, errors.Errorf("apk2: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, errors.New("apk2: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	if conf.PrivateKey == "" {
		return nil, errors.New("apk2: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey
	priv, err := conf.GetPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to get private key from configuration")
	}
	//apksigner wants a pkcs8 encoded privkey
	s.pkcs8Key, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to encode private key to pkcs8")
	}

	if conf.PublicKey == "" {
		return nil, errors.New("apk2: missing public cert in signer configuration")
	}
	s.PublicKey = conf.PublicKey
	return
}

// Config returns the configuration of the current signer
func (s *APK2Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:         s.ID,
		Type:       s.Type,
		PrivateKey: s.PrivateKey,
		PublicKey:  s.PublicKey,
	}
}

// SignFile takes a whole APK and returns a signed and aligned version
func (s *APK2Signer) SignFile(file []byte, options interface{}) (signer.SignedFile, error) {
	keyPath, err := ioutil.TempFile("", fmt.Sprintf("apk2_%s.key", s.ID))
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to create tempfile with private key")
	}
    defer os.Remove(keyPath.Name())
	err = ioutil.WriteFile(keyPath.Name(), []byte(s.pkcs8Key), 0400)
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to write private key to tempfile")
	}

	certPath, err := ioutil.TempFile("", fmt.Sprintf("apk2_%s.cert", s.ID))
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to create tempfile for input to sign")
	}
	defer os.Remove(certPath.Name())
	err = ioutil.WriteFile(certPath.Name(), []byte(s.PublicKey), 0400)
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to write public cert to tempfile")
	}

	// write the input to a temp file
	h := sha256.New()
	h.Write(file)
	tmpAPKFile, err := ioutil.TempFile("", fmt.Sprintf("apk2_input_%x.apk", h.Sum(nil)))
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to create tempfile for input to sign")
	}
	defer os.Remove(tmpAPKFile.Name())
	ioutil.WriteFile(tmpAPKFile.Name(), file, 0755)
	defer os.Remove(tmpAPKFile.Name())

	apkSigCmd := exec.Command("apksigner", "sign",
		"--key", keyPath.Name(),
		"--cert", certPath.Name(),
		"--v1-signing-enabled", "true",
		"--v2-signing-enabled", "true",
		"--min-sdk-version", "9",
		tmpAPKFile.Name(),
	)
	out, err := apkSigCmd.CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "apk2: failed to sign\n%s", out)
	}
	log.Debugf("signed as:\n%s\n", string(out))

	signedApk, err := ioutil.ReadFile(tmpAPKFile.Name())
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to read signed file")
	}
	return signer.SignedFile(signedApk), nil
}

// Options are not implemented for this signer
type Options struct {
}

// GetDefaultOptions returns default options of the signer
func (s *APK2Signer) GetDefaultOptions() interface{} {
	return Options{}
}

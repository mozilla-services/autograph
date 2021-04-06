package apk2

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"

	"github.com/mozilla-services/autograph/signer"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
)

const (
	// Type of this signer is "apk2" represents a signer that
	// shells out to apksigner to sign artifacts
	Type = "apk2"
)

// APK2Signer holds the configuration of the signer
type APK2Signer struct {
	signer.Configuration

	// minSdkVersion is the minimum Android SDK version the signed APK
	// will be compatible with. We need this when using ECDSA keys that
	// are only compatible with SDK>=18
	minSdkVersion string

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
	switch priv.(type) {
	case *ecdsa.PrivateKey:
		// ecdsa is only supported in sdk 18 and higher
		s.minSdkVersion = "18"
		log.Printf("apk2: setting min android sdk version to 18 as required to sign with ecdsa")
	default:
		log.Printf("apk2: setting min android sdk version to 9")
		s.minSdkVersion = "9"
	}
	//apksigner wants a pkcs8 encoded privkey
	s.pkcs8Key, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, errors.Wrap(err, "apk2: failed to encode private key to pkcs8")
	}

	if conf.Certificate == "" {
		return nil, errors.New("apk2: missing public cert in signer configuration")
	}
	s.Certificate = conf.Certificate
	return
}

// Config returns the configuration of the current signer
func (s *APK2Signer) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
	}
}

// SignFile signs a whole aligned APK file with v1 and v2 signatures
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
	err = ioutil.WriteFile(certPath.Name(), []byte(s.Certificate), 0400)
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

	apkSigCmd := exec.Command("java", "-jar", "/usr/bin/apksigner", "sign",
		"--key", keyPath.Name(),
		"--cert", certPath.Name(),
		"--v1-signing-enabled", "true",
		"--v2-signing-enabled", "true",
		"--min-sdk-version", s.minSdkVersion,
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

// GetTestFile returns a valid test APK
func (s *APK2Signer) GetTestFile() []byte {
	return testAPK
}

// Signature is a PKCS7 detached signature
type Signature struct {
	p7       *pkcs7.PKCS7
	Data     []byte
	Finished bool
}

// Verify verifies an apk pkcs7 signature
//
// WARNING: this function does not verify the JAR manifests or
// signature formats other than v1 JAR signing
func (sig *Signature) Verify() error {
	if !sig.Finished {
		return errors.New("apk2.Verify: cannot verify unfinished signature")
	}
	return sig.p7.Verify()
}

// Marshal returns the base64 representation of a v1 JAR signature
func (sig *Signature) Marshal() (string, error) {
	if !sig.Finished {
		return "", errors.New("apk2: cannot marshal unfinished signature")
	}
	if len(sig.Data) == 0 {
		return "", errors.New("apk2: cannot marshal empty signature data")
	}
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal takes the base64 representation of a v1 JAR PKCS7
// detached signature and the content of the signed data, and returns
// a PKCS7 struct
func Unmarshal(signature string, content []byte) (sig *Signature, err error) {
	sig = new(Signature)
	sig.Data, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, errors.Wrap(err, "apk2.Unmarshal: failed to decode base64 signature")
	}
	sig.p7, err = pkcs7.Parse(sig.Data)
	if err != nil {
		return sig, errors.Wrap(err, "apk2.Unmarshal: failed to parse pkcs7 signature")
	}
	sig.p7.Content = content
	sig.Finished = true
	return
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}

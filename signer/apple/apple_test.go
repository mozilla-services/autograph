// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package apple

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

// testDmg is a small, unsigned DMG disk image used only in tests.
//
//go:embed testdata/diskimage.dmg
var testDmg []byte

// testCertPEM/testKeyPEM are a static self-signed Developer ID certificate and
// PEM private key used by the New()/config tests, which validate configuration
// without needing an HSM or rcodesign. They need not correspond to each other.
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIBATANBgkqhkiG9w0BAQsFADCBnjEVMBMGCgmSJomT8ixk
AQEMBXVuc2V0MUQwQgYDVQQDDDtEZXZlbG9wZXIgSUQgQXBwbGljYXRpb246IEF1
dG9ncmFwaCBBcHBsZSBVbml0IFRlc3QgKHVuc2V0KTEOMAwGA1UECwwFdW5zZXQx
IjAgBgNVBAoMGUF1dG9ncmFwaCBBcHBsZSBVbml0IFRlc3QxCzAJBgNVBAYTAlhY
MB4XDTI2MDcxNjIyMzU0N1oXDTI3MDcxNjIyMzU0N1owgZ4xFTATBgoJkiaJk/Is
ZAEBDAV1bnNldDFEMEIGA1UEAww7RGV2ZWxvcGVyIElEIEFwcGxpY2F0aW9uOiBB
dXRvZ3JhcGggQXBwbGUgVW5pdCBUZXN0ICh1bnNldCkxDjAMBgNVBAsMBXVuc2V0
MSIwIAYDVQQKDBlBdXRvZ3JhcGggQXBwbGUgVW5pdCBUZXN0MQswCQYDVQQGEwJY
WDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALk91wxAgJcUlhS/l62+
D9vx4Ds+7vjYuTQ79mEBdRt0eRpB7hn6Yh09Zi3cehm29jmKJscYvt4kzfP1Dxvj
D/DbqtmnpNK0Sl1OHazumRLi+URmvQI5pT540CKBlsJit2GprqwUNbhQcLNr7iRd
199f2SAgzWbSO0fEmLFMnRsxNx+0oGXO2JZ/CVgqIcEU2o8Ho4LuIpXXiCSb+jrF
dCHHAci3mYKLII88LF6PMbA6TpO0/4efmG0FSEoXbuklD1BT2pJ9V6kS54NqP+OL
XByBoAGyM6bTqRTREcuvtw0YWSTNrXVB9hbIM8toi1+ffjP3agNYh+xWsIgtLF+b
3IMCAwEAAaNNMEswDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
AzAOBgNVHQ8BAf8EBAMCB4AwEwYKKoZIhvdjZAYBDQEB/wQCBQAwDQYJKoZIhvcN
AQELBQADggEBACI0Qk4cCIft3K15cFWeu0TfG/iICLfkU2udqm+d+g0v8uKbDYdh
+xJlyg34mYPmgoatkTybGQzaC6I+ZAUn06UrRNbZVqIp1hiLQlgAACfua4svigge
Slfu6xtc4k1NX3ZnphEpJoitci1FfxLL2LV/mz+ksasveID0KnsChK4LZ0CJErQV
0OpGV8ccrAq79yRXvuniHWyoBkt03odW/4wgghW6gPLBGbN7CofS4E/2lH4djFUG
Jz0qd20O+jOk5ECITIjHAZOvevugrF1UDyMSJCPtbEfv9IXnjITPicPmVWijrlsO
uoUqwMD40WI+uPbRvVAY7ipxQFgm2/dCNYw=
-----END CERTIFICATE-----
`

const testKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZHAlSH25U8o9R
C9Tw48RNzZBzgY+6NvH1eBXf5Ihv5LoSZGR4/2dFtLSzXDVG1oG+G1ob4OveKaA7
P3G/ncsY8Sry6CwmkSGb9z6jCKJVRAS2OEPIMo6OJoY0rsbK2pA8qd9nFbEhni5O
v8XVTnWV5Xyy7ogFG/eWdKxzFyN0MQq0kAU95GdXsfUwq5MljTK8hmOvh5OsixUy
6A5+oIEH3OMchb07lBXRw3SRqzv607wqVtP7UspbuuHaXcXLs1racE+dki1rGcZS
dSbxiDI6Sect/pJEkiCMcJPDiVtbQERJ0TqVx/aeQrlFvNjOiBcEt3g51ZtGj+8E
E9HUkeXdAgMBAAECggEBAKw/dRmlfCiDJLc9Nt1DJ2w+yfsJ8JjhnMeOVXSDYMe9
ZO7QnXHt1+ZSvwaKAm7IIrlMBAqYQSnKRqia5kkLDKYmOFftYZHblRmjaBt67yfM
xhw3uXcsvTMEV3eWrnskOkkW0Pp9GEI+uCicN33LOLkLEAr5+gprrNu+h07sLaGx
DJ7NNJMDUxBPm4IgzpH3Js12zvC1QPf3GpAYz8EZxff/resNF6RO57NZ5I87T2ic
XseZOIf1eFAFunt8Dd1zT9KAMxQ2F2OcR2mT9xBdwBth122b47O27ZgDDC9SZVeu
T7tWblBj8D7kad62tMbH+f+VC3DWhsKsU8WDrxgAxKECgYEA9MaH0OC3nFVPmEZa
0JtPKpzbzmJPjoSPhshcJ8HHf0u3xnKQ2kR+kkBEsXtOXDU5rw6/Q7oAuoz0uc6H
wrthnXAZcIk1xk3xy6rdw7gb2L3jgZR0ONod7s0o6HVkA5Xb7xMQeR5O/wv5PPuR
SvqD2IQDem3Znn1IEFMGULN7nfkCgYEA4xC6qqf21d9ZkMG0WFrcA8w72HxhbIKh
OKlnUzLyP93Izj9yA+RT2djtk6xGk74oj7rPT+2XNO3Ji9h2BU0trbDEBMv9JNbm
E8kALqTitFbtVmnPWe9MStfC+T0CUYDE6URKuueLyqZY5v4GS4uCOB04+LERQ5sJ
z693EnqaUAUCgYBFNUT9eCwyFaT1px7SULdnkwZLKlzYLP7v2wLDcvTXNy90+rue
GzO2YlmJ3RVg2OPAbWkC2zqNhIFFb/HOy3BkNWfb+8+qjCtLrLobNpkZBUeoQbNC
x9kixftFDrwCj4Kp7DgCJuGrF1WXOoHwMzjIJTteiGS5fS68/tyQQM848QKBgGNO
8sUmtu8tQyfrgCvQeT9z+IyjQZzKuSZl+NnLg2XpYyTJXN1U5FN369hVVXzSgzzx
cDA98o7knOx73IpPCfZYRDLw4KNXFcN7eofr93b2OdE8b8KexVhKa2zEgRoSXozD
IIgEMwCLpoBIg4pQ1sAiD8O89ZcC3NSnokVDt+/dAoGBAOSZth/psRNkSyqoep8Y
uI3nT74aZNi9cYEYyd+JlP3zokylcO9hKDgFDfeN7rQU17aZfzcDCtWKDIiWT419
sRbWCmq4LR4Z3uojD0DLmcGs4Bl+IqMfXNvroVBCxduMFAsioACnWxLbyHZ7kPnu
4t9Ck/+lV67PMgw71aRIrGb3
-----END PRIVATE KEY-----
`

const infoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.mozilla.autographtest</string>
<key>CFBundleName</key><string>MyApp</string>
<key>CFBundleExecutable</key><string>MyApp</string>
</dict></plist>
`

const jitEntitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>
`

// softHSM holds a SoftHSM token provisioned once for the application-mode
// (PKCS#11) signing tests. It is nil when SoftHSM (or rcodesign) is
// unavailable, in which case those tests skip.
var softHSM *softHSMEnv

type softHSMEnv struct {
	dir         string
	libPath     string
	tokenLabel  string
	pin         string
	appKeyLabel string
	appCertPEM  string
}

func TestMain(m *testing.M) {
	env, err := setupSoftHSM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "apple: SoftHSM application-mode signing tests will skip: %v\n", err)
	} else {
		softHSM = env
	}
	code := m.Run()
	if env != nil {
		os.RemoveAll(env.dir)
	}
	os.Exit(code)
}

// findSoftHSMLib locates the SoftHSM PKCS#11 provider shared object.
func findSoftHSMLib() string {
	if p := os.Getenv("SOFTHSM2_LIB"); p != "" {
		return p
	}
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// setupSoftHSM provisions a SoftHSM token with an application signing key
// (self-signed cert generated by rcodesign) and returns the settings needed to
// build application-mode signers against it. It sets SOFTHSM2_CONF for the test
// process (inherited by rcodesign children).
func setupSoftHSM() (*softHSMEnv, error) {
	util, err := exec.LookPath("softhsm2-util")
	if err != nil {
		return nil, fmt.Errorf("softhsm2-util not found on PATH")
	}
	if _, err := exec.LookPath(rcodesignBinary); err != nil {
		return nil, fmt.Errorf("rcodesign not found on PATH")
	}
	libPath := findSoftHSMLib()
	if libPath == "" {
		return nil, fmt.Errorf("libsofthsm2.so not found")
	}

	dir, err := os.MkdirTemp("", "apple_softhsm_")
	if err != nil {
		return nil, err
	}
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	confBody := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokenDir)
	if err := os.WriteFile(conf, []byte(confBody), 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	// Set for this process so both softhsm2-util and the rcodesign children
	// (which inherit os.Environ) use this isolated token store.
	os.Setenv("SOFTHSM2_CONF", conf)

	env := &softHSMEnv{dir: dir, libPath: libPath, tokenLabel: "autographtest", pin: "0000"}
	if out, err := exec.Command(util, "--init-token", "--free", "--label", env.tokenLabel,
		"--pin", env.pin, "--so-pin", env.pin).CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("init-token failed: %v\n%s", err, out)
	}

	env.appKeyLabel = "apple-app-key"
	env.appCertPEM, err = genAndImportKey(util, env, "developer-id-application", env.appKeyLabel, "a1")
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return env, nil
}

// genAndImportKey generates a self-signed cert+key with rcodesign, imports the
// private key into the SoftHSM token under keyLabel, and returns the cert PEM.
func genAndImportKey(util string, env *softHSMEnv, profile, keyLabel, id string) (string, error) {
	unified := filepath.Join(env.dir, keyLabel+".pem")
	if out, err := exec.Command(rcodesignBinary, "generate-self-signed-certificate",
		"--person-name", "Autograph Test", "--profile", profile,
		"--pem-unified-file", unified).CombinedOutput(); err != nil {
		return "", fmt.Errorf("generate cert failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(unified)
	if err != nil {
		return "", err
	}
	keyPEM, certPEM := splitPEM(string(data))
	if keyPEM == "" || certPEM == "" {
		return "", fmt.Errorf("generated pem missing key or certificate block")
	}
	keyFile := filepath.Join(env.dir, keyLabel+".key")
	if err := os.WriteFile(keyFile, []byte(keyPEM), 0600); err != nil {
		return "", err
	}
	if out, err := exec.Command(util, "--import", keyFile, "--token", env.tokenLabel,
		"--label", keyLabel, "--id", id, "--pin", env.pin).CombinedOutput(); err != nil {
		return "", fmt.Errorf("import key failed: %v\n%s", err, out)
	}
	return certPEM, nil
}

// splitPEM separates the first PRIVATE KEY block from the CERTIFICATE block(s).
func splitPEM(data string) (key, cert string) {
	const keyBegin = "-----BEGIN PRIVATE KEY-----"
	const keyEnd = "-----END PRIVATE KEY-----"
	const certBegin = "-----BEGIN CERTIFICATE-----"
	if i := strings.Index(data, keyBegin); i >= 0 {
		if j := strings.Index(data, keyEnd); j >= 0 {
			key = data[i : j+len(keyEnd)]
		}
	}
	if i := strings.Index(data, certBegin); i >= 0 {
		cert = data[i:]
	}
	return key, cert
}

func requireSoftHSM(t *testing.T) {
	t.Helper()
	if softHSM == nil {
		t.Skip("SoftHSM/rcodesign not available; skipping HSM signing test")
	}
}

func requireRcodesign(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(rcodesignBinary); err != nil {
		t.Skip("rcodesign not available; skipping signing test")
	}
}

// installer PEM credentials, generated once with rcodesign for installer-mode
// signing tests (rcodesign cannot sign .pkg with an HSM key).
var (
	installerOnce sync.Once
	installerKey  string
	installerCert string
	installerErr  error
)

func installerCreds(t *testing.T) (key, cert string) {
	t.Helper()
	requireRcodesign(t)
	installerOnce.Do(func() {
		dir, err := os.MkdirTemp("", "apple_inst_")
		if err != nil {
			installerErr = err
			return
		}
		defer os.RemoveAll(dir)
		unified := filepath.Join(dir, "inst.pem")
		if out, err := exec.Command(rcodesignBinary, "generate-self-signed-certificate",
			"--person-name", "Autograph Test Installer", "--profile", "developer-id-installer",
			"--pem-unified-file", unified).CombinedOutput(); err != nil {
			installerErr = fmt.Errorf("%v\n%s", err, out)
			return
		}
		data, err := os.ReadFile(unified)
		if err != nil {
			installerErr = err
			return
		}
		installerKey, installerCert = splitPEM(string(data))
	})
	if installerErr != nil {
		t.Fatalf("installer creds: %v", installerErr)
	}
	return installerKey, installerCert
}

// newDummySigner builds a signer for config/logic tests that don't sign. New()
// doesn't touch the HSM or rcodesign, so static credentials and a placeholder
// provider path are fine.
func newDummySigner(t *testing.T, mode string) *AppleSigner {
	t.Helper()
	conf := signer.Configuration{
		ID: "test-apple", Type: Type, Mode: mode, Certificate: testCertPEM,
		AppleConfig: signer.AppleConfig{TimestampURL: "none"},
	}
	var hsm HSMConfig
	if mode == ModeInstaller {
		conf.PrivateKey = testKeyPEM
	} else {
		conf.PrivateKey = "dummy-key-label"
		hsm = HSMConfig{LibraryPath: "/nonexistent/libsofthsm2.so", TokenLabel: "t", Pin: "0000"}
	}
	s, err := New(conf, hsm)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	return s
}

// newHSMSigner builds an application-mode signer backed by the provisioned
// SoftHSM token.
func newHSMSigner(t *testing.T) *AppleSigner {
	t.Helper()
	requireSoftHSM(t)
	conf := signer.Configuration{
		ID: "test-apple", Type: Type, Mode: ModeApplication,
		PrivateKey: softHSM.appKeyLabel, Certificate: softHSM.appCertPEM,
		AppleConfig: signer.AppleConfig{TimestampURL: "none"},
	}
	s, err := New(conf, HSMConfig{LibraryPath: softHSM.libPath, TokenLabel: softHSM.tokenLabel, Pin: softHSM.pin})
	if err != nil {
		t.Fatalf("failed to create HSM signer: %v", err)
	}
	return s
}

// newInstallerSigner builds an installer-mode signer with an in-memory PEM key.
func newInstallerSigner(t *testing.T) *AppleSigner {
	t.Helper()
	key, cert := installerCreds(t)
	conf := signer.Configuration{
		ID: "test-installer", Type: Type, Mode: ModeInstaller,
		PrivateKey: key, Certificate: cert,
		AppleConfig: signer.AppleConfig{TimestampURL: "none"},
	}
	s, err := New(conf, HSMConfig{})
	if err != nil {
		t.Fatalf("failed to create installer signer: %v", err)
	}
	return s
}

func sigInfo(t *testing.T, path string) string {
	t.Helper()
	out, _ := exec.Command(rcodesignBinary, "print-signature-info", path).CombinedOutput()
	return string(out)
}

func buildAppTarGz(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	macos := filepath.Join(dir, "MyApp.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "MyApp"), testMachO, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "MyApp.app", "Contents", "Info.plist"), []byte(infoPlist), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := createTarGz(dir)
	if err != nil {
		t.Fatalf("failed to build app tar.gz: %v", err)
	}
	return b
}

func TestNew(t *testing.T) {
	okHSM := HSMConfig{LibraryPath: "/x/libsofthsm2.so", TokenLabel: "t", Pin: "0000"}
	base := func(mode, key string) signer.Configuration {
		return signer.Configuration{ID: "id", Type: Type, Mode: mode, PrivateKey: key, Certificate: testCertPEM}
	}

	cases := []struct {
		name    string
		conf    signer.Configuration
		hsm     HSMConfig
		wantErr bool
	}{
		{"valid application", base(ModeApplication, "keylabel"), okHSM, false},
		{"valid installer", base(ModeInstaller, testKeyPEM), HSMConfig{}, false},
		{"default mode is application", base("", "keylabel"), okHSM, false},
		{"wrong type", signer.Configuration{ID: "id", Type: "nope", PrivateKey: "k", Certificate: testCertPEM}, okHSM, true},
		{"missing id", signer.Configuration{Type: Type, PrivateKey: "k", Certificate: testCertPEM}, okHSM, true},
		{"invalid mode", base("bogus", "k"), okHSM, true},
		{"missing key", signer.Configuration{ID: "id", Type: Type, Certificate: testCertPEM}, okHSM, true},
		{"missing cert", signer.Configuration{ID: "id", Type: Type, PrivateKey: "k"}, okHSM, true},
		{"bad cert", signer.Configuration{ID: "id", Type: Type, PrivateKey: "k", Certificate: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"}, okHSM, true},
		{"application PEM key rejected", base(ModeApplication, testKeyPEM), okHSM, true},
		{"application missing HSM", base(ModeApplication, "keylabel"), HSMConfig{}, true},
		{"installer label (non-PEM) rejected", base(ModeInstaller, "keylabel"), HSMConfig{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.conf, tc.hsm)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	s := newDummySigner(t, ModeApplication)
	c := s.Config()
	if c.Type != Type || c.ID != "test-apple" || c.Mode != ModeApplication {
		t.Errorf("unexpected config: %+v", c)
	}
	if c.AppleConfig.TimestampURL != "none" {
		t.Errorf("expected AppleConfig to round-trip, got %+v", c.AppleConfig)
	}
}

func TestGetDefaultOptions(t *testing.T) {
	s := newDummySigner(t, ModeApplication)
	if _, ok := s.GetDefaultOptions().(Options); !ok {
		t.Error("GetDefaultOptions did not return Options")
	}
}

func TestGetTestFile(t *testing.T) {
	if detectSingleType(newDummySigner(t, ModeApplication).GetTestFile()) != artifactMachO {
		t.Error("application-mode test file should be a Mach-O")
	}
	if detectSingleType(newDummySigner(t, ModeInstaller).GetTestFile()) != artifactXAR {
		t.Error("installer-mode test file should be a XAR/.pkg")
	}
}

func TestSignMachO(t *testing.T) {
	s := newHSMSigner(t)
	opts := Options{HardenedSignConfig: []signer.HardenedSignEntry{{Runtime: true}}}
	signed, err := s.SignFile(testMachO, opts)
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}
	if detectSingleType(signed) != artifactMachO {
		t.Fatal("output is not a Mach-O")
	}
	path := filepath.Join(t.TempDir(), "signed")
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatal(err)
	}
	info := sigInfo(t, path)
	if !strings.Contains(info, "CMS Signature") {
		t.Errorf("signed Mach-O missing CMS signature:\n%s", info)
	}
	if !strings.Contains(info, "RUNTIME") {
		t.Errorf("expected hardened runtime flag:\n%s", info)
	}
}

func TestSignBundle(t *testing.T) {
	s := newHSMSigner(t)
	opts := Options{HardenedSignConfig: []signer.HardenedSignEntry{
		{Globs: []string{"Contents/MacOS/MyApp"}, Entitlements: jitEntitlements, Runtime: true},
	}}
	signed, err := s.SignFile(buildAppTarGz(t), opts)
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}
	if !isGzip(signed) {
		t.Fatal("bundle output is not gzip")
	}
	out := t.TempDir()
	if err := extractTarGz(signed, out); err != nil {
		t.Fatalf("failed to extract signed bundle: %v", err)
	}
	appPath := filepath.Join(out, "MyApp.app")
	if _, err := os.Stat(appPath); err != nil {
		t.Fatalf("signed .app missing from output: %v", err)
	}
	info := sigInfo(t, appPath)
	if !strings.Contains(info, "CMS Signature") {
		t.Errorf("signed bundle missing CMS signature:\n%s", info)
	}
	if !strings.Contains(info, "allow-jit") {
		t.Errorf("expected scoped entitlement in signature:\n%s", info)
	}
}

func TestSignDMG(t *testing.T) {
	s := newHSMSigner(t)
	if detectSingleType(testDmg) != artifactDMG {
		t.Fatalf("fixture is not detected as a DMG")
	}
	signed, err := s.SignFile(testDmg, Options{})
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signed.dmg")
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatal(err)
	}
	if info := sigInfo(t, path); !strings.Contains(info, "code_signature_offset") {
		t.Errorf("signed DMG missing signature:\n%s", info)
	}
}

func TestSignPkg(t *testing.T) {
	// installer mode uses a PEM key (rcodesign cannot sign .pkg with PKCS#11).
	s := newInstallerSigner(t)
	if detectSingleType(testPkg) != artifactXAR {
		t.Fatalf("fixture is not detected as a XAR/.pkg")
	}
	signed, err := s.SignFile(testPkg, Options{})
	if err != nil {
		t.Fatalf("SignFile failed: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signed.pkg")
	if err := os.WriteFile(path, signed, 0644); err != nil {
		t.Fatal(err)
	}
	if info := sigInfo(t, path); !strings.Contains(info, "signature_algorithm") {
		t.Errorf("signed .pkg missing signature:\n%s", info)
	}
}

func TestModeValidation(t *testing.T) {
	// New() succeeds for both modes; SignFile rejects mismatched artifact types
	// before doing any signing, so this needs no HSM or rcodesign. A real
	// rcodesign invocation would produce an "apple: rcodesign failed" error, so
	// asserting the specific mode error (and the absence of "rcodesign") proves
	// signing was never attempted.
	cases := []struct {
		name    string
		signer  *AppleSigner
		input   []byte
		wantErr string
	}{
		{"application rejects .pkg", newDummySigner(t, ModeApplication), testPkg, "application mode cannot sign a XAR"},
		{"installer rejects Mach-O", newDummySigner(t, ModeInstaller), testMachO, "installer mode requires a XAR"},
		{"installer rejects .tar.gz", newDummySigner(t, ModeInstaller), buildAppTarGz(t), "installer mode cannot sign a .tar.gz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.signer.SignFile(tc.input, Options{})
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
			if strings.Contains(err.Error(), "rcodesign") {
				t.Fatalf("rcodesign should not have been invoked; got %v", err)
			}
		})
	}
}

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		glob  string
		path  string
		match bool
	}{
		{"Contents/MacOS/foo", "Contents/MacOS/foo", true},
		{"Contents/MacOS/foo", "Contents/MacOS/bar", false},
		{"Contents/MacOS/*", "Contents/MacOS/foo", true},
		{"Contents/MacOS/*", "Contents/MacOS/sub/foo", false},
		{"Contents/**", "Contents/MacOS/sub/foo", true},
		{"Contents/**/foo", "Contents/MacOS/sub/foo", true},
		{"Contents/**/foo", "Contents/foo", true},
		// ** spans whole segments only: must not match a partial segment.
		{"Contents/**/foo", "Contents/barfoo", false},
		{"a/*/c", "a/b/c", true},
		{"*.dylib", "libfoo.dylib", true},
		{"lib?.dylib", "liba.dylib", true},
		{"lib[ab].dylib", "libb.dylib", true},
		{"lib[!ab].dylib", "libc.dylib", true},
		{"lib[!ab].dylib", "liba.dylib", false},
	}
	for _, tc := range cases {
		re, err := globToRegexp(tc.glob)
		if err != nil {
			t.Fatalf("glob %q: unexpected error %v", tc.glob, err)
		}
		if got := re.MatchString(tc.path); got != tc.match {
			t.Errorf("glob %q vs %q: got %v, want %v", tc.glob, tc.path, got, tc.match)
		}
	}
}

func TestGlobToRegexpInvalid(t *testing.T) {
	// A malformed glob (from the request) must return an error, not panic.
	for _, bad := range []string{"[", `[\]`, "[z-a]"} {
		if _, err := globToRegexp(bad); err == nil {
			t.Errorf("glob %q: expected an error, got nil", bad)
		}
	}
}

func TestDetectSingleType(t *testing.T) {
	if detectSingleType(testMachO) != artifactMachO {
		t.Error("macho fixture not detected as Mach-O")
	}
	if detectSingleType(testPkg) != artifactXAR {
		t.Error("pkg fixture not detected as XAR")
	}
	if detectSingleType(testDmg) != artifactDMG {
		t.Error("dmg fixture not detected as DMG")
	}
	if detectSingleType([]byte("not an artifact")) != artifactUnknown {
		t.Error("random bytes should be unknown")
	}
}

func TestGetOptions(t *testing.T) {
	in := map[string]interface{}{
		"identifier": "org.example.app",
		"hardened_sign_config": []map[string]interface{}{
			{"globs": []string{"Contents/MacOS/foo"}, "runtime": true, "entitlements": "<plist/>"},
		},
	}
	opts, err := GetOptions(in)
	if err != nil {
		t.Fatalf("GetOptions failed: %v", err)
	}
	if opts.Identifier != "org.example.app" {
		t.Errorf("bad identifier: %q", opts.Identifier)
	}
	if len(opts.HardenedSignConfig) != 1 || !opts.HardenedSignConfig[0].Runtime {
		t.Errorf("bad hardened sign config: %+v", opts.HardenedSignConfig)
	}
}

// --- extractTarGz security tests (no HSM/rcodesign needed) ---

type tarEntry struct {
	typ      byte
	name     string
	linkname string
	mode     int64
	body     []byte
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0644
		}
		hdr := &tar.Header{Typeflag: e.typ, Name: e.name, Linkname: e.linkname, Mode: mode, Size: int64(len(e.body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// assertNothingOutside walks root and fails if any regular file or symlink was
// created outside dest (i.e. an extraction escape).
func assertNothingOutside(t *testing.T, root, dest string) {
	t.Helper()
	destPrefix := dest + string(os.PathSeparator)
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if p != dest && !strings.HasPrefix(p, destPrefix) {
			t.Errorf("extraction escaped dest: %s", p)
		}
		return nil
	})
}

// TestExtractTarGzContainment feeds malicious archives (path traversal, and the
// symlink/hardlink traversal PoCs from the security review) and asserts nothing
// is created outside dest. SecureJoin clamps escapes, so extraction may or may
// not return an error; the invariant is containment.
func TestExtractTarGzContainment(t *testing.T) {
	cases := []struct {
		name    string
		entries []tarEntry
	}{
		{"parent traversal in name", []tarEntry{{typ: tar.TypeReg, name: "../evil", body: []byte("x")}}},
		{"relative symlink escape then write", []tarEntry{
			{typ: tar.TypeSymlink, name: "evil", linkname: "../../.."},
			{typ: tar.TypeReg, name: "evil/pwned", body: []byte("x")},
		}},
		// PoC #1 from the review: a "." symlink lexically cancels a "..".
		{"dot-symlink write-through", []tarEntry{
			{typ: tar.TypeSymlink, name: "x", linkname: "."},
			{typ: tar.TypeSymlink, name: "x/y", linkname: "../canary.txt"},
			{typ: tar.TypeReg, name: "y", body: []byte("PWNED")},
		}},
		// deeper variant reaching several levels up.
		{"dot-symlink write-through depth", []tarEntry{
			{typ: tar.TypeSymlink, name: "a", linkname: "."},
			{typ: tar.TypeSymlink, name: "a/b", linkname: "."},
			{typ: tar.TypeSymlink, name: "a/b/c", linkname: "../../../victim.txt"},
			{typ: tar.TypeReg, name: "c", body: []byte("PWNED")},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "l1", "l2", "l3", "extract")
			_ = extractTarGz(makeTarGz(t, tc.entries), dest)
			assertNothingOutside(t, root, dest)
		})
	}
}

// TestExtractTarGzNoHardlinkExfil is PoC #2 from the review: a "." symlink plus
// a directory symlink lets a hardlink reach a server file above dest, whose
// bytes would then be copied into the re-archived output. Assert the secret
// never reaches the output.
func TestExtractTarGzNoHardlinkExfil(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "extract")
	const secret = "TOP-SECRET-HSM-PIN-1234"
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	entries := []tarEntry{
		{typ: tar.TypeSymlink, name: "d", linkname: "."},
		{typ: tar.TypeSymlink, name: "d/esc", linkname: ".."},
		{typ: tar.TypeLink, name: "captured", linkname: "esc/secret.txt"},
	}
	_ = extractTarGz(makeTarGz(t, entries), dest)

	out, err := createTarGz(dest)
	if err != nil {
		t.Fatalf("createTarGz: %v", err)
	}
	if bytes.Contains(out, []byte(secret)) {
		t.Fatal("server secret was exfiltrated into the output archive")
	}
}

// TestCreateTarGzDeduplicatesHardlinks guards against the re-archive
// amplification found in review: N hardlinks to one file must not copy the
// content N times into the (in-memory) output.
func TestCreateTarGzDeduplicatesHardlinks(t *testing.T) {
	root := t.TempDir()
	// incompressible content so gzip can't hide duplication
	blob := make([]byte, 1<<20) // 1 MiB
	for i := range blob {
		blob[i] = byte(i*2654435761 + i>>3)
	}
	if err := os.WriteFile(filepath.Join(root, "real"), blob, 0644); err != nil {
		t.Fatal(err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		if err := os.Link(filepath.Join(root, "real"), filepath.Join(root, fmt.Sprintf("hl%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	out, err := createTarGz(root)
	if err != nil {
		t.Fatal(err)
	}
	// Without inode dedup this would be ~ (n+1) MiB; with dedup it's ~1 MiB.
	if len(out) > 5<<20 {
		t.Fatalf("hardlinks were not deduplicated: output is %d bytes for a 1 MiB file + %d hardlinks", len(out), n)
	}
	// And the links must round-trip back to the same content.
	dest := filepath.Join(t.TempDir(), "back")
	if err := extractTarGz(out, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "hl7"))
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("hardlink content did not round-trip (err %v, equal %v)", err, bytes.Equal(got, blob))
	}
}

func TestExtractTarGzValidSymlink(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")
	entries := []tarEntry{
		{typ: tar.TypeDir, name: "App/", mode: 0755},
		{typ: tar.TypeReg, name: "App/real", body: []byte("hi"), mode: 0644},
		{typ: tar.TypeSymlink, name: "App/link", linkname: "real"},
	}
	if err := extractTarGz(makeTarGz(t, entries), dest); err != nil {
		t.Fatalf("valid relative symlink was rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "App", "link"))
	if err != nil || string(got) != "hi" {
		t.Fatalf("relative symlink did not round-trip: got %q err %v", got, err)
	}
}

func TestExtractTarGzSizeCap(t *testing.T) {
	orig := maxUncompressedBundleBytes
	maxUncompressedBundleBytes = 1024
	defer func() { maxUncompressedBundleBytes = orig }()

	entries := []tarEntry{{typ: tar.TypeReg, name: "big", body: bytes.Repeat([]byte("A"), 4096)}}
	err := extractTarGz(makeTarGz(t, entries), filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "max decompressed size") {
		t.Fatalf("expected a decompressed-size-cap error, got %v", err)
	}
}

func TestExtractTarGzEntryCap(t *testing.T) {
	orig := maxBundleEntries
	maxBundleEntries = 10
	defer func() { maxBundleEntries = orig }()

	var entries []tarEntry
	for i := 0; i < 50; i++ {
		entries = append(entries, tarEntry{typ: tar.TypeDir, name: fmt.Sprintf("d%d/", i), mode: 0755})
	}
	err := extractTarGz(makeTarGz(t, entries), filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "max entry count") {
		t.Fatalf("expected an entry-count-cap error, got %v", err)
	}
}

// --- arg assembly tests (no HSM/rcodesign needed) ---

func hasFlagValue(args []string, flag, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBaseSignArgs(t *testing.T) {
	s := newDummySigner(t, ModeApplication)
	s.AppleConfig = signer.AppleConfig{TeamName: "TEAM", TimestampURL: "none", ForNotarization: true}
	got := s.baseSignArgs([]string{"-C", "/x/cfg"})
	want := []string{"sign", "-C", "/x/cfg", "--team-name", "TEAM", "--timestamp-url", "none", "--for-notarization"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("baseSignArgs = %v, want %v", got, want)
	}

	// Empty AppleConfig omits the optional flags; credential args are preserved.
	s.AppleConfig = signer.AppleConfig{}
	got = s.baseSignArgs([]string{"--pem-file", "/p"})
	want = []string{"sign", "--pem-file", "/p"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("baseSignArgs (empty) = %v, want %v", got, want)
	}
}

func TestSingleFileArgs(t *testing.T) {
	s := newDummySigner(t, ModeApplication)
	s.AppleConfig = signer.AppleConfig{}
	wd := t.TempDir()

	// Mach-O: identifier and runtime apply.
	args, err := s.singleFileArgs([]string{"-C", "/c"}, artifactMachO,
		[]signer.HardenedSignEntry{{Runtime: true}}, Options{Identifier: "org.x"}, wd)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--binary-identifier", "org.x") {
		t.Errorf("Mach-O args missing --binary-identifier: %v", args)
	}
	if !hasFlagValue(args, "--code-signature-flags", "runtime") {
		t.Errorf("Mach-O args missing runtime flag: %v", args)
	}

	// DMG: identifier and runtime do not apply.
	args, err = s.singleFileArgs([]string{"-C", "/c"}, artifactDMG,
		[]signer.HardenedSignEntry{{Runtime: true}}, Options{Identifier: "org.x"}, wd)
	if err != nil {
		t.Fatal(err)
	}
	if hasFlag(args, "--binary-identifier") {
		t.Errorf("DMG args should not include --binary-identifier: %v", args)
	}
	if hasFlag(args, "--code-signature-flags") {
		t.Errorf("DMG args should not include --code-signature-flags: %v", args)
	}
}

func TestMainScopeArgs(t *testing.T) {
	wd := t.TempDir()
	entries := []signer.HardenedSignEntry{
		{Runtime: true, Entitlements: "<plist/>"},            // main entry
		{Globs: []string{"Contents/MacOS/x"}, Runtime: true}, // path-scoped, ignored for a bare Mach-O
	}
	args, err := mainScopeArgs(wd, entries)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--code-signature-flags", "runtime") {
		t.Errorf("missing runtime flag: %v", args)
	}
	// The entitlements are written to a file and referenced unscoped with -e.
	var entFile string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-e" {
			entFile = args[i+1]
		}
	}
	if entFile == "" {
		t.Fatalf("missing -e entitlements arg: %v", args)
	}
	if data, err := os.ReadFile(entFile); err != nil || string(data) != "<plist/>" {
		t.Errorf("entitlements file wrong: got %q err %v", data, err)
	}
}

func TestEntryScopes(t *testing.T) {
	allPaths := []string{"Contents/MacOS/foo", "Contents/MacOS/bar", "Contents/Frameworks/x.dylib"}

	scopes, err := entryScopes(allPaths, signer.HardenedSignEntry{})
	if err != nil || !reflect.DeepEqual(scopes, []string{""}) {
		t.Errorf("empty globs should map to the main scope, got %v err %v", scopes, err)
	}

	scopes, err = entryScopes(allPaths, signer.HardenedSignEntry{Globs: []string{"Contents/MacOS/*"}})
	if err != nil || !reflect.DeepEqual(scopes, []string{"Contents/MacOS/foo", "Contents/MacOS/bar"}) {
		t.Errorf("glob expansion wrong: got %v err %v", scopes, err)
	}

	if _, err := entryScopes(allPaths, signer.HardenedSignEntry{Globs: []string{"["}}); err == nil {
		t.Error("an invalid glob should return an error")
	}
}

func TestBundleScopedArgs(t *testing.T) {
	app := t.TempDir()
	if err := os.MkdirAll(filepath.Join(app, "Contents", "MacOS"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "Contents", "MacOS", "foo"), []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	entries := []signer.HardenedSignEntry{
		{Globs: []string{"Contents/MacOS/foo"}, Entitlements: "<plist/>", Runtime: true},
	}
	args, err := bundleScopedArgs(app, t.TempDir(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFlagValue(args, "--code-signature-flags", "Contents/MacOS/foo:runtime") {
		t.Errorf("missing scoped runtime flag: %v", args)
	}
	found := false
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-e" && strings.HasPrefix(args[i+1], "Contents/MacOS/foo:") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing scoped entitlements arg: %v", args)
	}
}

func TestWithScope(t *testing.T) {
	if got := withScope("", "runtime"); got != "runtime" {
		t.Errorf("empty scope: got %q", got)
	}
	if got := withScope("Contents/MacOS/x", "runtime"); got != "Contents/MacOS/x:runtime" {
		t.Errorf("scoped: got %q", got)
	}
}

func TestWritePkcs11Config(t *testing.T) {
	s := newDummySigner(t, ModeApplication) // library "/nonexistent...", token "t", pin "0000", key "dummy-key-label"
	cfg := filepath.Join(t.TempDir(), "rcodesign.toml")
	if err := s.writePkcs11Config(cfg, "/certs/leaf.pem"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0400 {
		t.Errorf("config mode = %v, want 0400", fi.Mode().Perm())
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"[signer.pkcs11]",
		`key_label = "dummy-key-label"`,
		`certificate_file = "/certs/leaf.pem"`,
		`token_label = "t"`,
		`pkcs11_pin = "0000"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("config missing %q:\n%s", want, body)
		}
	}

	// A provider with no token/pin omits those keys.
	s2, err := New(signer.Configuration{
		ID: "x", Type: Type, Mode: ModeApplication, PrivateKey: "k", Certificate: testCertPEM,
	}, HSMConfig{LibraryPath: "/x/lib.so"})
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := filepath.Join(t.TempDir(), "rcodesign.toml")
	if err := s2.writePkcs11Config(cfg2, "/certs/leaf.pem"); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(cfg2)
	if strings.Contains(string(data2), "token_label") || strings.Contains(string(data2), "pkcs11_pin") {
		t.Errorf("empty token/pin should be omitted:\n%s", data2)
	}
}

func TestResolveEntries(t *testing.T) {
	s := newDummySigner(t, ModeApplication)
	s.AppleConfig.HardenedSignConfig = []signer.HardenedSignEntry{{Runtime: true}}

	// No per-request config falls back to the signer default.
	got := s.resolveEntries(Options{})
	if len(got) != 1 || !got[0].Runtime {
		t.Errorf("expected config default, got %+v", got)
	}

	// A per-request config overrides the default.
	got = s.resolveEntries(Options{HardenedSignConfig: []signer.HardenedSignEntry{{Globs: []string{"x"}}}})
	if len(got) != 1 || len(got[0].Globs) != 1 || got[0].Runtime {
		t.Errorf("expected request override, got %+v", got)
	}
}

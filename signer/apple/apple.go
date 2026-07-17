// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package apple implements an autograph signer for Apple/macOS artifacts. It
// shells out to rcodesign (github.com/indygreg/apple-platform-rs) to sign
// standalone Mach-O binaries, application bundles (delivered as a .tar.gz
// containing a .app), XAR archives (.pkg installers), and DMG disk images.
// Only signing is implemented here; notarization and stapling are handled by a
// separate system.
//
// Key handling differs by mode:
//
//   - application mode (Mach-O, .app, .dmg) signs with an HSM-resident key
//     through PKCS#11. rcodesign opens the same PKCS#11 provider autograph is
//     configured with (conf.HSM) and signs inside the HSM; the private key
//     never leaves it.
//
//   - installer mode (.pkg / XAR) signs with an in-memory PEM key because
//     rcodesign's XAR path has no PKCS#11 support: it only accepts an in-memory
//     (PEM/p12) key and rejects any HSM key. .pkg installers therefore use a
//     software Developer ID Installer key.
package apple

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/mozilla-services/autograph/signer"

	log "github.com/sirupsen/logrus"
)

const (
	// Type of this signer is "apple". It shells out to rcodesign to sign
	// macOS artifacts (see the package doc for how each mode gets its key).
	Type = "apple"

	// ModeApplication signs Mach-O binaries, .app bundles, and DMG disk
	// images. These use a "Developer ID Application" certificate. This is the
	// default mode.
	ModeApplication = "application"

	// ModeInstaller signs XAR archives (.pkg installers). These require a
	// separate "Developer ID Installer" certificate.
	ModeInstaller = "installer"

	// rcodesignBinary is the name of the rcodesign executable, expected on
	// PATH. It must be built with the pkcs11 feature (see the repo Dockerfile).
	rcodesignBinary = "rcodesign"
)

// HSMConfig holds the PKCS#11 provider settings the signer passes to rcodesign.
// It is populated from autograph's central HSM configuration (conf.HSM) so all
// signers share one provider.
type HSMConfig struct {
	// LibraryPath is the path to the PKCS#11 provider shared object
	// (--pkcs11-library). Required.
	LibraryPath string

	// TokenLabel selects the token holding the key (--pkcs11-token-label).
	TokenLabel string

	// Pin is the PKCS#11 user PIN. When set it is written to a short-lived
	// rcodesign config file (not the command line). May be empty for providers
	// that don't require a PIN.
	Pin string
}

// AppleSigner holds the configuration of the signer.
type AppleSigner struct {
	signer.Configuration

	// mode is ModeApplication or ModeInstaller.
	mode string

	// keyLabel is the PKCS#11 label of the signing key in the HSM (taken from
	// the signer's PrivateKey configuration field).
	keyLabel string

	// certPEM is the signing certificate chain (leaf first) in PEM form. In
	// application mode it is written to a temp file and referenced by the
	// rcodesign PKCS#11 config (the key is in the HSM; the certificate is
	// supplied out of band).
	certPEM []byte

	// hsm holds the PKCS#11 provider settings (application mode only).
	hsm HSMConfig

	// pemBundle holds the private key (PKCS#8) followed by the certificate
	// chain, used only in installer mode where rcodesign cannot use a PKCS#11
	// key for .pkg/XAR signing. It is written to a temp file passed via
	// --pem-file.
	pemBundle []byte
}

// New initializes an apple signer using a configuration and the shared HSM
// (PKCS#11) provider settings.
func New(conf signer.Configuration, hsm HSMConfig) (*AppleSigner, error) {
	s := new(AppleSigner)

	if conf.Type != Type {
		return nil, fmt.Errorf("apple: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type

	if conf.ID == "" {
		return nil, fmt.Errorf("apple: missing signer ID in signer configuration")
	}
	s.ID = conf.ID

	switch conf.Mode {
	case ModeApplication, ModeInstaller:
	case "":
		conf.Mode = ModeApplication
	default:
		return nil, fmt.Errorf("apple: invalid mode %q, must be %q or %q", conf.Mode, ModeApplication, ModeInstaller)
	}
	s.mode = conf.Mode
	s.Mode = conf.Mode

	if conf.PrivateKey == "" {
		return nil, fmt.Errorf("apple: missing private key in signer configuration")
	}
	if conf.Certificate == "" {
		return nil, fmt.Errorf("apple: missing certificate in signer configuration")
	}
	if err := validateCertChain([]byte(conf.Certificate)); err != nil {
		return nil, fmt.Errorf("apple: invalid certificate in signer configuration: %w", err)
	}
	s.PrivateKey = conf.PrivateKey
	s.Certificate = conf.Certificate
	s.certPEM = []byte(conf.Certificate)
	s.AppleConfig = conf.AppleConfig

	if s.mode == ModeInstaller {
		// .pkg / XAR signing cannot use a PKCS#11/HSM key (see the package
		// doc). Require an inline PEM key and build a single PEM bundle
		// (key + certificate chain) to pass to rcodesign via --pem-file.
		if !conf.PrivateKeyHasPEMPrefix() {
			return nil, fmt.Errorf("apple: installer mode requires an inline PEM private key; rcodesign cannot sign .pkg/XAR with an HSM/PKCS#11 key")
		}
		priv, err := conf.GetPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("apple: failed to get installer private key from configuration: %w", err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("apple: failed to encode installer private key to pkcs8: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		var bundle bytes.Buffer
		bundle.Write(keyPEM)
		if !bytes.HasSuffix(keyPEM, []byte("\n")) {
			bundle.WriteByte('\n')
		}
		bundle.WriteString(strings.TrimLeft(conf.Certificate, "\r\n"))
		s.pemBundle = bundle.Bytes()
		return s, nil
	}

	// application mode: the signing key lives in the HSM; PrivateKey holds its
	// PKCS#11 label, not key material. Reject an inline PEM key to avoid
	// silently signing with a software key.
	if conf.PrivateKeyHasPEMPrefix() {
		return nil, fmt.Errorf("apple: application mode PrivateKey must be a PKCS#11 key label, not an inline PEM key")
	}
	s.keyLabel = conf.PrivateKey
	if hsm.LibraryPath == "" {
		return nil, fmt.Errorf("apple: application mode requires a PKCS#11/HSM provider but none is configured (set the hsm section)")
	}
	s.hsm = hsm
	return s, nil
}

// validateCertChain ensures the PEM data contains at least one X.509
// certificate and that every certificate block parses.
func validateCertChain(pemData []byte) error {
	rest := pemData
	found := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		found++
	}
	if found == 0 {
		return fmt.Errorf("no CERTIFICATE PEM block found")
	}
	return nil
}

// Config returns the configuration of the current signer.
func (s *AppleSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		Mode:        s.Mode,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
		AppleConfig: s.AppleConfig,
	}
}

// Options are per-request signing options. They mirror (a subset of) Mozilla
// iscript's hardened-sign-config and, when present, override the signer's
// configured defaults.
type Options struct {
	// HardenedSignConfig, when non-empty, replaces the signer's configured
	// default hardened_sign_config for this request.
	HardenedSignConfig []signer.HardenedSignEntry `json:"hardened_sign_config,omitempty"`

	// Identifier sets --binary-identifier. It only applies to standalone
	// Mach-O binaries; bundles use their Info.plist CFBundleIdentifier.
	Identifier string `json:"identifier,omitempty"`
}

// GetDefaultOptions returns the default options of the signer.
func (s *AppleSigner) GetDefaultOptions() interface{} {
	return Options{}
}

// resolveEntries returns the hardened-sign entries for a request: the
// request's own entries when present, otherwise the signer's configured
// defaults.
func (s *AppleSigner) resolveEntries(opts Options) []signer.HardenedSignEntry {
	if len(opts.HardenedSignConfig) > 0 {
		return opts.HardenedSignConfig
	}
	return s.AppleConfig.HardenedSignConfig
}

// GetOptions reflects an input interface into an Options struct.
func GetOptions(input interface{}) (options Options, err error) {
	buf, err := json.Marshal(input)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, &options)
	return
}

// GetTestFile returns a valid artifact the signer can sign, used by the
// monitor. It matches the signer's mode: an unsigned Mach-O for application
// mode, and an unsigned .pkg for installer mode.
func (s *AppleSigner) GetTestFile() []byte {
	if s.mode == ModeInstaller {
		return testPkg
	}
	return testMachO
}

// SignFile signs a macOS artifact and returns the signed artifact. The input
// type is auto-detected: a gzip stream is treated as a .tar.gz containing a
// .app bundle (extracted, signed, and re-archived); anything else is treated
// as a single-file artifact (Mach-O, DMG, or XAR/.pkg) and signed in place.
func (s *AppleSigner) SignFile(input []byte, options interface{}) (signer.SignedFile, error) {
	opts, err := GetOptions(options)
	if err != nil {
		return nil, fmt.Errorf("apple: failed to parse options: %w", err)
	}
	entries := s.resolveEntries(opts)

	workDir, err := os.MkdirTemp("", fmt.Sprintf("apple_%s_", s.ID))
	if err != nil {
		return nil, fmt.Errorf("apple: failed to create work dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(workDir); err != nil {
			log.Warnf("apple: failed to remove work dir %q: %v", workDir, err)
		}
	}()

	// Write the credential material (PKCS#11 config for application mode, PEM
	// bundle for installer mode) into the 0700 work dir and get the rcodesign
	// args that reference it. Everything here is removed with the work dir.
	credArgs, err := s.prepareCredentials(workDir)
	if err != nil {
		return nil, err
	}

	if isGzip(input) {
		if s.mode == ModeInstaller {
			return nil, fmt.Errorf("apple: installer mode cannot sign a .tar.gz bundle; expected a .pkg")
		}
		return s.signBundle(input, credArgs, workDir, entries, opts)
	}
	return s.signSingleFile(input, credArgs, workDir, entries, opts)
}

// prepareCredentials writes the credential files for the signer's mode into
// workDir and returns the rcodesign arguments that reference them.
//
//   - installer mode: a 0400 PEM bundle (key + cert) referenced by --pem-file.
//   - application mode: a 0400 PKCS#11 config file (carrying the PIN, so it
//     never reaches the command line or environment) referenced by -C.
func (s *AppleSigner) prepareCredentials(workDir string) ([]string, error) {
	if s.mode == ModeInstaller {
		pemFile := filepath.Join(workDir, "credentials.pem")
		if err := os.WriteFile(pemFile, s.pemBundle, 0400); err != nil {
			return nil, fmt.Errorf("apple: failed to write credentials: %w", err)
		}
		return []string{"--pem-file", pemFile}, nil
	}
	certFile := filepath.Join(workDir, "certificate.pem")
	if err := os.WriteFile(certFile, s.certPEM, 0400); err != nil {
		return nil, fmt.Errorf("apple: failed to write certificate: %w", err)
	}
	configFile := filepath.Join(workDir, "rcodesign.toml")
	if err := s.writePkcs11Config(configFile, certFile); err != nil {
		return nil, err
	}
	return []string{"-C", configFile}, nil
}

// signSingleFile signs a standalone Mach-O, DMG, or XAR/.pkg artifact in place.
func (s *AppleSigner) signSingleFile(input []byte, credArgs []string, workDir string, entries []signer.HardenedSignEntry, opts Options) (signer.SignedFile, error) {
	kind := detectSingleType(input)
	switch s.mode {
	case ModeInstaller:
		if kind != artifactXAR {
			return nil, fmt.Errorf("apple: installer mode requires a XAR/.pkg artifact, got %s", kind)
		}
	case ModeApplication:
		if kind == artifactXAR {
			return nil, fmt.Errorf("apple: application mode cannot sign a XAR/.pkg artifact; use an installer-mode signer")
		}
	}

	inPath := filepath.Join(workDir, "artifact")
	if err := os.WriteFile(inPath, input, 0644); err != nil {
		return nil, fmt.Errorf("apple: failed to write input artifact: %w", err)
	}

	args, err := s.singleFileArgs(credArgs, kind, entries, opts, workDir)
	if err != nil {
		return nil, err
	}
	args = append(args, inPath)

	if err := s.runRcodesign(args); err != nil {
		return nil, err
	}
	signed, err := os.ReadFile(inPath)
	if err != nil {
		return nil, fmt.Errorf("apple: failed to read signed artifact: %w", err)
	}
	return signer.SignedFile(signed), nil
}

// singleFileArgs builds the rcodesign arguments for a single-file artifact
// (everything before the input path). Entitlements and the hardened runtime
// only apply to Mach-O; DMG and XAR wrappers are signed without them, and
// --binary-identifier applies only to a bare Mach-O.
func (s *AppleSigner) singleFileArgs(credArgs []string, kind artifactType, entries []signer.HardenedSignEntry, opts Options, workDir string) ([]string, error) {
	args := s.baseSignArgs(credArgs)
	if opts.Identifier != "" && kind == artifactMachO {
		args = append(args, "--binary-identifier", opts.Identifier)
	}
	if kind == artifactMachO {
		mainArgs, err := mainScopeArgs(workDir, entries)
		if err != nil {
			return nil, err
		}
		args = append(args, mainArgs...)
	}
	return args, nil
}

// signBundle extracts a .tar.gz, signs every top-level .app bundle it contains,
// and returns a re-created .tar.gz of the (now signed) tree.
func (s *AppleSigner) signBundle(input []byte, credArgs []string, workDir string, entries []signer.HardenedSignEntry, opts Options) (signer.SignedFile, error) {
	extractDir := filepath.Join(workDir, "extract")
	if err := extractTarGz(input, extractDir); err != nil {
		return nil, fmt.Errorf("apple: failed to extract bundle archive: %w", err)
	}

	appDirs, err := findAppBundles(extractDir)
	if err != nil {
		return nil, err
	}
	if len(appDirs) == 0 {
		return nil, fmt.Errorf("apple: no .app bundle found in the .tar.gz archive")
	}

	for _, app := range appDirs {
		appAbs := filepath.Join(extractDir, filepath.FromSlash(app))
		args := s.baseSignArgs(credArgs)
		scopedArgs, err := bundleScopedArgs(appAbs, workDir, entries)
		if err != nil {
			return nil, err
		}
		args = append(args, scopedArgs...)
		args = append(args, appAbs)
		if err := s.runRcodesign(args); err != nil {
			return nil, fmt.Errorf("apple: failed to sign bundle %q: %w", app, err)
		}
	}

	out, err := createTarGz(extractDir)
	if err != nil {
		return nil, fmt.Errorf("apple: failed to re-archive signed bundle: %w", err)
	}
	return signer.SignedFile(out), nil
}

// baseSignArgs returns the rcodesign arguments common to every signing
// operation: the sign subcommand, the mode-specific credential args, team
// name, timestamp handling, and notarization flag.
func (s *AppleSigner) baseSignArgs(credArgs []string) []string {
	args := append([]string{"sign"}, credArgs...)
	if s.AppleConfig.TeamName != "" {
		args = append(args, "--team-name", s.AppleConfig.TeamName)
	}
	// An empty TimestampURL leaves rcodesign's default (Apple's server). Any
	// explicit value (including the special "none") is passed through.
	if s.AppleConfig.TimestampURL != "" {
		args = append(args, "--timestamp-url", s.AppleConfig.TimestampURL)
	}
	if s.AppleConfig.ForNotarization {
		args = append(args, "--for-notarization")
	}
	return args
}

// writePkcs11Config writes a 0400 rcodesign TOML config selecting the HSM
// PKCS#11 signing key and certificate. Keeping these settings (especially the
// PIN) in a file avoids exposing the PIN on the command line or through the
// environment (rcodesign's --pkcs11-pin-env is currently unreliable).
func (s *AppleSigner) writePkcs11Config(path, certFile string) error {
	var b strings.Builder
	b.WriteString("[signer.pkcs11]\n")
	fmt.Fprintf(&b, "library_path = %s\n", tomlString(s.hsm.LibraryPath))
	fmt.Fprintf(&b, "key_label = %s\n", tomlString(s.keyLabel))
	fmt.Fprintf(&b, "certificate_file = %s\n", tomlString(certFile))
	if s.hsm.TokenLabel != "" {
		fmt.Fprintf(&b, "token_label = %s\n", tomlString(s.hsm.TokenLabel))
	}
	if s.hsm.Pin != "" {
		fmt.Fprintf(&b, "pkcs11_pin = %s\n", tomlString(s.hsm.Pin))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0400); err != nil {
		return fmt.Errorf("apple: failed to write rcodesign config: %w", err)
	}
	return nil
}

// tomlString renders a Go string as a TOML basic string.
func tomlString(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return `"` + v + `"`
}

// runRcodesign executes rcodesign (inheriting the parent environment so the
// PKCS#11 provider's own configuration, e.g. KMS_PKCS11_CONFIG or
// SOFTHSM2_CONF, is available) and wraps failures with the combined output.
func (s *AppleSigner) runRcodesign(args []string) error {
	cmd := exec.Command(rcodesignBinary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apple: rcodesign failed: %w\n%s", err, out)
	}
	log.Debugf("apple: rcodesign output:\n%s", out)
	return nil
}

// mainScopeArgs builds unscoped rcodesign args (applying to the main entity)
// for a standalone Mach-O from the hardened-sign entries that target the main
// entity. Path-scoped entries are ignored for a bare Mach-O since there is no
// bundle tree to match against.
func mainScopeArgs(workDir string, entries []signer.HardenedSignEntry) ([]string, error) {
	var args []string
	runtime := false
	entWritten := false
	for i, e := range entries {
		if !entryTargetsMain(e) {
			continue
		}
		if e.Runtime {
			runtime = true
		}
		if e.Entitlements != "" && !entWritten {
			entFile := filepath.Join(workDir, fmt.Sprintf("entitlements-main-%d.plist", i))
			if err := os.WriteFile(entFile, []byte(e.Entitlements), 0644); err != nil {
				return nil, fmt.Errorf("apple: failed to write entitlements: %w", err)
			}
			args = append(args, "-e", entFile)
			entWritten = true
		}
	}
	if runtime {
		args = append(args, "--code-signature-flags", "runtime")
	}
	return args, nil
}

// bundleScopedArgs expands each hardened-sign entry's globs against the
// extracted bundle and returns rcodesign scoped arguments applying the
// entitlements and runtime flag to the matched paths.
func bundleScopedArgs(appAbs, workDir string, entries []signer.HardenedSignEntry) ([]string, error) {
	allPaths, err := listRelPaths(appAbs)
	if err != nil {
		return nil, err
	}
	var args []string
	for i, e := range entries {
		var entFile string
		if e.Entitlements != "" {
			entFile = filepath.Join(workDir, fmt.Sprintf("entitlements-%d.plist", i))
			if err := os.WriteFile(entFile, []byte(e.Entitlements), 0644); err != nil {
				return nil, fmt.Errorf("apple: failed to write entitlements: %w", err)
			}
		}
		scopes, err := entryScopes(allPaths, e)
		if err != nil {
			return nil, err
		}
		for _, scope := range scopes {
			if e.Runtime {
				args = append(args, "--code-signature-flags", withScope(scope, "runtime"))
			}
			if entFile != "" {
				args = append(args, "-e", withScope(scope, entFile))
			}
		}
	}
	return args, nil
}

// entryScopes resolves an entry's globs to rcodesign scope strings. An empty
// scope string ("") denotes the main (unscoped) entity. It returns an error if
// a glob (which comes from the request) is not a valid pattern.
func entryScopes(allPaths []string, e signer.HardenedSignEntry) ([]string, error) {
	if len(e.Globs) == 0 {
		return []string{""}, nil
	}
	var scopes []string
	seen := map[string]bool{}
	for _, g := range e.Globs {
		g = strings.TrimPrefix(strings.TrimSpace(g), "/")
		if g == "" || g == "main" || g == "@main" {
			if !seen[""] {
				seen[""] = true
				scopes = append(scopes, "")
			}
			continue
		}
		re, err := globToRegexp(g)
		if err != nil {
			return nil, fmt.Errorf("apple: invalid hardened-sign glob %q: %w", g, err)
		}
		matched := false
		for _, rel := range allPaths {
			if re.MatchString(rel) && !seen[rel] {
				seen[rel] = true
				scopes = append(scopes, rel)
				matched = true
			}
		}
		if !matched {
			log.Warnf("apple: hardened-sign glob %q matched no paths in bundle", g)
		}
	}
	return scopes, nil
}

// entryTargetsMain reports whether a hardened-sign entry applies to the main
// entity (empty globs, or a glob referring to the main scope).
func entryTargetsMain(e signer.HardenedSignEntry) bool {
	if len(e.Globs) == 0 {
		return true
	}
	for _, g := range e.Globs {
		switch strings.TrimPrefix(strings.TrimSpace(g), "/") {
		case "", "main", "@main":
			return true
		}
	}
	return false
}

// withScope formats a scoped rcodesign value. An empty scope yields an
// unscoped value (which rcodesign applies to the main entity).
func withScope(scope, value string) string {
	if scope == "" {
		return value
	}
	return scope + ":" + value
}

// artifactType identifies a single-file macOS artifact.
type artifactType string

const (
	artifactMachO   artifactType = "mach-o"
	artifactXAR     artifactType = "xar/pkg"
	artifactDMG     artifactType = "dmg"
	artifactUnknown artifactType = "unknown"
)

// isGzip reports whether data begins with the gzip magic bytes.
func isGzip(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// detectSingleType inspects the leading (and, for DMG, trailing) bytes to
// classify a single-file artifact.
func detectSingleType(data []byte) artifactType {
	if len(data) >= 4 {
		switch {
		case bytes.Equal(data[:4], []byte("xar!")):
			return artifactXAR
		case isMachOMagic(data[:4]):
			return artifactMachO
		}
	}
	// DMG has a 512-byte "koly" trailer at the end of the file.
	if len(data) >= 512 && bytes.Equal(data[len(data)-512:len(data)-508], []byte("koly")) {
		return artifactDMG
	}
	return artifactUnknown
}

// isMachOMagic reports whether the 4 bytes are a Mach-O or fat/universal magic.
func isMachOMagic(b []byte) bool {
	switch {
	case bytes.Equal(b, []byte{0xfe, 0xed, 0xfa, 0xce}), // 32-bit BE
		bytes.Equal(b, []byte{0xce, 0xfa, 0xed, 0xfe}), // 32-bit LE
		bytes.Equal(b, []byte{0xfe, 0xed, 0xfa, 0xcf}), // 64-bit BE
		bytes.Equal(b, []byte{0xcf, 0xfa, 0xed, 0xfe}), // 64-bit LE
		bytes.Equal(b, []byte{0xca, 0xfe, 0xba, 0xbe}), // fat BE
		bytes.Equal(b, []byte{0xbe, 0xba, 0xfe, 0xca}): // fat LE
		return true
	}
	return false
}

// globToRegexp converts a shell-style glob (supporting *, **, ?, and [...]
// character classes) into an anchored regexp matched against forward-slash
// relative paths. * matches within a single path segment; ** spans whole
// segments only ("a/**/b" matches "a/b" and "a/x/b" but not "a/xb"). It
// returns an error if the glob (which comes from the request) is not a valid
// pattern.
func globToRegexp(g string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); {
		c := g[i]
		switch c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				i += 2
				if i < len(g) && g[i] == '/' {
					i++
					// "**/" matches zero or more whole path segments
					b.WriteString("(?:.*/)?")
				} else {
					// trailing "**" matches the rest of the path
					b.WriteString(".*")
				}
				continue
			}
			b.WriteString("[^/]*")
			i++
		case '?':
			b.WriteString("[^/]")
			i++
		case '[':
			j := i + 1
			b.WriteByte('[')
			if j < len(g) && g[j] == '!' {
				b.WriteByte('^')
				j++
			}
			for j < len(g) && g[j] != ']' {
				b.WriteByte(g[j])
				j++
			}
			b.WriteByte(']')
			i = j + 1
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("bad glob pattern: %w", err)
	}
	return re, nil
}

// listRelPaths returns every path under root as a forward-slash path relative
// to root (excluding root itself).
func listRelPaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	return paths, err
}

// findAppBundles returns the forward-slash relative paths of the top-level
// .app bundle directories under root. Nested bundles are skipped since
// rcodesign signs them recursively.
func findAppBundles(root string) ([]string, error) {
	var apps []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".app") {
			rel, relErr := filepath.Rel(root, p)
			if relErr != nil {
				return relErr
			}
			apps = append(apps, filepath.ToSlash(rel))
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("apple: failed to scan for .app bundles: %w", err)
	}
	return apps, nil
}

// Limits on a bundle archive to prevent a small .tar.gz from exhausting
// resources (gzip can expand ~1000:1, and the request body limit only bounds
// the compressed size). Both are generous relative to real macOS app bundles
// (a few hundred MB, ~tens of thousands of files) and are vars only so tests
// can lower them.
var (
	// maxUncompressedBundleBytes caps total bytes written to disk on extraction
	// and total content re-archived by createTarGz.
	maxUncompressedBundleBytes int64 = 2 << 30 // 2 GiB
	// maxBundleEntries caps the number of archive entries, bounding inode and
	// CPU use from an archive of many tiny/empty entries.
	maxBundleEntries = 200000
)

// extractTarGz extracts a gzip-compressed tar archive into dest, preserving
// file modes and symlinks. Every entry location (and every hardlink source) is
// resolved with filepath-securejoin, which follows existing symlink components
// but clamps any escape back inside dest — so an attacker-supplied archive
// cannot write or read outside dest via "..", symlink, or hardlink traversal.
// This is safe against symlink races because dest is a fresh 0700 dir with no
// concurrent writer. It also caps total size and entry count.
func extractTarGz(data []byte, dest string) error {
	if err := os.MkdirAll(dest, 0755); err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("apple: gzip: %w", err)
	}
	defer gz.Close()

	remaining := maxUncompressedBundleBytes
	entries := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("apple: tar: %w", err)
		}
		entries++
		if entries > maxBundleEntries {
			return fmt.Errorf("apple: bundle exceeds max entry count of %d", maxBundleEntries)
		}
		// Resolve the entry's real location inside dest, clamping any traversal.
		target, err := securejoin.SecureJoin(dest, hdr.Name)
		if err != nil {
			return fmt.Errorf("apple: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&os.ModePerm); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			// O_NOFOLLOW is belt-and-suspenders: SecureJoin has already
			// resolved any leaf symlink, so target is never a symlink here.
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, os.FileMode(hdr.Mode)&os.ModePerm)
			if err != nil {
				return err
			}
			// Cap per-file output at the remaining budget (+1 to detect
			// overflow) so a decompression bomb can't exceed the total.
			n, copyErr := io.Copy(f, io.LimitReader(tr, remaining+1))
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			remaining -= n
			if remaining < 0 {
				return fmt.Errorf("apple: bundle exceeds max decompressed size of %d bytes", maxUncompressedBundleBytes)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			// The symlink is created at a clamped-within-dest location, and any
			// later access through it is re-clamped by SecureJoin, so an
			// escaping target cannot be used to read/write outside dest. Reject
			// absolute targets defensively so we never emit one.
			if filepath.IsAbs(hdr.Linkname) {
				return fmt.Errorf("apple: absolute symlink target %q is not allowed", hdr.Linkname)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			// Clamp the hardlink source inside dest too, else its bytes (e.g. a
			// server secret) could be linked in and copied into the output.
			src, err := securejoin.SecureJoin(dest, hdr.Linkname)
			if err != nil {
				return fmt.Errorf("apple: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			if err := os.Link(src, target); err != nil {
				return err
			}
		default:
			log.Warnf("apple: skipping unsupported tar entry %q (type %d)", hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// inodeKey returns a (device, inode) key for a hardlinked regular file. ok is
// false for files with a single link or on platforms that don't expose
// syscall.Stat_t, in which case hardlink dedup is simply skipped.
func inodeKey(info os.FileInfo) (key [2]uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink <= 1 {
		return key, false
	}
	return [2]uint64{uint64(st.Dev), uint64(st.Ino)}, true
}

// createTarGz builds a gzip-compressed tar archive of everything under root,
// preserving relative paths, file modes, symlinks, and hardlinks (deduplicated
// by inode). Total content is bounded by maxUncompressedBundleBytes.
func createTarGz(root string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// Deduplicate hardlinks by inode: the first occurrence is written as a
	// regular file and later links to the same inode are emitted as tar
	// hardlinks. This keeps the archive faithful and, crucially, stops one
	// on-disk file from being re-copied once per hardlink (which would let a
	// tiny archive of many hardlinks blow up the in-memory re-archive).
	firstByInode := map[[2]uint64]string{}
	var written int64

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}

		if info.Mode().IsRegular() {
			if key, ok := inodeKey(info); ok {
				if first, dup := firstByInode[key]; dup {
					hdr.Typeflag = tar.TypeLink
					hdr.Linkname = first
					hdr.Size = 0
					return tw.WriteHeader(hdr)
				}
				firstByInode[key] = hdr.Name
			}
			written += info.Size()
			if written > maxUncompressedBundleBytes {
				return fmt.Errorf("apple: re-archived bundle exceeds max size of %d bytes", maxUncompressedBundleBytes)
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		}
		return tw.WriteHeader(hdr)
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

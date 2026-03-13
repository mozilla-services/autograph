package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mozilla-services/autograph/formats"
)

func verifyGPG2RPMSignature(resp formats.SignatureResponse) error {
	log.Printf("Verifying %s", resp)
	if resp.PublicKey == "" {
		return fmt.Errorf("gpg2/rpmsign: empty public_key in response")
	}
	if len(resp.SignedFiles) != 1 {
		return fmt.Errorf("gpg2/rpmsign: expected exactly 1 signed file, got %d", len(resp.SignedFiles))
	}
	sf := resp.SignedFiles[0]
	if sf.Name == "" {
		sf.Name = "monitor.rpm"
	}
	if filepath.Ext(sf.Name) != ".rpm" {
		return fmt.Errorf("gpg2/rpmsign: signed file %q is not an .rpm", sf.Name)
	}

	// Decode the signed RPM bytes.
	rpmBytes, err := base64.StdEncoding.DecodeString(sf.Content)
	if err != nil {
		return fmt.Errorf("gpg2/rpmsign: failed to base64-decode signed rpm: %w", err)
	}
	log.Print("Decoded: signed RPM bytes")

	// Create isolated workspace: rpm db + files.
	workDir, err := os.MkdirTemp("", "autograph-monitor-rpmsign-*")
	if err != nil {
		return fmt.Errorf("gpg2/rpmsign: failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	rpmDBPath := filepath.Join(workDir, "rpmdb")
	if err := os.MkdirAll(rpmDBPath, 0o700); err != nil {
		return fmt.Errorf("gpg2/rpmsign: failed to create rpmdb dir: %w", err)
	}

	pubKeyPath := filepath.Join(workDir, "pubkey.asc")
	if err := os.WriteFile(pubKeyPath, []byte(resp.PublicKey), 0o600); err != nil {
		return fmt.Errorf("gpg2/rpmsign: failed to write pubkey: %w", err)
	}

	rpmPath := filepath.Join(workDir, filepath.Base(sf.Name))
	if err := os.WriteFile(rpmPath, rpmBytes, 0o600); err != nil {
		return fmt.Errorf("gpg2/rpmsign: failed to write signed rpm: %w", err)
	}

	// Run rpm in an isolated dbpath so we don't depend on system RPM keyring or root.
	// 1) init db
	// 2) import key
	// 3) verify signature
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	run := func(name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return out, fmt.Errorf("%s %v failed: %w\n%s", name, args, err, string(out))
		}
		return out, nil
	}

	// Some distros require initdb before --import works with a custom dbpath.
	if _, err := run("rpm", "--dbpath", rpmDBPath, "--initdb"); err != nil {
		return fmt.Errorf("gpg2/rpmsign: rpm initdb failed: %w", err)
	}

	if _, err := run("rpm", "--dbpath", rpmDBPath, "--import", pubKeyPath); err != nil {
		return fmt.Errorf("gpg2/rpmsign: rpm import key failed: %w", err)
	}

	// --checksig returns non-zero on failure; that's enough for monitoring.
	out, err := run("rpm", "--dbpath", rpmDBPath, "--checksig", "--verbose", rpmPath)
	if err != nil {
		return fmt.Errorf("gpg2/rpmsign: rpm checksig failed: %w", err)
	}
	log.Printf("--checksig: %s", out)

	// Optional sanity check: ensure output indicates a signature was checked.
	s := strings.ToLower(string(out))
	if !strings.Contains(s, "signature") && !strings.Contains(s, "pgp") && !strings.Contains(s, "rsa") {
		return fmt.Errorf("gpg2/rpmsign: unexpected rpm checksig output:\n%s", string(out))
	}

	return nil
}

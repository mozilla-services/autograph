package gpg2

import (
	"bytes"
	"crypto/md5"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mozilla-services/autograph/signer"
)

func assertNewSignerWithConfOK(t *testing.T, conf signer.Configuration) *GPG2Signer {
	// These test names end up quite long, and some versions of GPG don't work well
	// with very long paths. See https://bugzilla.redhat.com/show_bug.cgi?id=1813705
	// To work around this, we use a hashed version of the test name. This keeps
	// the prefix consistent across runs while still being short enough.
	hashedName := md5.Sum([]byte(t.Name()))
	tmpDirPrefix := fmt.Sprintf("%x", hashedName)

	s, err := New(conf, tmpDirPrefix)
	if s == nil {
		t.Fatal("expected non-nil signer for valid conf, but got nil signer and err %w", err)
	}
	if err != nil {
		t.Fatalf("signer initialization failed with: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(s.tmpDir, "*"))
	if err != nil {
		t.Fatalf("signer initialization failed to find files in temp dir: %v", err)
	}
	// t.Logf("found files %s", matches)

	// check keyring exists
	foundKeyring := false
	for _, filename := range matches {
		if filepath.Base(filename) == keyRingFilename {
			foundKeyring = true
		}
	}
	if !foundKeyring {
		t.Fatalf("signer initialization failed to create keyring in signer temp dir")
	}

	// check for gpg.conf written for debsign and rpmsign
	if s.Mode == ModeDebsign || s.Mode == ModeRPMSign {
		foundConf := false
		for _, filename := range matches {
			if filepath.Base(filename) == gpgConfFilename {
				foundConf = true
			}
		}
		if !foundConf {
			t.Fatalf("signer initialization failed to create gpg.conf in signer temp dir for %s", s.Mode)
		}
	}

	// check private key is not left on disk
	for _, filename := range matches {
		matched, err := filepath.Match("gpg2_privatekey*", filepath.Base(filename))
		if err != nil {
			t.Fatal(err)
		}
		if matched {
			t.Fatalf("signer initialization failed to remove temp gpg private key: %s", filename)
		}
	}

	return s
}

func assertNewSignerWithConfErrs(t *testing.T, invalidConf signer.Configuration) {
	s, err := New(invalidConf, "")
	if s != nil {
		t.Fatalf("expected nil signer for invalid conf, but got non-nil signer %v", s)
	}
	if err == nil {
		t.Fatal("signer initialization did not fail")
	}
}

// assertClearSignedFilesVerify creates a temp directory
// writes and imports the signer's public key in a new GPG keyring
// then writes and verifies each clear signed file
func assertClearSignedFilesVerify(t *testing.T, signer *GPG2Signer, testname string, signedFiles []signer.NamedSignedFile) {
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("autograph_gpg2_test_%s_", testname))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// write the public key to a file
	publicKeyPath := filepath.Join(tmpDir, "gpg2_publickey")
	err = os.WriteFile(publicKeyPath, []byte(signer.PublicKey), 0755)
	if err != nil {
		t.Fatal(err)
	}
	// call gnupg to create a new keyring, load the key in it
	// t.Logf("loading public key %s\n", signer.PublicKey)
	gnupgCreateKeyring := exec.Command("gpg",
		"--no-options",
		"--homedir", tmpDir,
		"--no-default-keyring",
		"--keyring", filepath.Join(tmpDir, "autograph_test_gpg2_keyring.gpg"),
		"--import", publicKeyPath)
	out, err := gnupgCreateKeyring.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
	}
	// t.Logf("load pubkey out:\n%s", out)

	// write and verify each clear signed file
	// gpg --verify considers more than one signed file a detached sig
	for _, signedFile := range signedFiles {
		signedFilePath := filepath.Join(tmpDir, signedFile.Name)
		err = os.WriteFile(signedFilePath, signedFile.Bytes, 0755)
		if err != nil {
			t.Fatal(err)
		}
		// verify the signature
		gnupgVerifySig := exec.Command("gpg",
			"--no-options",
			"--homedir", tmpDir,
			"--no-default-keyring",
			"--keyring", filepath.Join(tmpDir, "autograph_test_gpg2_keyring.gpg"),
			"--batch",
			"--yes",
			"--pinentry-mode", "error",
			"--verify", signedFilePath)
		out, err = gnupgVerifySig.CombinedOutput()
		if err != nil {
			t.Fatalf("error verifying detached sig: %s\n%s", err, out)
		}
		t.Logf("GnuPG PGP signature verification output:\n%s\n", out)
	}
}

func assertRPMSignedFilesVerify(t *testing.T, signer *GPG2Signer, testname string, signedFiles []signer.NamedSignedFile) {
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("autograph_gpg2_test_%s_", testname))
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	publicKeyPath := filepath.Join(tmpDir, "gpg2_publickey.asc")
	err = os.WriteFile(publicKeyPath, []byte(signer.PublicKey), 0644)
	if err != nil {
		t.Fatal(err)
	}

	rpmInitDB := exec.Command("rpm", "--dbpath", tmpDir, "--initdb")
	out, err := rpmInitDB.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to initialize rpm database: %s\n%s", err, out)
	}

	rpmImportKey := exec.Command("rpm",
		"--dbpath", tmpDir,
		"--import", publicKeyPath)
	out, err = rpmImportKey.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to import public key into rpm keyring: %s\n%s", err, out)
	}

	for _, signedFile := range signedFiles {
		signedFilePath := filepath.Join(tmpDir, signedFile.Name)
		err = os.WriteFile(signedFilePath, signedFile.Bytes, 0644)
		if err != nil {
			t.Fatal(err)
		}

		rpmVerifySig := exec.Command("rpm",
			"--dbpath", tmpDir,
			"-K", signedFilePath)
		out, err = rpmVerifySig.CombinedOutput()
		if err != nil {
			t.Fatalf("error verifying rpm signature: %s\n%s", err, out)
		}

		if !strings.Contains(string(out), "digests signatures OK") {
			t.Fatalf("rpm signature verification failed: %s", out)
		}
		t.Logf("RPM signature verification output:\n%s\n", out)
	}
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	for _, conf := range validSignerConfigs {
		t.Run(fmt.Sprintf("signer %s is valid", conf.ID), func(t *testing.T) {
			t.Parallel()

			_ = assertNewSignerWithConfOK(t, conf)
		})
	}

	t.Run("signer with empty mode defaults to gpg2 mode", func(t *testing.T) {
		t.Parallel()

		conf := pgpsubkeyGPG2SignerConf
		conf.Mode = ""
		s := assertNewSignerWithConfOK(t, conf)
		if s.Mode != ModeGPG2 {
			t.Fatal("gpg signer with empty str for mode did not default to gpg2 mode")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.Type = "badType"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid ID", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.ID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid mode", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.Mode = "system-addon"
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PrivateKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.PrivateKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid PublicKey", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.PublicKey = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("invalid KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.KeyID = ""
		assertNewSignerWithConfErrs(t, invalidConf)
	})

	t.Run("non-alphnumeric KeyID", func(t *testing.T) {
		t.Parallel()

		invalidConf := pgpsubkeyGPG2SignerConf
		invalidConf.KeyID = "!?;\\"
		assertNewSignerWithConfErrs(t, invalidConf)
	})
}

func TestSignerAtExit(t *testing.T) {
	t.Parallel()

	for _, conf := range validSignerConfigs {
		t.Run(fmt.Sprintf("signer %s AtExit clean signer temp dir", conf.ID), func(t *testing.T) {
			t.Parallel()

			s := assertNewSignerWithConfOK(t, conf)
			if err := s.AtExit(); err != nil {
				t.Fatal(err)
			}
			// check AtExit cleans up s.tmpDir
			_, err := os.Stat(s.tmpDir)
			if !os.IsNotExist(err) {
				t.Fatalf("AtExit failed to clean temp dir %s", s.tmpDir)
			}
		})
	}
}

func TestConfig(t *testing.T) {
	t.Parallel()

	for _, conf := range validSignerConfigs {
		t.Run(fmt.Sprintf("signer %s config is ok", conf.ID), func(t *testing.T) {
			t.Parallel()

			s := assertNewSignerWithConfOK(t, conf)

			if s.Config().Type != conf.Type {
				t.Fatalf("signer type %q does not match configuration %q", s.Config().Type, conf.Type)
			}
			if s.Config().ID != conf.ID {
				t.Fatalf("signer id %q does not match configuration %q", s.Config().ID, conf.ID)
			}
			if s.Config().PrivateKey != conf.PrivateKey {
				t.Fatalf("signer private key %q does not match configuration %q", s.Config().PrivateKey, conf.PrivateKey)
			}
		})
	}
}

func TestOptionsAreEmpty(t *testing.T) {
	t.Parallel()

	for _, conf := range validSignerConfigs {
		t.Run(fmt.Sprintf("signer %s default options are empty", conf.ID), func(t *testing.T) {
			t.Parallel()

			s := assertNewSignerWithConfOK(t, conf)
			defaultOpts := s.GetDefaultOptions()
			expectedOpts := Options{}
			if defaultOpts != expectedOpts {
				t.Fatalf("signer returned unexpected default options: %v", defaultOpts)
			}

		})
	}
}

func TestSignData(t *testing.T) {
	for _, conf := range validSignerConfigs {
		input := []byte("foobarbaz1234abcd")
		t.Run(fmt.Sprintf("signer %s signs data", conf.ID), func(t *testing.T) {
			// initialize a signer
			s := assertNewSignerWithConfOK(t, conf)

			// sign input data
			sig, err := s.SignData(input, s.GetDefaultOptions())
			if s.Mode != ModeGPG2 {
				if err == nil {
					t.Fatalf("signer in mode %s signed GPG2 data unexpectedly", s.Mode)
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to sign data: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(s.tmpDir, "gpg2_*input*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 0 {
				t.Fatalf("sign data did not clean up temp input files: %s", matches)
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
				tmpSignatureFile, err := os.CreateTemp("", fmt.Sprintf("gpg2_TestSignPGPAndVerifyWithGnuPG_signature_%s_", s.ID))
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(tmpSignatureFile.Name())
				err = os.WriteFile(tmpSignatureFile.Name(), []byte(sigstr), 0755)
				if err != nil {
					t.Fatalf("error writing file %s: %q", tmpSignatureFile.Name(), err)
				}

				// write the input to a temp file
				tmpContentFile, err := os.CreateTemp("", fmt.Sprintf("gpg2_TestSignPGPAndVerifyWithGnuPG_input_%s_", s.ID))
				if err != nil {
					t.Fatal(err)
				}

				defer os.Remove(tmpContentFile.Name())
				err = os.WriteFile(tmpContentFile.Name(), input, 0755)
				if err != nil {
					t.Fatal(err)
				}

				// write the public key to a temp file
				tmpPublicKeyFile, err := os.CreateTemp("", fmt.Sprintf("gpg2_TestSignPGPAndVerifyWithGnuPG_publickey_%s_", s.ID))
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(tmpPublicKeyFile.Name())
				// fmt.Printf("loading %s\n", s.PublicKey)
				err = os.WriteFile(tmpPublicKeyFile.Name(), []byte(s.PublicKey), 0755)
				if err != nil {
					t.Fatal(err)
				}

				tmpKeyringDir, err := os.MkdirTemp("", "keyring")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(tmpKeyringDir)

				tmpKeyring := filepath.Join(tmpKeyringDir, "keyring.gpg")

				// call gnupg to create a new keyring, load the key in it
				gnupgCreateKeyring := exec.Command("gpg", "--no-default-keyring",
					"--keyring", tmpKeyring,
					"--import", tmpPublicKeyFile.Name())
				out, err := gnupgCreateKeyring.CombinedOutput()
				if err != nil {
					t.Fatalf("failed to load public key into keyring: %s\n%s", err, out)
				}

				// verify the signature
				gnupgVerifySig := exec.Command("gpg", "--no-default-keyring",
					"--keyring", tmpKeyring,
					"--verify", tmpSignatureFile.Name(), tmpContentFile.Name())
				out, err = gnupgVerifySig.CombinedOutput()
				if err != nil {
					t.Fatalf("error verifying sig: %s\n%s", err, out)
				}
				t.Logf("GnuPG PGP signature verification output:\n%s\n", out)
			})
		})
	}
}

func TestGPG2Signer_SignFiles(t *testing.T) {
	type fields struct {
		Configuration signer.Configuration
	}
	type args struct {
		inputs  []signer.NamedUnsignedFile
		options interface{}
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantErr       bool
		wantErrStr    string
		wantErrPrefix string
	}{
		{
			name: fmt.Sprintf("signer %s in mode %s errors", randompgpGPG2SignerConf.ID, randompgpGPG2SignerConf.Mode),
			fields: fields{
				Configuration: randompgpGPG2SignerConf,
			},
			wantErr:    true,
			wantErrStr: "gpg2: can only sign multiple files in debsign or rpmsign mode",
		},
		{
			name: "debsign errors for invalid file extensions",
			fields: fields{
				Configuration: pgpsubkeyDebsignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "foo.changes",
						Bytes: []byte(""),
					},
					{
						Name:  "bar.exe",
						Bytes: []byte(""),
					},
				},
				options: nil,
			},
			wantErr:    true,
			wantErrStr: "gpg2: cannot sign file 1. File missing extension .buildinfo, .dsc, or .changes",
		},
		{
			name: "rpmsign errors for invalid file extensions",
			fields: fields{
				Configuration: pgpsubkeyRPMSignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "foo.rpm",
						Bytes: []byte(""),
					},
					{
						Name:  "bar.exe",
						Bytes: []byte(""),
					},
				},
				options: nil,
			},
			wantErr:    true,
			wantErrStr: "gpg2: cannot sign file 1. File missing extension .rpm",
		},
		{
			name: "rpmsign errors for .dsc file",
			fields: fields{
				Configuration: pgpsubkeyRPMSignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "foo.dsc",
						Bytes: []byte(""),
					},
				},
				options: nil,
			},
			wantErr:    true,
			wantErrStr: "gpg2: cannot sign file 0. File missing extension .rpm",
		},
		{
			name: "errors for unsupported .commands file",
			fields: fields{
				Configuration: pgpsubkeyDebsignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "foo.commands",
						Bytes: []byte("invalid"),
					},
				},
				options: nil,
			},
			wantErr:    true,
			wantErrStr: "gpg2: cannot sign file 0. Files missing extension .buildinfo, .dsc, or .changes",
		},
		{
			name: "errors for debsign error on invalid .changes file",
			fields: fields{
				Configuration: pgpsubkeyDebsignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "foo_bar_amd64.changes",
						Bytes: []byte("Files:\ndb1177999615f0aaeed19bf8fc850fc9 3754 python optional sphinx_1.7.2-1.dsc"),
					},
				},
				options: nil,
			},
			wantErr:       true,
			wantErrPrefix: "gpg2: failed to debsign inputs: exit status 1\ndebsign: Can't find or can't read dsc file",
		},
		{
			name: "debsign empty files ok",
			fields: fields{
				Configuration: pgpsubkeyDebsignSignerConf,
			},
			args: args{
				inputs:  []signer.NamedUnsignedFile{},
				options: nil,
			},
			wantErr: false,
		},
		{
			name: "rpmsign empty files ok",
			fields: fields{
				Configuration: pgpsubkeyRPMSignSignerConf,
			},
			args: args{
				inputs:  []signer.NamedUnsignedFile{},
				options: nil,
			},
			wantErr: false,
		},
		{
			name: "rpmsign errors on invalid rpm file",
			fields: fields{
				Configuration: pgpsubkeyRPMSignSignerConf,
			},
			args: args{
				inputs: []signer.NamedUnsignedFile{
					{
						Name:  "invalid.rpm",
						Bytes: []byte("not a valid rpm file"),
					},
				},
				options: nil,
			},
			wantErr:       true,
			wantErrPrefix: "gpg2: failed to rpmsign inputs",
		},
		{
			name: fmt.Sprintf("signer %s in mode %s ok", randompgpDebsignSignerConf.ID, randompgpDebsignSignerConf.Mode),
			fields: fields{
				Configuration: randompgpDebsignSignerConf,
			},
			args: args{
				inputs:  sphinxDebsignInputs,
				options: nil,
			},
			wantErr: false,
		},
		{
			name: fmt.Sprintf("signer %s in mode %s ok", pgpsubkeyDebsignSignerConf.ID, pgpsubkeyDebsignSignerConf.Mode),
			fields: fields{
				Configuration: pgpsubkeyDebsignSignerConf,
			},
			args: args{
				inputs:  sphinxDebsignInputs,
				options: nil,
			},
			wantErr: false,
		},
		{
			name: fmt.Sprintf("signer %s in mode %s ok", randompgpRPMSignSignerConf.ID, randompgpRPMSignSignerConf.Mode),
			fields: fields{
				Configuration: randompgpRPMSignSignerConf,
			},
			args: args{
				inputs:  testpkgRPMSignInputs,
				options: nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// initialize a signer
			s := assertNewSignerWithConfOK(t, tt.fields.Configuration)

			gotSignedFiles, err := s.SignFiles(tt.args.inputs, tt.args.options)

			// t.Logf("SignFiles err:\n%q", err)
			if tt.wantErr {
				if err == nil {
					t.Errorf("GPG2Signer.SignFiles() error = %v, wantErr %v", err, tt.wantErr)
				} else if !(err.Error() == tt.wantErrStr || strings.HasPrefix(err.Error(), tt.wantErrPrefix)) {
					t.Errorf("GPG2Signer.SignFiles() error.Error() = %q, wantErrStr %q or prefix %q", err.Error(), tt.wantErrStr, tt.wantErrPrefix)
				}
				return
			}
			if len(gotSignedFiles) != len(tt.args.inputs) {
				t.Errorf("GPG2Signer.SignFiles() returned %d signed files != %d input files", len(gotSignedFiles), len(tt.args.inputs))
			}
			for i, signedFile := range gotSignedFiles {
				// t.Logf("%s:\n%s", signedFile.Name, signedFile.Bytes)
				if signedFile.Name != tt.args.inputs[i].Name {
					t.Errorf("GPG2Signer.SignFiles() file %d: signed file name %q != input file name %q", i, signedFile.Name, tt.args.inputs[i].Name)
				}
			}

			switch s.Mode {
			case ModeDebsign:
				assertClearSignedFilesVerify(t, s, "verify-debsigned-files", gotSignedFiles)
			case ModeRPMSign:
				assertRPMSignedFilesVerify(t, s, "verify-rpmsigned-files", gotSignedFiles)
			}
			matches, err := filepath.Glob(filepath.Join(s.tmpDir, "sign_files*", "*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 0 {
				t.Fatalf("sign files did not clean up its temp input directories: %s", matches)
			}
		})
	}
}

// signer configs from the dev autograph.yaml

//go:embed "test/fixtures/randompgp.key"
var randompgpPrivateKey string

//go:embed "test/fixtures/randompgp.pub"
var randompgpPublicKey string

var randompgpGPG2SignerConf = signer.Configuration{
	ID:         "gpg2test-randompgp",
	Type:       Type,
	Mode:       ModeGPG2,
	KeyID:      "0xDD0A5D99AAAB1F1A",
	Passphrase: "abcdef123",
	PrivateKey: randompgpPrivateKey,
	PublicKey:  randompgpPublicKey,
}

var randompgpDebsignSignerConf = signer.Configuration{
	ID:         "gpg2test-randompgp-debsign",
	Type:       Type,
	Mode:       ModeDebsign,
	KeyID:      "A2910E4FBEA076009BCDE536DD0A5D99AAAB1F1A",
	Passphrase: "abcdef123",
	PrivateKey: randompgpPrivateKey,
	PublicKey:  randompgpPublicKey,
}

var randompgpRPMSignSignerConf = signer.Configuration{
	ID:         "gpg2test-randompgp-rpmsign",
	Type:       Type,
	Mode:       ModeRPMSign,
	KeyID:      "A2910E4FBEA076009BCDE536DD0A5D99AAAB1F1A",
	Passphrase: "abcdef123",
	PrivateKey: randompgpPrivateKey,
	PublicKey:  randompgpPublicKey,
}

//go:embed "test/fixtures/pgpsubkey.key"
var pgpsubkeyPrivateKey string

//go:embed "test/fixtures/pgpsubkey.pub"
var pgpsubkeyPublicKey string

// debsign test files from https://github.com/Debian/devscripts/tree/37b5cc1e5e47cf5ff472ef1f8847de547731df44/test/debsign

//go:embed "test/fixtures/sphinx_1.7.2-1.dsc"
var sphinxDsc []byte

//go:embed "test/fixtures/sphinx_1.7.2-1_amd64.buildinfo"
var sphinxBuildinfo []byte

//go:embed "test/fixtures/sphinx_1.7.2-1_amd64.changes"
var sphinxChanges []byte

var sphinxDebsignInputs = []signer.NamedUnsignedFile{
	{
		Name:  "sphinx_1.7.2-1.dsc",
		Bytes: sphinxDsc,
	},
	{
		Name:  "sphinx_1.7.2-1_amd64.buildinfo",
		Bytes: sphinxBuildinfo,
	},
	{
		Name:  "sphinx_1.7.2-1_amd64.changes",
		Bytes: sphinxChanges,
	},
}

//go:embed "test/fixtures/testpkg-1.0-1.x86_64.rpm"
var testpkgRPM []byte

var testpkgRPMSignInputs = []signer.NamedUnsignedFile{
	{
		Name:  "testpkg-1.0-1.x86_64.rpm",
		Bytes: testpkgRPM,
	},
}

var pgpsubkeyGPG2SignerConf = signer.Configuration{
	ID:         "gpg2test",
	Type:       Type,
	Mode:       ModeGPG2,
	KeyID:      "0xE09F6B4F9E6FDCCB",
	Passphrase: "abcdef123",
	PrivateKey: pgpsubkeyPrivateKey,
	PublicKey:  pgpsubkeyPublicKey,
}

var pgpsubkeyDebsignSignerConf = signer.Configuration{
	ID:         "pgpsubkey-debsign",
	Type:       Type,
	Mode:       ModeDebsign,
	KeyID:      "1D02D42C7C2086373E2B7D8ED01EF1FA33C6BAEB",
	Passphrase: "abcdef123",
	PrivateKey: pgpsubkeyPrivateKey,
	PublicKey:  pgpsubkeyPublicKey,
}

var pgpsubkeyRPMSignSignerConf = signer.Configuration{
	ID:         "pgpsubkey-rpmsign",
	Type:       Type,
	Mode:       ModeRPMSign,
	KeyID:      "1D02D42C7C2086373E2B7D8ED01EF1FA33C6BAEB",
	Passphrase: "abcdef123",
	PrivateKey: pgpsubkeyPrivateKey,
	PublicKey:  pgpsubkeyPublicKey,
}

var validSignerConfigs = []signer.Configuration{
	randompgpGPG2SignerConf,
	randompgpDebsignSignerConf,
	randompgpRPMSignSignerConf,
	pgpsubkeyGPG2SignerConf,
	pgpsubkeyDebsignSignerConf,
	pgpsubkeyRPMSignSignerConf,
}

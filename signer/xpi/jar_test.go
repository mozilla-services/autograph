package xpi

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"io/ioutil"
	"testing"
)

func TestFormatFilenameShort(t *testing.T) {
	t.Parallel()

	fn := []byte("LocalizedFormats_fr.properties")
	expected := []byte("LocalizedFormats_fr.properties")

	formatted, err := formatFilename(fn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(formatted, expected) {
		t.Fatalf("manifest filename mismatch Expected:\n%q\nGot:\n%q", expected, formatted)
	}
}

func TestFormatFilenameLong(t *testing.T) {
	t.Parallel()

	fn := []byte("assets/org/apache/commons/math3/exception/util/LocalizedFormats_fr.properties")
	expected := []byte("assets/org/apache/commons/math3/exception/util/LocalizedFormats_f\n r.properties")

	formatted, err := formatFilename(fn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(formatted, expected) {
		t.Fatalf("manifest filename mismatch Expected:\n%q\nGot:\n%q", expected, formatted)
	}
}

func TestFormatFilenameInvalidUTF8(t *testing.T) {
	t.Parallel()

	_, err := formatFilename([]byte{0xff, 0xfe, 0xfd})
	if err == nil {
		t.Fatal("format filename did not error for invalid UTF8")
	}
}

func TestFormatFilenameWithControlCharacter(t *testing.T) {
	t.Parallel()

	// Both are the same, really, but `expected` is slightly more readable.
	fn := []byte("some/file\x0d")
	expected := []byte("some/file\r")

	formatted, err := formatFilename(fn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(formatted, expected) {
		t.Fatalf("manifest filename mismatch Expected:\n%q\nGot:\n%q", expected, formatted)
	}
}

func TestFormatFilenameTooLong(t *testing.T) {
	t.Parallel()

	_, err := formatFilename(make([]byte, maxHeaderBytes+1))
	if err == nil {
		t.Fatal("format filename did not error for excessively long line")
	}
}

func TestFormatFilenameLonger(t *testing.T) {
	t.Parallel()

	fn := []byte("assets/org/apache/commons/math3/exception/assets/org/apache/commons/math3/exception/util/assets/org/apache/commons/math3/exception/util/LocalizedFormats_fr.properties")
	expected := []byte("assets/org/apache/commons/math3/exception/assets/org/apache/commo\n ns/math3/exception/util/assets/org/apache/commons/math3/exception/util\n /LocalizedFormats_fr.properties")

	formatted, err := formatFilename(fn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(formatted, expected) {
		t.Fatalf("manifest filename mismatch Expected:\n%q\nGot:\n%q", expected, formatted)
	}
}

func TestFormatFilenameExact(t *testing.T) {
	t.Parallel()

	fn := []byte("assets/org/apache/commons/math3/exception/assets/org/apache/commons/math3/exception/util/assets/org/apache/commons/math3/exception/util")
	expected := []byte("assets/org/apache/commons/math3/exception/assets/org/apache/commo\n ns/math3/exception/util/assets/org/apache/commons/math3/exception/util")

	formatted, err := formatFilename(fn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(formatted, expected) {
		t.Fatalf("manifest filename mismatch Expected:\n%+v\nGot:\n%+v", expected, formatted)
	}
}

func TestMakingJarManifest(t *testing.T) {
	t.Parallel()

	// should not include user-provided COSE signature files in manifest
	manifest, err := makeJARManifest(unsignedEmptyCOSE)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unsignedEmptyCOSEManifest, manifest) {
		t.Fatalf("manifest mismatch. Expect:\n%+v\nGot:\n%+v", unsignedEmptyCOSEManifest, manifest)
	}

	manifest, sigfile, err := makeJARManifestAndSignatureFile(unsignedBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, unsignedBootstrapManifest) {
		t.Fatalf("manifest mismatch. Expect:\n%q\nGot:\n%q", unsignedBootstrapManifest, manifest)
	}
	if !bytes.Equal(sigfile, unsignedBootstrapSignatureFile) {
		t.Fatalf("signature file mismatch. Expect:\n%q\nGot:\n%q", unsignedBootstrapSignatureFile, sigfile)
	}
}

func TestRepack(t *testing.T) {
	t.Parallel()

	repackedZip, err := repackJAR(unsignedBootstrap, unsignedBootstrapManifest, unsignedBootstrapSignatureFile, unsignedBootstrapSignature)
	if err != nil {
		t.Fatal(err)
	}

	zipReader := bytes.NewReader(repackedZip)
	r, err := zip.NewReader(zipReader, int64(len(repackedZip)))
	if err != nil {
		t.Fatal(err)
	}
	var hasManifest, hasSignatureFile, hasSignature bool
	var fileCount int
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Name {
		case "test.txt", "bootstrap.js", "install.rdf":
			fileCount++
		case "META-INF/manifest.mf":
			if !bytes.Equal(data, unsignedBootstrapManifest) {
				t.Fatalf("manifest mismatch. Expect:\n%q\nGot:\n%q", unsignedBootstrapManifest, data)
			}
			hasManifest = true
		case "META-INF/mozilla.sf":
			if !bytes.Equal(data, unsignedBootstrapSignatureFile) {
				t.Fatalf("signature file mismatch. Expect:\n%q\nGot:\n%q", unsignedBootstrapSignatureFile, data)
			}
			hasSignatureFile = true
		case "META-INF/mozilla.rsa":
			if !bytes.Equal(data, unsignedBootstrapSignature) {
				t.Fatalf("signature mismatch. Expect:\n%x\nGot:\n%x", unsignedBootstrapSignature, data)
			}
			hasSignature = true
		default:
			t.Fatalf("found unknown file in zip archive: %q", f.Name)
		}
	}
	if fileCount != 3 {
		t.Fatalf("found %d data files in zip archive, expected 3", fileCount)
	}
	if !hasManifest {
		t.Fatal("manifest file not found in zip archive")
	}
	if !hasSignatureFile {
		t.Fatal("signature file not found in zip archive")
	}
	if !hasSignature {
		t.Fatal("signature not found in zip archive")
	}
}

func TestRepackEmptyCOSE(t *testing.T) {
	t.Parallel()

	repackedZip, err := repackJARWithMetafiles(unsignedEmptyCOSE, []Metafile{
		{coseManifestPath, unsignedEmptyCOSEManifest},
		{coseSigPath, unsignedEmptyCOSESig},
	})
	if err != nil {
		t.Fatal(err)
	}

	zipReader := bytes.NewReader(repackedZip)
	r, err := zip.NewReader(zipReader, int64(len(repackedZip)))
	if err != nil {
		t.Fatal(err)
	}
	var hasManifest, hasSignature bool
	var fileCount int
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}

		switch f.Name {
		case "META-INF/cose.manifest":
			if !bytes.Equal(data, unsignedEmptyCOSEManifest) {
				t.Fatalf("manifest mismatch. Expect:\n%q\nGot:\n%q", unsignedEmptyCOSEManifest, data)
			}
			hasManifest = true
		case "META-INF/cose.sig":
			if !bytes.Equal(data, unsignedEmptyCOSESig) {
				t.Fatalf("signature mismatch. Expect:\n%x\nGot:\n%x", unsignedEmptyCOSESig, data)
			}
			hasSignature = true
		default:
			t.Fatalf("found unknown file in zip archive: %q", f.Name)
		}
	}
	if fileCount != 0 {
		t.Fatalf("found %d data files in zip archive, expected 0", fileCount)
	}
	if !hasManifest {
		t.Fatal("manifest file not found in zip archive")
	}
	if !hasSignature {
		t.Fatal("signature not found in zip archive")
	}

}

func TestIsCOSESignatureFile(t *testing.T) {
	var testcases = []struct {
		expect   bool
		filename string
	}{
		{true, "META-INF/COSE.SIG"},
		{true, "META-INF/cose.sig"},
		{true, "META-INF/CoSe.sig"},
		{true, "META-INF/CoSe.sIg"},
		{true, "META-INF/CoSe.SIG"},
		{true, "META-INF/COSE.MANIFEST"},
		{true, "META-INF/cose.manifest"},
		{true, "META-INF/CoSe.manifest"},
		{true, "META-INF/CoSe.mAnifest"},
		{true, "META-INF/CoSe.MANIFEST"},
		{false, "META-INF/manifest.mf"},
		{false, "META-INF/mozilla.sf"},
		{false, "META-INF/mozilla.SF"},
		{false, "META-INF/SIG-foo"},
		{false, "META-INF/sig-bar"},
		{false, "META-INF/foo.bar"},
		{false, "META-INF/foo.rsa.bar"},
		{false, "META-INF/foo.RSA.bar"},
		{false, "META-INF/.mf.foo"},
		{false, "meta-inf/cose.sig"},
	}
	for i, testcase := range testcases {
		if isCOSESignatureFile(testcase.filename) != testcase.expect {
			t.Fatalf("testcase %d failed. %q returned %t, expected %t",
				i, testcase.filename, isCOSESignatureFile(testcase.filename), testcase.expect)
		}
	}
}

func TestIsSignatureFile(t *testing.T) {
	var testcases = []struct {
		expect   bool
		filename string
	}{
		{true, "META-INF/MOZILLA.RSA"},
		{true, "META-INF/mozilla.rsa"},
		{true, "META-INF/MoZiLLa.RSA"},
		{true, "META-INF/MOZILLA.DSA"},
		{true, "META-INF/mozilla.dsa"},
		{true, "META-INF/MoZiLLa.DSA"},
		{true, "META-INF/MANIFEST.MF"},
		{true, "META-INF/manifest.mf"},
		{true, "META-INF/mozilla.sf"},
		{true, "META-INF/mozilla.SF"},
		{true, "META-INF/SIG-foo"},
		{true, "META-INF/sig-bar"},
		{false, "META-INF/foo.bar"},
		{false, "META-INF/foo.rsa.bar"},
		{false, "META-INF/foo.RSA.bar"},
		{false, "META-INF/.mf.foo"},
	}
	for i, testcase := range testcases {
		if isJARSignatureFile(testcase.filename) != testcase.expect {
			t.Fatalf("testcase %d failed. %q returned %t, expected %t",
				i, testcase.filename, isJARSignatureFile(testcase.filename), testcase.expect)
		}
	}
}

func TestMetafileIsNameValid(t *testing.T) {
	var m = Metafile{
		Name: "META-INF/foo",
		Body: []byte("doesn't matter"),
	}
	if m.IsNameValid() != true {
		t.Fatalf("TestMetafileIsNameValid: path META-INF/foo did not return expected result: true")
	}
	m.Name = "../../etc/shadow"
	if m.IsNameValid() != false {
		t.Fatalf("TestMetafileIsNameValid: path ../../etc/shadow did not return expected result: false")
	}
}

func TestMakePKCS7ManifestValidatesMetafileName(t *testing.T) {
	_, err := makePKCS7Manifest([]byte(""), []Metafile{
		Metafile{
			Name: "./",
			Body: []byte("foo"),
		},
	})
	if err == nil {
		t.Fatalf("makePKCS7Manifest did not err for invalid metafile name")
	}
}

func TestRepackJARWithMetafilesValidatesMetafileName(t *testing.T) {
	_, err := repackJARWithMetafiles([]byte(""), []Metafile{
		Metafile{
			Name: "./",
			Body: []byte("foo"),
		},
	})
	if err == nil {
		t.Fatalf("repackJARWithMetafiles did not err for invalid metafile name")
	}
}

func TestExtractAddonIDAndVersionFromWebextManifest(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name            string
		addonBytes      []byte
		manifestBytes   []byte
		expectedErrStr  string
		expectedID      string
		expectedVersion string
	}{
		{
			name:           "empty manifest",
			expectedErrStr: "unexpected end of JSON input",
		},
		{
			name:           "invalid JSON",
			manifestBytes:  []byte("{"),
			expectedErrStr: "unexpected end of JSON input",
		},
		{
			name:           "only int version in JSON",
			manifestBytes:  []byte("{\"version\":42}"),
			expectedErrStr: "json: cannot unmarshal number into Go struct field .version of type string",
		},
		{
			name:            "only str version in JSON",
			manifestBytes:   []byte("{\"version\":\"42\"}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "42",
		},
		{
			name:            "only ID in JSON",
			manifestBytes:   []byte("{\"browser_specific_settings\":{\"gecko\":{\"id\":\"foo\"}}}"),
			expectedErrStr:  "",
			expectedID:      "foo",
			expectedVersion: "",
		},
		{
			name:            "empty browser_specific_settings in JSON",
			manifestBytes:   []byte("{\"browser_specific_settings\":{}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "empty browser_specific_settings.gecko in JSON",
			manifestBytes:   []byte("{\"browser_specific_settings\":{\"gecko\":{}}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "empty str for browser_specific_settings.gecko.id in JSON",
			manifestBytes:   []byte("{\"browser_specific_settings\":{\"gecko\":{\"id\":\"\"}}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "empty applications in JSON",
			manifestBytes:   []byte("{\"applications\":{}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "empty applications.gecko in JSON",
			manifestBytes:   []byte("{\"applications\":{\"gecko\":{}}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "empty str for applications.gecko.id in JSON",
			manifestBytes:   []byte("{\"applications\":{\"gecko\":{\"id\":\"\"}}}"),
			expectedErrStr:  "",
			expectedID:      "",
			expectedVersion: "",
		},
		{
			name:            "applications.gecko.id set in JSON",
			manifestBytes:   []byte("{\"applications\":{\"gecko\":{\"id\":\"addon@example.com\"}}}"),
			expectedErrStr:  "",
			expectedID:      "addon@example.com",
			expectedVersion: "",
		},
		{
			// addons-linter will reject having both set for AMO web-ext signing
			name:            "version with applications.gecko.id and browser_specific_settings.gecko.id both set in JSON prefers browser_specific_settings id",
			manifestBytes:   []byte("{\"applications\":{\"gecko\":{\"id\":\"addon@example.com\"}},\"browser_specific_settings\":{\"gecko\":{\"id\":\"{5ae54d6f-bcb2-48ec-b98c-7a19e983283f}\"}},\"version\":\"1.2.3\"}"),
			expectedErrStr:  "",
			expectedID:      "{5ae54d6f-bcb2-48ec-b98c-7a19e983283f}",
			expectedVersion: "1.2.3",
		},
		{
			name:            "ublock_origin-1.33.2-an+fx.xpi",
			addonBytes:      ublockOrigin,
			expectedID:      "uBlock0@raymondhill.net",
			expectedVersion: "1.33.2",
		},
	}
	for _, testcase := range testcases {
		testcase := testcase
		t.Run(testcase.name, func(t *testing.T) {
			t.Parallel()

			var err error
			if len(testcase.addonBytes) > 0 {
				testcase.manifestBytes, err = readFileFromZIP(testcase.addonBytes, webextManifestPath)
				if err != nil {
					t.Fatalf("error reading manifest: %q", err)
				}
			}

			id, version, err := extractAddonIDAndVersionFromWebextManifest(testcase.manifestBytes)
			if id != testcase.expectedID {
				t.Fatalf("gecko id %q did not match expected %q", id, testcase.expectedID)
			}
			if version != testcase.expectedVersion {
				t.Fatalf("version %q did not match expected %q", version, testcase.expectedVersion)
			}
			if len(testcase.expectedErrStr) > 0 {
				if err == nil {
					t.Fatalf("testcase did not fail as expected")
				}
				if err.Error() != testcase.expectedErrStr {
					t.Fatalf("testcase failed with %q not expected %q", err.Error(), testcase.expectedErrStr)
				}
			} else if err != nil {
				t.Fatalf("testcase returned unexpected err: %q", err)
			}
		})
	}
}

// a copy of toolkit/mozapps/extensions/test/xpcshell/data/signing_checks/unsigned_bootstrap_2.xpi
//
// $ unzip -l test/fixtures/unsigned_bootstrap_2.xpi
// Archive:  test/fixtures/unsigned_bootstrap_2.xpi
//
//	Length      Date    Time    Name
//
// ---------  ---------- -----   ----
//
//	1195  04-02-2015 16:11   bootstrap.js
//	 688  04-02-2015 16:10   install.rdf
//	  55  04-02-2015 16:12   test.txt
//
// ---------                     -------
//
//	1938                     3 files
//
//go:embed "test/fixtures/unsigned_bootstrap_2.xpi"
var unsignedBootstrap []byte

var unsignedBootstrapManifest = []byte(`Manifest-Version: 1.0

Name: bootstrap.js
Digest-Algorithms: SHA1 SHA256
SHA1-Digest: RBQlzx98wYTuqEZZQKdav2H9Gag=
SHA256-Digest: m186SAMS1n5Q8hOWNE6+vGOXxfxH45sAzDlji1E3qaI=

Name: install.rdf
Digest-Algorithms: SHA1 SHA256
SHA1-Digest: WRohqAlB/BhgUjM2RDI+pTV6ihQ=
SHA256-Digest: LHIIuDZ3MKJG7tRhByz81k3UThgCjakBe0JxGZhxF9w=

Name: test.txt
Digest-Algorithms: SHA1 SHA256
SHA1-Digest: 8mPWZnQPS9arW9Tu/vmC+JHgnYA=
SHA256-Digest: 8usFS0xIHQV5njGLlVZofDfPreYQP4+qWMMvYF5fvNw=

`)

var unsignedBootstrapSignatureFile = []byte(`Signature-Version: 1.0
SHA1-Digest-Manifest: hWJRXCpbMGcu7pD6jEH4YibF5KQ=
SHA256-Digest-Manifest: DEeZKUfwfIdRBxyA9IkCXkUaYaTn6mWnljQtELTy4cg=

`)

var unsignedBootstrapSignature = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

// a zip file containing only reserved COSE sig files
//
// $ cat META-INF/cose.manifest
// bad manifest
// $ cat META-INF/cose.sig
// invalid sig
// $ unzip -l cose-empty.zip
// Archive:  cose-empty.zip
//
//	Length      Date    Time    Name
//
// ---------  ---------- -----   ----
//
//	 0  2019-03-13 14:24   META-INF/
//	13  2019-03-13 13:58   META-INF/cose.manifest
//	12  2019-03-13 13:58   META-INF/cose.sig
//
// ---------                     -------
//
//	25                     3 files
//
//go:embed "test/fixtures/cose-empty.zip"
var unsignedEmptyCOSE []byte

var unsignedEmptyCOSEManifest = []byte("Manifest-Version: 1.0\n\n")
var unsignedEmptyCOSESig = []byte("dummy signature")

// files with PK7 and COSE signatures
//
//go:embed "test/fixtures/firefox-70.0.1/omni.ja.zip"
var fxOmnija []byte

//go:embed "test/fixtures/firefox-70.0.1/browser/omni.ja.zip"
var fxBrowserOmnija []byte

//go:embed "test/fixtures/ublock_origin-1.33.2-an+fx.xpi"
var ublockOrigin []byte

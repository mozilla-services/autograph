package apk

import (
	"archive/zip"
	"bytes"
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
		t.Fatalf("manifest filename mismatch Expected:\n%s\nGot:\n%s", expected, formatted)
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
		t.Fatalf("manifest filename mismatch Expected:\n%s\nGot:\n%s", expected, formatted)
	}
}

func TestFormatFilenameInvalidUTF8(t *testing.T) {
	t.Parallel()

	_, err := formatFilename([]byte{0xff, 0xfe, 0xfd})
	if err == nil {
		t.Fatal("format filename did not error for invalid UTF8")
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
		t.Fatalf("manifest filename mismatch Expected:\n%s\nGot:\n%s", expected, formatted)
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

	manifest, sigfile, err := makeJARManifests(smallZip)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, smallZipManifest) {
		t.Fatalf("manifest mismatch. Expect:\n%s\nGot:\n%s", smallZipManifest, manifest)
	}
	if !bytes.Equal(sigfile, smallZipSignatureFile) {
		t.Fatalf("signature file mismatch. Expect:\n%s\nGot:\n%s", smallZipSignatureFile, sigfile)
	}
}

func TestRepackAndAlign(t *testing.T) {
	t.Parallel()

	repackedZip, err := repackAndAlignJAR(smallZip, smallZipManifest, smallZipSignatureFile, smallZipSignature)
	if err != nil {
		t.Fatal(err)
	}

	zipReader := bytes.NewReader(repackedZip)
	r, err := zip.NewReader(zipReader, int64(len(repackedZip)))
	if err != nil {
		t.Fatal(err)
	}
	var hasData, hasManifest, hasSignatureFile, hasSignature bool
	for _, f := range r.File {
		rc, err := f.Open()
		defer rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Name {
		case "foo.txt":
			if !bytes.Equal(data, []byte("bar \n")) {
				t.Fatalf("data mismatch. Expect: 'bar \\n' Got:%q", data)
			}
			hasData = true
		case "META-INF/MANIFEST.MF":
			if !bytes.Equal(data, smallZipManifest) {
				t.Fatalf("manifest mismatch. Expect:\n%s\nGot:\n%s", smallZipManifest, data)
			}
			hasManifest = true
		case "META-INF/SIGNATURE.SF":
			if !bytes.Equal(data, smallZipSignatureFile) {
				t.Fatalf("signature file mismatch. Expect:\n%s\nGot:\n%s", smallZipSignatureFile, data)
			}
			hasSignatureFile = true
		case "META-INF/SIGNATURE.RSA":
			if !bytes.Equal(data, smallZipSignature) {
				t.Fatalf("signature mismatch. Expect:\n%x\nGot:\n%x", smallZipSignature, data)
			}
			hasSignature = true
		default:
			t.Fatalf("found unknow file in zip archive: %s", f.Name)
		}
	}
	if !hasData {
		t.Fatal("data file not found in zip archive")
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

func TestIsSignatureFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		expect   bool
		filename string
	}{
		{true, "META-INF/SIGNATURE.RSA"},
		{true, "META-INF/signature.rsa"},
		{true, "META-INF/SiGnAtUre.RSA"},
		{true, "META-INF/SIGNATURE.DSA"},
		{true, "META-INF/signature.dsa"},
		{true, "META-INF/SiGnAtUre.DSA"},
		{true, "META-INF/MANIFEST.MF"},
		{true, "META-INF/manifest.mf"},
		{true, "META-INF/signature.sf"},
		{true, "META-INF/signature.SF"},
		{true, "META-INF/SIG-foo"},
		{true, "META-INF/sig-bar"},
		{false, "META-INF/foo.bar"},
		{false, "META-INF/foo.rsa.bar"},
		{false, "META-INF/foo.RSA.bar"},
		{false, "META-INF/.mf.foo"},
	}
	for i, testcase := range testcases {
		if isSignatureFile(testcase.filename) != testcase.expect {
			t.Fatalf("isCompressibleFile testcase %d failed. %q returned %t, expected %t",
				i, testcase.filename, isSignatureFile(testcase.filename), testcase.expect)
		}
	}
}

// Fixtures can be added by converting APKs to string literals using hexdump, eg:
// hexdump -v -e '16/1 "_x%02X" "\n"' /tmp/fakeapk/fakeapk.zip | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/'

// a dummy zip file with a single file in it
var smallZip = []byte("\x50\x4B\x03\x04\x0A\x00\x00\x00\x00\x00\x0D\x8E\x70\x4C\xD4\x32" +
	"\x6E\x84\x05\x00\x00\x00\x05\x00\x00\x00\x07\x00\x1C\x00\x66\x6F" +
	"\x6F\x2E\x74\x78\x74\x55\x54\x09\x00\x03\xAA\x3B\xAC\x5A\xAA\x3B" +
	"\xAC\x5A\x75\x78\x0B\x00\x01\x04\xE8\x03\x00\x00\x04\xE8\x03\x00" +
	"\x00\x62\x61\x72\x20\x0A\x50\x4B\x01\x02\x1E\x03\x0A\x00\x00\x00" +
	"\x00\x00\x0D\x8E\x70\x4C\xD4\x32\x6E\x84\x05\x00\x00\x00\x05\x00" +
	"\x00\x00\x07\x00\x18\x00\x00\x00\x00\x00\x01\x00\x00\x00\xA4\x81" +
	"\x00\x00\x00\x00\x66\x6F\x6F\x2E\x74\x78\x74\x55\x54\x05\x00\x03" +
	"\xAA\x3B\xAC\x5A\x75\x78\x0B\x00\x01\x04\xE8\x03\x00\x00\x04\xE8" +
	"\x03\x00\x00\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x4D" +
	"\x00\x00\x00\x46\x00\x00\x00\x00\x00")

var smallZipManifest = []byte(`Manifest-Version: 1.0
Built-By: Generated-by-Autograph
Created-By: go.mozilla.org/autograph

Name: foo.txt
SHA-256-Digest: aE/i11OBml60LVIdT0GjCqhQdvwtRRY+sL8ySX8+1EY=

`)

var smallZipSignatureFile = []byte(`Signature-Version: 1.0
Created-By: 1.0.0 autograph-client (go.mozilla.org/autograph)
SHA-256-Digest-Manifest: LpKUd4ScoPSLipDW2FHd6XJqnxx3pgCBEXygZPGQFCw=

Name: foo.txt
SHA-256-Digest: aE/i11OBml60LVIdT0GjCqhQdvwtRRY+sL8ySX8+1EY=

`)

var smallZipSignature = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

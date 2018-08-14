package xpi

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

func TestMakingJarManifest(t *testing.T) {
	manifest, sigfile, err := makeJARManifestAndSignatureFile(unsignedBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest, unsignedBootstrapManifest) {
		t.Fatalf("manifest mismatch. Expect:\n%s\nGot:\n%s", unsignedBootstrapManifest, manifest)
	}
	if !bytes.Equal(sigfile, unsignedBootstrapSignatureFile) {
		t.Fatalf("signature file mismatch. Expect:\n%s\nGot:\n%s", unsignedBootstrapSignatureFile, sigfile)
	}
}

func TestRepack(t *testing.T) {
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
		defer rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		switch f.Name {
		case "test.txt", "bootstrap.js", "install.rdf":
			fileCount++
		case "META-INF/manifest.mf":
			if !bytes.Equal(data, unsignedBootstrapManifest) {
				t.Fatalf("manifest mismatch. Expect:\n%s\nGot:\n%s", unsignedBootstrapManifest, data)
			}
			hasManifest = true
		case "META-INF/mozilla.sf":
			if !bytes.Equal(data, unsignedBootstrapSignatureFile) {
				t.Fatalf("signature file mismatch. Expect:\n%s\nGot:\n%s", unsignedBootstrapSignatureFile, data)
			}
			hasSignatureFile = true
		case "META-INF/mozilla.rsa":
			if !bytes.Equal(data, unsignedBootstrapSignature) {
				t.Fatalf("signature mismatch. Expect:\n%x\nGot:\n%x", unsignedBootstrapSignature, data)
			}
			hasSignature = true
		default:
			t.Fatalf("found unknown file in zip archive: %s", f.Name)
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

// Fixtures can be added by converting APKs to string literals using hexdump, eg:
// hexdump -v -e '16/1 "_x%02X" "\n"' /tmp/fakeapk/fakeapk.zip | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/'

// a copy of toolkit/mozapps/extensions/test/xpcshell/data/signing_checks/unsigned_bootstrap_2.xpi
var unsignedBootstrap = []byte("\x50\x4B\x03\x04\x14\x00\x02\x00\x08\x00\x62\x69\x82\x46\x7F\x0B" +
	"\x45\xED\x2C\x01\x00\x00\xAB\x04\x00\x00\x0C\x00\x1C\x00\x62\x6F" +
	"\x6F\x74\x73\x74\x72\x61\x70\x2E\x6A\x73\x55\x54\x09\x00\x03\x57" +
	"\xA2\x1D\x55\x73\xA2\x1D\x55\x75\x78\x0B\x00\x01\x04\xF6\x01\x00" +
	"\x00\x04\x14\x00\x00\x00\xB5\x93\x4F\x4B\xC3\x40\x10\xC5\xEF\xF9" +
	"\x14\x43\x4E\xAD\x94\x8D\x78\xB4\x78\x12\x0F\xBD\xA8\x58\xE9\x35" +
	"\x6C\x93\x69\x13\xD9\xEC\x84\x9D\xD9\x06\x11\xBF\xBB\x13\x9A\xB6" +
	"\x20\xA2\xF4\x8F\xB7\xDD\xC7\xCC\x6F\xDF\x7B\xB0\xF7\xD4\xB4\xE4" +
	"\xD1\x0B\x9B\x28\xB5\x63\x53\xEB\x3D\xC8\x28\x0D\xC8\x14\x43\x81" +
	"\xB7\x59\xB6\x0E\x98\x35\x54\x46\x87\x9C\xCD\x31\x6C\xEA\x02\xD9" +
	"\xBC\x71\x93\x8E\xA7\x49\x52\x90\x67\x81\xC5\xC3\xCB\x7C\xF6\xF4" +
	"\x08\x77\x70\xA3\x5A\x96\xC1\x2B\xAA\xCA\x82\x2D\x43\x51\xD9\xDA" +
	"\xC3\x2A\x50\x03\x6D\xC0\x15\xD0\x92\x15\x82\x81\x81\x3C\x5C\xE5" +
	"\x01\x2D\x93\x9F\xF4\x4B\x4C\x60\x5D\x67\xDF\x19\x18\x05\xA4\xB2" +
	"\x02\xCE\xB2\x24\xAB\xE8\x0B\xA9\x75\xBA\xD6\xB7\xAC\x73\xA3\xD2" +
	"\x8A\x9D\xC0\x76\x73\x0C\x1F\x09\xC0\xDE\x57\xFF\x04\x1B\xDD\x9F" +
	"\x79\x79\xD6\xF3\x28\x5D\x12\x09\x4B\xB0\xAD\xA8\x27\x33\x20\xB0" +
	"\xCC\x7B\x0B\x0A\x4D\x27\x3B\xF7\x1A\xE7\x78\x50\x4E\xAE\x3C\x90" +
	"\x7A\x63\x46\x95\xC5\x56\x39\x8D\xB8\xCD\x95\xEE\x03\x4E\x93\xCF" +
	"\xE4\xD0\x81\xCE\x04\x89\xED\x39\x1D\x58\x25\x6D\xF0\xDC\x02\x06" +
	"\x23\x17\x2C\x60\x47\xFC\xA3\x80\x2A\x4A\x49\x9D\xBF\x68\x03\xD7" +
	"\x47\x3A\x1D\x3C\xE4\x1E\xBB\x6F\xE1\x55\x39\x2D\xFC\x0E\xF9\x7B" +
	"\xFA\xE8\xFF\xE9\x13\x1C\xD9\xC0\xDE\xC7\x05\x2B\x38\x30\x7F\xEA" +
	"\xE0\x0B\x50\x4B\x03\x04\x14\x00\x02\x00\x08\x00\x5D\x69\x82\x46" +
	"\xF2\xFB\xF8\x2C\x4D\x01\x00\x00\xB0\x02\x00\x00\x0B\x00\x1C\x00" +
	"\x69\x6E\x73\x74\x61\x6C\x6C\x2E\x72\x64\x66\x55\x54\x09\x00\x03" +
	"\x52\xA2\x1D\x55\x73\xA2\x1D\x55\x75\x78\x0B\x00\x01\x04\xF6\x01" +
	"\x00\x00\x04\x14\x00\x00\x00\x85\x92\xCB\x6E\xC2\x30\x10\x45\xF7" +
	"\xF9\x0A\x37\xAC\x1D\x87\x14\x55\x22\x0A\xA1\x48\x94\x55\xBB\x41" +
	"\x6D\xF7\x26\x31\x60\xC9\x8F\xC8\x9E\x34\x69\xBF\xBE\x8E\xF3\x00" +
	"\x44\xA5\x7A\x61\x29\x77\xCE\x9D\x19\x5F\x25\x5B\xB7\x52\xA0\x2F" +
	"\x66\x2C\xD7\x6A\x15\xCE\xA3\x38\x5C\xE7\x41\x90\xED\xB7\x3B\xE4" +
	"\x2A\xCA\xAE\xC2\x33\x40\x95\x12\xD2\x34\x4D\xD4\x3C\x46\xDA\x9C" +
	"\xC8\x7C\xB9\x5C\x92\x38\x21\x49\x82\x4D\x79\xC4\xF6\x5B\x01\x6D" +
	"\xB1\xB2\xB3\x30\x40\xDD\xF1\xC6\x94\xC9\x1B\xAF\xD4\x3F\x5C\x08" +
	"\xEA\x1B\x24\x71\xBC\x20\x4C\x76\xEE\x59\xE8\xC6\x21\x94\x6D\x99" +
	"\x2D\x0C\xAF\xC0\xAD\x81\xE8\x41\xD7\xB0\x0A\x6B\xA3\xD2\xC1\x95" +
	"\x72\x65\x81\x0A\x81\x25\x55\xFC\xC8\x2C\x38\x57\x37\x29\x63\x32" +
	"\xE5\x65\x0E\x4E\x79\xEE\x2E\x7B\x3D\x26\x23\x7D\x75\x22\x87\x67" +
	"\xE6\x49\x14\xFB\xDA\xF8\x3D\x01\x07\xAD\xC1\x82\xA1\x55\x0E\xA6" +
	"\x66\x9E\xB9\x48\x41\x8F\x3D\x60\x8C\x76\x46\x2B\x40\x2F\xAA\x44" +
	"\x6F\x0C\xE8\x96\x02\x45\x18\x5F\xDA\x28\x2A\x59\xFE\xEE\xD6\x41" +
	"\x9B\xB2\xC4\x5A\xF9\x46\x5E\x9C\x90\xBA\x2A\x29\xB0\x8F\xFD\x6B" +
	"\x3E\x44\x24\x74\x41\xC5\x59\x5B\x48\x17\xEE\x90\xBE\x1E\xB9\x80" +
	"\xBC\xF9\x82\x07\x53\x0B\xA0\xE6\xC4\x60\x53\x55\x82\x17\x14\xA6" +
	"\x77\xDC\x66\x39\x6A\x53\x54\x6D\x55\xD8\x33\x13\xE2\x9F\xB8\x46" +
	"\x87\xE4\xEA\x73\x48\x69\xE1\x81\x2B\xE1\x16\xA4\xED\xA8\x3F\xF5" +
	"\xE0\x45\x18\xF7\x22\x77\x8B\x79\xF2\x8F\x87\x04\x77\x74\x46\xDC" +
	"\x2F\x99\x07\xBF\x50\x4B\x03\x04\x0A\x00\x02\x00\x00\x00\x86\x69" +
	"\x82\x46\x7D\xB5\xAF\x6B\x37\x00\x00\x00\x37\x00\x00\x00\x08\x00" +
	"\x1C\x00\x74\x65\x73\x74\x2E\x74\x78\x74\x55\x54\x09\x00\x03\x9B" +
	"\xA2\x1D\x55\x9B\xA2\x1D\x55\x75\x78\x0B\x00\x01\x04\xF6\x01\x00" +
	"\x00\x04\x14\x00\x00\x00\x54\x68\x69\x73\x20\x74\x65\x73\x74\x20" +
	"\x66\x69\x6C\x65\x20\x63\x61\x6E\x20\x62\x65\x20\x61\x6C\x74\x65" +
	"\x72\x65\x64\x20\x74\x6F\x20\x62\x72\x65\x61\x6B\x20\x73\x69\x67" +
	"\x6E\x69\x6E\x67\x20\x63\x68\x65\x63\x6B\x73\x2E\x0A\x50\x4B\x01" +
	"\x02\x1E\x03\x14\x00\x02\x00\x08\x00\x62\x69\x82\x46\x7F\x0B\x45" +
	"\xED\x2C\x01\x00\x00\xAB\x04\x00\x00\x0C\x00\x18\x00\x00\x00\x00" +
	"\x00\x01\x00\x00\x00\xA4\x81\x00\x00\x00\x00\x62\x6F\x6F\x74\x73" +
	"\x74\x72\x61\x70\x2E\x6A\x73\x55\x54\x05\x00\x03\x57\xA2\x1D\x55" +
	"\x75\x78\x0B\x00\x01\x04\xF6\x01\x00\x00\x04\x14\x00\x00\x00\x50" +
	"\x4B\x01\x02\x1E\x03\x14\x00\x02\x00\x08\x00\x5D\x69\x82\x46\xF2" +
	"\xFB\xF8\x2C\x4D\x01\x00\x00\xB0\x02\x00\x00\x0B\x00\x18\x00\x00" +
	"\x00\x00\x00\x01\x00\x00\x00\xA4\x81\x72\x01\x00\x00\x69\x6E\x73" +
	"\x74\x61\x6C\x6C\x2E\x72\x64\x66\x55\x54\x05\x00\x03\x52\xA2\x1D" +
	"\x55\x75\x78\x0B\x00\x01\x04\xF6\x01\x00\x00\x04\x14\x00\x00\x00" +
	"\x50\x4B\x01\x02\x1E\x03\x0A\x00\x02\x00\x00\x00\x86\x69\x82\x46" +
	"\x7D\xB5\xAF\x6B\x37\x00\x00\x00\x37\x00\x00\x00\x08\x00\x18\x00" +
	"\x00\x00\x00\x00\x01\x00\x00\x00\xA4\x81\x04\x03\x00\x00\x74\x65" +
	"\x73\x74\x2E\x74\x78\x74\x55\x54\x05\x00\x03\x9B\xA2\x1D\x55\x75" +
	"\x78\x0B\x00\x01\x04\xF6\x01\x00\x00\x04\x14\x00\x00\x00\x50\x4B" +
	"\x05\x06\x00\x00\x00\x00\x03\x00\x03\x00\xF1\x00\x00\x00\x7D\x03" +
	"\x00\x00\x00\x00")

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


func getZIPReader(zipBytes []byte) *zip.Reader {
	reader := bytes.NewReader(zipBytes)
	r, err := zip.NewReader(reader, int64(len(zipBytes)))
	if err != nil {
		panic(fmt.Sprintf("Error reading ZIP %s", err))
	}
	return r
}

func TestMakeManifestsAndRepackJarMatchPythonSigningClients(t *testing.T) {
	t.Parallel()

	// NB: we're just checking JAR packing this isn't a valid signature
	pkcs7Signature, err := ioutil.ReadFile("test/zigbert.test.pkcs7.der")
	if err != nil {
		t.Fatalf("error reading test/signingClientsPKCS7DataBlob %s", err)
	}
	testJar, err := ioutil.ReadFile("test/test-jar.zip")
	if err != nil {
		t.Fatalf("error reading test/test-jar.zip %s", err)
	}
	// result of signing_clients test_make_signed
	signedJar, err := ioutil.ReadFile("test/test-jar-signed.zip")
	if err != nil {
		t.Fatalf("error reading test/test-jar-signed.zip %s", err)
	}
	manifest, sigfile, err := makeJARManifestAndSignatureFile(testJar)
	if err != nil {
		t.Fatalf("error making JAR manifests: %s", err)
	}
	repacked, err := repackJAR(testJar, manifest, sigfile, pkcs7Signature)
	if err != nil {
		t.Fatalf("error repacking jar: %s", err)
	}

	var (
		repackedReader = getZIPReader(repacked)
		signedReader = getZIPReader(signedJar)
	)
	repackedManifest, err := readFileFromZIP(repacked, "META-INF/manifest.mf")
	if err != nil {
		t.Fatalf("error reading META-INF/manifest.mf from repacked jar: %s", err)
	}
	signedManifest, err := readFileFromZIP(signedJar, "META-INF/manifest.mf")
	if err != nil {
		t.Fatalf("error reading META-INF/manifest.mf from signed jar: %s", err)
	}

	if string(repackedManifest) != string(signedManifest) {
		t.Fatalf("Manifest contents do not match!\nrepacked:\n%s\nexpected:\n%s\n", string(repackedManifest), string(signedManifest))
	}
	if len(repackedManifest) != len(signedManifest) {
		t.Fatalf("Manifest lengths do not match!\nrepacked:\n%d\nexpected:\n%d\n", len(repackedManifest), len(signedManifest))
	}

	if len(repackedReader.File) != len(signedReader.File) {
		for _, f := range signedReader.File {
			t.Logf("signed: %s\n", f.Name)
		}
		for _, f := range repackedReader.File {
			t.Logf("repacked: %s\n", f.Name)
		}
		t.Fatalf("Wrong number of entries %d in repacked and %d in expected", len(repackedReader.File), len(signedReader.File))
	}

        // verify the signed zipfiles match contents
	for i, f := range signedReader.File {
		if f.Name != repackedReader.File[i].Name {
			for _, f := range signedReader.File {
				t.Logf("signed: %s\n", f.Name)
			}
			for _, f := range repackedReader.File {
				t.Logf("repacked: %s\n", f.Name)
			}
			t.Fatalf("file %d named %s does not match expected %s", i, repackedReader.File[i].Name, f.Name)
		}
	}
}

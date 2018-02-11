package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
)

func makeJARManifests(input []byte) (manifest, sigfile []byte, err error) {
	inputReader := bytes.NewReader(input)
	r, err := zip.NewReader(inputReader, int64(len(input)))
	if err != nil {
		return
	}

	// first generate the manifest file by calculated a sha256 in each zip entry
	mw := bytes.NewBuffer(manifest)

	for _, f := range r.File {
		// reserved signature files do not get included in the manifest
		if isSignatureFile(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return manifest, sigfile, err
		}
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			return manifest, sigfile, err
		}
		h := sha256.New()
		h.Write(data)
		fmt.Fprintf(mw, "Name: %s\nSHA-256-Digest: %s\n\n",
			f.Name,
			base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}
	manifestBody := mw.Bytes()
	manifest = []byte(`Manifest-Version: 1.0
Built-By: Generated-by-Autograph
Created-By: go.mozilla.org/autograph
`)
	manifest = append(manifest, manifestBody...)

	// then calculate a signature file by hashing the manifest and adding some metadata
	sw := bytes.NewBuffer(sigfile)
	fmt.Fprint(sw, "Signature-Version: 1.0\n")
	fmt.Fprint(sw, "Created-By: 1.0.0 autograph-client (go.mozilla.org/autograph)\n")
	h := sha256.New()
	h.Write(manifest)
	fmt.Fprintf(sw, "SHA-256-Digest-Manifest: %s\n\n",
		base64.StdEncoding.EncodeToString(h.Sum(nil)))
	fmt.Fprintf(sw, "%s", manifestBody)
	sigfile = sw.Bytes()

	return
}

// repackAndAlignJAR inserts the manifest, signature file and pkcs7 signature in the input JAR file,
// and return a JAR ZIP archive aligned on 4 bytes words
func repackAndAlignJAR(input, manifest, sigfile, signature []byte) (output []byte, err error) {
	var (
		alignment = 4
		bias      = 0
		rc        io.ReadCloser
		fwhead    *zip.FileHeader
		fw        io.Writer
		data      []byte
	)
	inputReader := bytes.NewReader(input)
	r, err := zip.NewReader(inputReader, int64(len(input)))
	if err != nil {
		return
	}
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)

	// Create a new zip archive.
	w := zip.NewWriter(buf)

	// Iterate through the files in the archive,
	for _, f := range r.File {
		// skip signature files, we have new ones we'll add at the end
		if isSignatureFile(f.Name) {
			continue
		}
		rc, err = f.Open()
		if err != nil {
			return
		}
		var padlen int
		if f.CompressedSize64 != f.UncompressedSize64 {
			// File is compressed, copy the entry without padding, aka do nothing
		} else {
			// Calculate padding to be added to the extras of the entry
			// source: https://android.googlesource.com/platform/build.git/+/android-4.2.2_r1/tools/zipalign/ZipAlign.cpp#76
			newOffset := len(f.Extra) + bias
			padlen = (alignment - (newOffset % alignment)) % alignment
		}

		fwhead := &zip.FileHeader{
			Name:   f.Name,
			Method: zip.Deflate,
		}
		// add the padding (padlen number of null bytes) to the extra field of the file header
		// in order to align files on 4 bytes
		for i := 0; i < padlen; i++ {
			fwhead.Extra = append(fwhead.Extra, '\x00')
		}

		// insert the file into the archive
		fw, err = w.CreateHeader(fwhead)
		if err != nil {
			return
		}
		data, err = ioutil.ReadAll(rc)
		if err != nil {
			return
		}
		_, err = fw.Write(data)
		if err != nil {
			return
		}
		rc.Close()
		bias += padlen
	}
	// insert the signature files. Those will be compressed
	// so we don't have to worry about their alignment
	var metas = []struct {
		Name string
		Body []byte
	}{
		{"META-INF/MANIFEST.MF", manifest},
		{"META-INF/SIGNATURE.SF", sigfile},
		{"META-INF/SIGNATURE.RSA", signature},
	}
	for _, meta := range metas {
		fwhead = &zip.FileHeader{
			Name:   meta.Name,
			Method: zip.Deflate,
		}
		fw, err = w.CreateHeader(fwhead)
		if err != nil {
			return
		}
		_, err = fw.Write(meta.Body)
		if err != nil {
			return
		}
	}
	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		return
	}

	output = buf.Bytes()
	return
}

// The JAR format defines a number of signature files stored under the META-INF directory
// META-INF/MANIFEST.MF
// META-INF/*.SF
// META-INF/*.DSA
// META-INF/*.RSA
// META-INF/SIG-*
// and their lowercase variants
// https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
func isSignatureFile(name string) bool {
	if strings.HasPrefix(name, "META-INF/") {
		if name == "MANIFEST.MF" || name == "manifest.mf" ||
			strings.HasSuffix(name, ".SF") || strings.HasSuffix(name, ".sf") ||
			strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".rsa") ||
			strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".dsa") ||
			strings.HasPrefix(name, "SIG-") || strings.HasPrefix(name, "sig-") {
			return true
		}
	}
	return false
}

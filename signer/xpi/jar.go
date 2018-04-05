package xpi

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
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

	// first generate the manifest file by calculating a sha1 and sha256 hash for each zip entry
	mw := bytes.NewBuffer(manifest)
	manifest = []byte(fmt.Sprintf("Manifest-Version: 1.0\n\n"))

	for _, f := range r.File {
		if isSignatureFile(f.Name) {
			// reserved signature files do not get included in the manifest
			continue
		}
		if f.FileInfo().IsDir() {
			// directories do not get included
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
		fmt.Fprintf(mw, "Name: %s\nDigest-Algorithms: SHA1 SHA256\n", f.Name)
		h1 := sha1.New()
		h1.Write(data)
		fmt.Fprintf(mw, "SHA1-Digest: %s\n", base64.StdEncoding.EncodeToString(h1.Sum(nil)))
		h2 := sha256.New()
		h2.Write(data)
		fmt.Fprintf(mw, "SHA256-Digest: %s\n\n", base64.StdEncoding.EncodeToString(h2.Sum(nil)))
	}
	manifestBody := mw.Bytes()
	manifest = append(manifest, manifestBody...)

	// then calculate a signature file by hashing the manifest with sha1 and sha256
	sw := bytes.NewBuffer(sigfile)
	fmt.Fprint(sw, "Signature-Version: 1.0\n")
	h1 := sha1.New()
	h1.Write(manifest)
	fmt.Fprintf(sw, "SHA1-Digest-Manifest: %s\n", base64.StdEncoding.EncodeToString(h1.Sum(nil)))
	h2 := sha256.New()
	h2.Write(manifest)
	fmt.Fprintf(sw, "SHA256-Digest-Manifest: %s\n\n", base64.StdEncoding.EncodeToString(h2.Sum(nil)))
	sigfile = sw.Bytes()

	return
}

// repackJAR inserts the manifest, signature file and pkcs7 signature in the input JAR file,
// and return a JAR ZIP archive
func repackJAR(input, manifest, sigfile, signature []byte) (output []byte, err error) {
	var (
		rc     io.ReadCloser
		fwhead *zip.FileHeader
		fw     io.Writer
		data   []byte
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
		fwhead := &zip.FileHeader{
			Name:   f.Name,
			Method: zip.Deflate,
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
	}
	// insert the signature files. Those will be compressed
	// so we don't have to worry about their alignment
	var metas = []struct {
		Name string
		Body []byte
	}{
		{"META-INF/manifest.mf", manifest},
		{"META-INF/mozilla.sf", sigfile},
		{"META-INF/mozilla.rsa", signature},
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
		name = strings.TrimPrefix(name, "META-INF/")
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

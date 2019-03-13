package xpi

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"strings"
	"unicode/utf8"
)

// consts and vars for formatFilename
const (
	maxLineByteLen      = 72
	maxContinuedByteLen = 70    // -1 for leading space and -1 for trailing \n newline
	maxHeaderBytes      = 65535 // max length for wrapped / multiline headers is 2 << 15 - 1
)

var maxFirstLineByteLen = maxLineByteLen - (len([]byte("Name: ")) + 1) // + 1 for a \n newline

// formatFilename formats filename lines to satisfy:
//
// No line may be longer than 72 bytes (not characters), in its
// UTF8-encoded form. If a value would make the initial line longer
// than this, it should be continued on extra lines (each starting
// with a single SPACE).
//
// https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
// refed from: https://source.android.com/security/apksigning/#v1
func formatFilename(filename []byte) (formatted []byte, err error) {
	if !utf8.Valid(filename) {
		err = errors.Errorf("xpi: invalid UTF8 in filename %s", filename)
		return
	}
	var (
		filenameLen      = len(filename)
		writtenFileBytes = 0 // number of bytes of the filename we've written
	)
	if filenameLen > maxHeaderBytes {
		err = errors.Errorf("xpi: filename length %d exceeds the wrappable limit %d", filenameLen, maxHeaderBytes)
		return
	}
	if filenameLen <= maxFirstLineByteLen {
		formatted = filename
		return
	}
	formatted = append(formatted, filename[:maxFirstLineByteLen]...)
	writtenFileBytes += maxFirstLineByteLen
	for {
		if filenameLen-writtenFileBytes <= 0 {
			break
		} else if filenameLen-writtenFileBytes < maxContinuedByteLen {
			formatted = append(formatted, []byte("\n ")...)
			formatted = append(formatted, filename[writtenFileBytes:]...)
			break
		} else {
			formatted = append(formatted, []byte("\n ")...)
			formatted = append(formatted, filename[writtenFileBytes:writtenFileBytes+maxContinuedByteLen]...)
			writtenFileBytes += maxContinuedByteLen
		}
	}
	return
}

func makePKCS7Manifest(input []byte, metafiles []Metafile) (manifest []byte, err error) {
	for _, f := range metafiles {
		if !f.IsNameValid() {
			err = errors.Errorf("Cannot pack metafile with invalid path %s", f.Name)
			return
		}
	}

	manifest, err = makeJARManifest(input)
	if err != nil {
		return
	}

	mw := bytes.NewBuffer(manifest)
	for _, f := range metafiles {
		fmt.Fprintf(mw, "Name: %s\nDigest-Algorithms: SHA1 SHA256\n", f.Name)
		h1 := sha1.New()
		h1.Write(f.Body)
		fmt.Fprintf(mw, "SHA1-Digest: %s\n", base64.StdEncoding.EncodeToString(h1.Sum(nil)))
		h2 := sha256.New()
		h2.Write(f.Body)
		fmt.Fprintf(mw, "SHA256-Digest: %s\n\n", base64.StdEncoding.EncodeToString(h2.Sum(nil)))
	}

	return mw.Bytes(), err
}

// makeJARManifestAndSignatureFile writes hashes for all entries in a zip to a
// manifest file then hashes the manifest file to write a signature
// file and returns both
func makeJARManifestAndSignatureFile(input []byte) (manifest, sigfile []byte, err error) {
	manifest, err = makeJARManifest(input)
	if err != nil {
		return
	}

	sigfile, err = makeJARSignatureFile(manifest)
	if err != nil {
		return
	}

	return
}

// makeJARManifest calculates a sha1 and sha256 hash for each zip entry and writes them to a manifest file
func makeJARManifest(input []byte) (manifest []byte, err error) {
	inputReader := bytes.NewReader(input)
	r, err := zip.NewReader(inputReader, int64(len(input)))
	if err != nil {
		return
	}

	// generate the manifest file by calculating a sha1 and sha256 hashes for each zip entry
	mw := bytes.NewBuffer(manifest)
	manifest = []byte(fmt.Sprintf("Manifest-Version: 1.0\n\n"))

	for _, f := range r.File {
		if isJARSignatureFile(f.Name) {
			// reserved signature files do not get included in the manifest
			continue
		}
		if f.FileInfo().IsDir() {
			// directories do not get included
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return manifest, err
		}
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			return manifest, err
		}

		filename, err := formatFilename([]byte(f.Name))
		if err != nil {
			return manifest, err
		}
		h1 := sha1.New()
		h1.Write(data)
		h2 := sha256.New()
		h2.Write(data)

		fmt.Fprintf(mw, "Name: %s\nDigest-Algorithms: SHA1 SHA256\nSHA1-Digest: %s\nSHA256-Digest: %s\n\n",
			filename,
			base64.StdEncoding.EncodeToString(h1.Sum(nil)),
			base64.StdEncoding.EncodeToString(h2.Sum(nil)))
	}
	manifestBody := mw.Bytes()
	manifest = append(manifest, manifestBody...)

	return
}

// makeJARSignatureFile calculates a signature file by hashing the manifest with sha1 and sha256
func makeJARSignatureFile(manifest []byte) (sigfile []byte, err error) {
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

// Metafile is a file to pack into a JAR at .Name with contents .Body
type Metafile struct {
	Name string
	Body []byte
}

// IsNameValid checks whether a Metafile.Name is non-nil and begins
// with "META-INF/" functions taking Metafile args should validate
// names before reading or writing them to JARs
func (m *Metafile) IsNameValid() bool {
	return m != nil && strings.HasPrefix(m.Name, "META-INF/")
}

// repackJARWithMetafiles inserts metafiles in the input JAR file and returns a JAR ZIP archive
func repackJARWithMetafiles(input []byte, metafiles []Metafile) (output []byte, err error) {
	for _, f := range metafiles {
		if !f.IsNameValid() {
			err = errors.Errorf("Cannot pack metafile with invalid path %s", f.Name)
			return
		}
	}
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
		if isJARSignatureFile(f.Name) {
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
	for _, meta := range metafiles {
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

// repackJAR inserts the manifest, signature file and pkcs7 signature in the input JAR file,
// and return a JAR ZIP archive
func repackJAR(input, manifest, sigfile, signature []byte) (output []byte, err error) {
	var metas = []Metafile{
		{pkcs7ManifestPath, manifest},
		{pkcs7SignatureFilePath, sigfile},
		{pkcs7SigPath, signature},
	}
	return repackJARWithMetafiles(input, metas)
}

// The JAR format defines a number of signature files stored under the META-INF directory
// META-INF/MANIFEST.MF
// META-INF/*.SF
// META-INF/*.DSA
// META-INF/*.RSA
// META-INF/SIG-*
// and their lowercase variants
// https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File
func isJARSignatureFile(name string) bool {
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

// The XPI format reserves a couple number signature files stored under the META-INF directory
// META-INF/COSE.SIG
// META-INF/COSE.MANIFEST
// and their lower and mixed case variants
func isCOSESignatureFile(name string) bool {
	if strings.HasPrefix(name, "META-INF/") {
		name = strings.ToLower(strings.TrimPrefix(name, "META-INF/"))
		if name == "cose.manifest" || name == "cose.sig" {
			return true
		}
	}
	return false
}

// readFileFromZIP reads a given filename out of a ZIP and returns it or an error
func readFileFromZIP(signedXPI []byte, filename string) ([]byte, error) {
	zipReader := bytes.NewReader(signedXPI)
	r, err := zip.NewReader(zipReader, int64(len(signedXPI)))
	if err != nil {
		return nil, errors.Wrap(err, "Error reading ZIP")
	}

	for _, f := range r.File {
		if f.Name == filename {
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				return nil, errors.Wrapf(err, "Error opening file %s in ZIP", filename)
			}
			data, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, errors.Wrapf(err, "Error reading file %s in ZIP", filename)
			}
			return data, nil
		}
	}
	return nil, errors.Errorf("failed to find %s in ZIP", filename)
}

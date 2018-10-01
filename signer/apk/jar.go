package apk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"io"
	"io/ioutil"
	"strings"
	"unicode/utf8"
	"github.com/pkg/errors"
)

// consts and vars for formatFilename
const (
	maxLineByteLen = 72
	maxContinuedByteLen = 70 // -1 for leading space and -1 for trailing \n newline
)
var maxFirstLineByteLen = maxLineByteLen - (len([]byte("Name: ")) + 1)  // + 1 for a \n newline

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
		err = errors.Errorf("apk: invalid UTF8 in filename %s", filename)
		return
	}
	var (
		filenameLen = len(filename)
		writtenFileBytes = 0 // number of bytes of the filename we've written
	)
	if filenameLen <= maxFirstLineByteLen {
		formatted = filename
		return
	}
	formatted = append(formatted, filename[:maxFirstLineByteLen]...)
	writtenFileBytes += maxFirstLineByteLen
	for {
		if filenameLen - writtenFileBytes <= 0 {
			break
		} else if filenameLen - writtenFileBytes < maxContinuedByteLen {
			formatted = append(formatted, []byte("\n ")...)
			formatted = append(formatted, filename[writtenFileBytes:]...)
			break
		} else {
			formatted = append(formatted, []byte("\n ")...)
			formatted = append(formatted, filename[writtenFileBytes:writtenFileBytes + maxContinuedByteLen]...)
			writtenFileBytes += maxContinuedByteLen
		}
	}
	return
}

func makeJARManifests(input []byte) (manifest, sigfile []byte, err error) {
	inputReader := bytes.NewReader(input)
	r, err := zip.NewReader(inputReader, int64(len(input)))
	if err != nil {
		return
	}

	// first generate the manifest file by calculated a sha256 in each zip entry
	mw := bytes.NewBuffer(manifest)

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
		h := sha256.New()
		h.Write(data)

		filename, err := formatFilename([]byte(f.Name))
		if err != nil {
			return manifest, sigfile, err
		}
		fmt.Fprintf(mw, "Name: %s\nSHA-256-Digest: %s\n\n",
			filename,
			base64.StdEncoding.EncodeToString(h.Sum(nil)))
	}
	manifestBody := mw.Bytes()
	manifest = []byte(`Manifest-Version: 1.0
Built-By: Generated-by-Autograph
Created-By: go.mozilla.org/autograph

`)
	manifest = append(manifest, manifestBody...)
	for lineno, line := range bytes.Split(manifest, []byte("\n")) {
		if len(line) > 72 {
			return manifest, sigfile, errors.Errorf("apk: invalid manifest line %d: %s", lineno, line)
		}
	}

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

// isJARAligned checks if an APK is aligned to 4 bytes / 32-bits (to
// which "allows those portions to be accessed directly with mmap()
// even if they contain binary data with alignment restrictions.")
// returns an err when an uncompressed file isn't aligned or another
// error occurs (error reading ZIP bytes or fetching a file data
// offset) should be equivalent to zipalign -c -v 4 from:
// https://android.googlesource.com/platform/build.git/+/android-4.2.2_r1/tools/zipalign/README.txt
//
// Since this function logs, but not in MozLog format it should not be
// called from server code.
func isJARAligned(input []byte) error {
	const alignment = 4
	r, err := zip.NewReader(bytes.NewReader(input), int64(len(input)))
	if err != nil {
		return err
	}

	for _, f := range r.File {
		offset, err := f.DataOffset()
		if err != nil {
			return err
		}
		isCompressed := f.Method != zip.Store

		if isCompressed {
			log.Printf("%10d %s (OK - compressed)\n", offset, f.Name)
			continue
		}
		if offset % alignment == 0 {
			log.Printf("%10d %s (OK)\n", offset, f.Name)
		} else {
			log.Printf("%10d %s (BAD - %d)\n", offset, f.Name, offset % alignment)
			return errors.Errorf("apk: unaligned file at %d %s (BAD - %d)", offset, f.Name, offset % alignment)
		}
	}
	return nil
}

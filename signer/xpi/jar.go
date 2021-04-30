package xpi

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
		err = fmt.Errorf("xpi: invalid UTF8 in filename %q", filename)
		return
	}
	var (
		filenameLen      = len(filename)
		writtenFileBytes = 0 // number of bytes of the filename we've written
	)
	if filenameLen > maxHeaderBytes {
		err = fmt.Errorf("xpi: filename length %d exceeds the wrappable limit %d", filenameLen, maxHeaderBytes)
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
			err = fmt.Errorf("Cannot makePKCS7Manifest with metafile at invalid path %q", f.Name)
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
		if isJARSignatureFile(f.Name) || isCOSESignatureFile(f.Name) {
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
			err = fmt.Errorf("Cannot pack metafile with invalid path %q", f.Name)
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
		if isJARSignatureFile(f.Name) || isCOSESignatureFile(f.Name) {
			continue
		}
		if f.FileInfo().IsDir() {
			// directories do not get included
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

// appendFileToZIP appends a file with its contents to a ZIP archive and returns it or an error
func appendFileToZIP(input []byte, filepath string, filecontents []byte) (output []byte, err error) {
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
	// append a file. Those will be compressed
	// so we don't have to worry about their alignment
	fwhead = &zip.FileHeader{
		Name:   filepath,
		Method: zip.Deflate,
	}
	fw, err = w.CreateHeader(fwhead)
	if err != nil {
		return
	}
	_, err = fw.Write(filecontents)
	if err != nil {
		return
	}
	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		return
	}
	output = buf.Bytes()
	return
}

// removeFileFromZIP remove all archive entries matching a given file
// path and returns the filtered XPI or an error
func removeFileFromZIP(input []byte, filepath string) (output []byte, err error) {
	var (
		rc   io.ReadCloser
		fw   io.Writer
		data []byte
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
		if f.Name == filepath {
			log.Infof("xpi: skipping filepath path %q matching reserved name %q", f.Name, filepath)
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
	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		return
	}
	output = buf.Bytes()
	return
}

// readFileFromZIP reads a given filename out of a ZIP and returns it or an error
func readFileFromZIP(signedXPI []byte, filename string) ([]byte, error) {
	zipReader := bytes.NewReader(signedXPI)
	r, err := zip.NewReader(zipReader, int64(len(signedXPI)))
	if err != nil {
		return nil, fmt.Errorf("Error reading ZIP: %w", err)
	}

	for _, f := range r.File {
		if f.Name == filename {
			rc, err := f.Open()
			defer rc.Close()
			if err != nil {
				return nil, fmt.Errorf("Error opening file %q in ZIP: %w", filename, err)
			}
			data, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("Error reading file %q in ZIP: %w", filename, err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("failed to find %q in ZIP", filename)
}

// readXPIContentsToMap reads XPI file contents into memory into a
// filenameToContents hashmap
func readXPIContentsToMap(signedXPI []byte) (map[string][]byte, error) {
	var (
		ok                 bool
		err                error
		filenameToContents = make(map[string][]byte)
	)

	zipReader := bytes.NewReader(signedXPI)
	r, err := zip.NewReader(zipReader, int64(len(signedXPI)))
	if err != nil {
		return nil, fmt.Errorf("Error reading ZIP: %w", err)
	}

	for _, f := range r.File {
		rc, err := f.Open()
		defer rc.Close()
		if err != nil {
			return nil, fmt.Errorf("Error opening file %q in ZIP: %w", f.Name, err)
		}
		data, err := ioutil.ReadAll(rc)
		if err != nil {
			return nil, fmt.Errorf("Error reading file %q in ZIP: %w", f.Name, err)
		}
		if _, ok = filenameToContents[f.Name]; ok {
			return nil, fmt.Errorf("%q occurs twice in ZIP", f.Name)
		}
		filenameToContents[f.Name] = data
	}

	return filenameToContents, nil
}

// parseManifestEntry parses name, sha1, and sha256 digests from JAR
// manifest files with entries in the format:
//
// Name: test.txt
// Digest-Algorithms: SHA1 SHA256
// SHA1-Digest: 8mPWZnQPS9arW9Tu/vmC+JHgnYA=
// SHA256-Digest: 8usFS0xIHQV5njGLlVZofDfPreYQP4+qWMMvYF5fvNw=
//
func parseManifestEntry(entry []byte) (filename string, fileSHA1, fileSHA256 []byte, err error) {
	// unwrap long lines (TODO: use ReplaceAll after upgrading to 1.12)
	entry = bytes.Replace(entry, []byte("\n "), []byte(""), -1)

	for i, line := range bytes.Split(entry, []byte("\n")) {
		switch i {
		case 0:
			tmp := bytes.Split(line, []byte("Name: "))
			if len(tmp) != 2 {
				return "", nil, nil, fmt.Errorf("unexpected name line: %q", line)
			}
			filename = string(tmp[1])
		case 1:
			if !bytes.Equal(line, []byte("Digest-Algorithms: SHA1 SHA256")) {
				return "", nil, nil, fmt.Errorf("unexpected digest algs: %q", line)
			}
		case 2:
			tmp := bytes.Split(line, []byte("SHA1-Digest: "))
			if len(tmp) != 2 {
				return "", nil, nil, fmt.Errorf("unexpected SHA1 line: %q", line)
			}
			fileSHA1 = tmp[1]
		case 3:
			tmp := bytes.Split(line, []byte("SHA256-Digest: "))
			if len(tmp) != 2 {
				return "", nil, nil, fmt.Errorf("unexpected SHA256 line: %q", line)
			}
			fileSHA256 = tmp[1]
		default:
			return "", nil, nil, fmt.Errorf("unexpected manifest line: %q", line)
		}
	}
	return filename, fileSHA1, fileSHA256, nil
}

// checkSHAsums
func checkSHAsums(data, sha1sum, sha256sum []byte) error {
	h1 := sha1.New()
	h1.Write(data)
	h2 := sha256.New()
	h2.Write(data)
	computedSHA1 := []byte(base64.StdEncoding.EncodeToString(h1.Sum(nil)))
	computedSHA256 := []byte(base64.StdEncoding.EncodeToString(h2.Sum(nil)))

	if !bytes.Equal(sha1sum, computedSHA1) {
		return fmt.Errorf("SHA1 mismatch got %q but computed %q", sha1sum, computedSHA1)
	}
	if !bytes.Equal(sha256sum, computedSHA256) {
		return fmt.Errorf("SHA2 mismatch got %q but computed %q", sha256sum, computedSHA256)
	}
	return nil
}

// verifyAndCountManifest reads an XPI, parses a manifest and checks:
//
// * for duplicate XPI filenames
// * for duplicate manifest entries
// * all manifest entries have a matching XPI filename
// * shasums match between manifest entry and XPI contents
//
// Returns the number of entries in the zip file and manifest or an error.
func verifyAndCountManifest(signedXPI []byte, manifestPath string) (int, int, error) {
	var (
		ok                 bool
		err                error
		filenameToContents map[string][]byte
		manifestBytes      []byte
		manifestEntryNames = make(map[string]bool)
	)

	filenameToContents, err = readXPIContentsToMap(signedXPI)
	if err != nil {
		return -1, -1, fmt.Errorf("error reading XPI contents to map: %w", err)
	}
	if manifestBytes, ok = filenameToContents[manifestPath]; !ok {
		return -1, -1, fmt.Errorf("did not find manifest %q in zip: %w", manifestPath, err)
	}

	for _, entry := range bytes.Split(manifestBytes, []byte("\n\n")) {
		// skip 'Manifest-Version: 1.0' line at start of file and empty line
		// and \n\n at EOF
		if bytes.Equal(entry, []byte("Manifest-Version: 1.0")) || bytes.Equal(entry, []byte("")) {
			continue
		}
		filename, fileSHA1, fileSHA256, err := parseManifestEntry(entry)
		if err != nil {
			return -1, -1, fmt.Errorf("failed to parse manifest entry: %q: %w", entry, err)
		}
		if filename == "" || fileSHA1 == nil || fileSHA256 == nil {
			return -1, -1, fmt.Errorf("failed to parse manifest entry: %q", entry)
		}

		if _, ok = manifestEntryNames[filename]; ok {
			return -1, -1, fmt.Errorf("duplicate entries for file %q in manifest", filename)
		}
		manifestEntryNames[filename] = true

		var contents []byte
		if contents, ok = filenameToContents[string(filename)]; !ok {
			return -1, -1, fmt.Errorf("file %q in manifest but not XPI", filename)
		}

		err = checkSHAsums(contents, fileSHA1, fileSHA256)
		if err != nil {
			return -1, -1, fmt.Errorf("file %q hash mistmatch between manifest and computed: %w", filename, err)
		}

	}
	return len(filenameToContents), len(manifestEntryNames), nil
}

package xpi // import "github.com/mozilla-services/autograph/signer/xpi"

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mozilla-services/autograph/signer"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/cose"
	"go.mozilla.org/pkcs7"
)

const (
	// Type of this signer is "xpi"
	Type = "xpi"

	// ModeAddOn represents a signer that issues signatures for
	// regular firefox add-ons and web extensions developed by anyone
	ModeAddOn = "add-on"

	// ModeAddOnWithRecommendation represents a signer that issues
	// signatures for regular firefox add-ons and web extensions
	// developed by anyone including a recommendation file
	ModeAddOnWithRecommendation = "add-on-with-recommendation"

	// ModeExtension represents a signer that issues signatures for
	// internal extensions developed by Mozilla
	ModeExtension = "extension"

	// ModeSystemAddOn represents a signer that issues signatures for
	// System Add-Ons developed by Mozilla
	ModeSystemAddOn = "system add-on"

	// ModeHotFix represents a signer that issues signatures for
	// Firefox HotFixes
	ModeHotFix = "hotfix"

	coseManifestPath       = "META-INF/cose.manifest"
	coseSigPath            = "META-INF/cose.sig"
	pkcs7ManifestPath      = "META-INF/manifest.mf"
	pkcs7SignatureFilePath = "META-INF/mozilla.sf"
	pkcs7SigPath           = "META-INF/mozilla.rsa"

	// rsaKeyMinSize is the minimum RSA Key size for issuer keys and new EE RSA keys
	rsaKeyMinSize = 2048
)

var (
	// EENotBefore is the NotBefore value used in generated
	// EE/leaf certs. Fx ignores EE certs when it verifies addons,
	// but we pin it to 2020-01-01 so we can use existing chain
	// verification logic in tests and the monitor
	EENotBefore = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// An XPISigner is configured to issue detached PKCS7 and COSE
// signatures for Firefox Add-ons of various types.
type XPISigner struct {
	signer.Configuration
	issuerKey       crypto.PrivateKey
	issuerPublicKey crypto.PublicKey
	issuerCert      *x509.Certificate

	// OU is the organizational unit of the end-entity certificate
	// generated for each operation performed by this signer
	OU string

	// EndEntityCN is the subject CN of the end-entity certificate generated
	// for each operation performed by this signer. Most of the time
	// the ID will be left blank and provided by the requester of the
	// signature, but for hotfix signers, it is set to a specific value.
	EndEntityCN string

	// rand is the CSPRNG to use from the HSM or crypto/rand
	rand io.Reader

	// rsa cache is used to pre-generate RSA private keys and speed up
	// the signing process
	rsaCache chan *rsa.PrivateKey

	// rsaCacheGeneratorSleepDuration is how frequently each cache key
	// generator tries to add a key to the cache chan
	rsaCacheGeneratorSleepDuration time.Duration

	// rsaCacheFetchTimeout is how long a consumer waits for the
	// cache before generating its own key
	rsaCacheFetchTimeout time.Duration

	// rsaCacheSizeSampleRate is how frequently the monitor
	// reports the cache size and capacity
	rsaCacheSizeSampleRate time.Duration

	// stats is the statsd client for reporting metrics
	stats *signer.StatsClient

	// recommendationAllowedStates is a map of strings the signer
	// is allowed to set in the recommendations file to true
	// indicating whether they're allowed or not
	recommendationAllowedStates map[string]bool

	// recommendationFilePath is the path in the XPI to save the
	// recommendations file
	recommendationFilePath string

	// recommendationValidityRelativeStart is when to set the
	// recommendation validity not_before relative to now
	recommendationValidityRelativeStart time.Duration

	// recommendationValidityDuration is when to set the
	// recommendation validity not_after relative to now
	//
	// i.e.
	//         ValidityRelativeStart    ValidityDuration
	//       <----------------------> <------------------->
	//      |                        |                     |
	//   not_before          now / signing TS          not_after
	recommendationValidityDuration time.Duration
}

// New initializes an XPI signer using a configuration
func New(conf signer.Configuration, stats *signer.StatsClient) (s *XPISigner, err error) {
	s = new(XPISigner)
	if conf.Type != Type {
		return nil, fmt.Errorf("xpi: invalid type %q, must be %q", conf.Type, Type)
	}
	s.Type = conf.Type
	if conf.ID == "" {
		return nil, fmt.Errorf("xpi: missing signer ID in signer configuration")
	}
	s.ID = conf.ID
	if conf.PrivateKey == "" {
		return nil, fmt.Errorf("xpi: missing private key in signer configuration")
	}
	s.PrivateKey = conf.PrivateKey

	s.rand = conf.GetRand()
	s.issuerKey, s.issuerPublicKey, s.PublicKey, err = conf.GetKeys()
	if err != nil {
		return nil, fmt.Errorf("xpi: GetKeys failed to retrieve signer: %w", err)
	}

	block, _ := pem.Decode([]byte(conf.Certificate))
	if block == nil {
		return nil, fmt.Errorf("xpi: failed to parse certificate PEM")
	}
	s.issuerCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("xpi: could not parse X.509 certificate: %w", err)
	}
	// some sanity checks for the signer cert
	if !s.issuerCert.IsCA {
		return nil, fmt.Errorf("xpi: signer certificate must have CA constraint set to true")
	}
	if time.Now().Before(s.issuerCert.NotBefore) || time.Now().After(s.issuerCert.NotAfter) {
		return nil, fmt.Errorf("xpi: signer certificate is not currently valid")
	}
	if s.issuerCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("xpi: signer certificate is missing certificate signing key usage")
	}
	hasCodeSigning := false
	for _, eku := range s.issuerCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return nil, fmt.Errorf("xpi: signer certificate does not have code signing EKU")
	}
	switch conf.Mode {
	case ModeAddOn, ModeAddOnWithRecommendation:
		s.OU = "Production"
	case ModeExtension:
		s.OU = "Mozilla Extensions"
	case ModeSystemAddOn:
		s.OU = "Mozilla Components"
	case ModeHotFix:
		// FIXME: this also needs to pin the signing key somehow
		s.OU = "Production"
		s.EndEntityCN = "firefox-hotfix@mozilla.org"
	default:
		return nil, fmt.Errorf("xpi: unknown signer mode %q, must be 'add-on', 'extension', 'system add-on' or 'hotfix'", conf.Mode)
	}
	s.Mode = conf.Mode
	s.stats = stats

	if conf.Mode == ModeAddOnWithRecommendation {
		s.recommendationAllowedStates = conf.RecommendationConfig.AllowedStates
		s.recommendationValidityRelativeStart = conf.RecommendationConfig.ValidityRelativeStart
		s.recommendationValidityDuration = conf.RecommendationConfig.ValidityDuration
		log.Infof("xpi: set recommendation options allowed states: %+v, path: %q, start duration: %q duration: %q",
			s.recommendationAllowedStates,
			s.recommendationFilePath,
			s.recommendationValidityRelativeStart,
			s.recommendationValidityDuration)
	}
	s.recommendationFilePath = conf.RecommendationConfig.FilePath
	log.Infof("xpi: signer %q is ignoring recommendation file path %q", s.ID, s.recommendationFilePath)

	// If the private key is rsa, launch go routines that
	// populates the rsa cache with private keys of the same
	// length
	if issuerKey, ok := s.issuerKey.(*rsa.PrivateKey); ok {
		if issuerKey.N.BitLen() < rsaKeyMinSize {
			return nil, fmt.Errorf("xpi: issuer RSA key must be at least %d bits", rsaKeyMinSize)
		}
		if conf.RSACacheConfig.StatsSampleRate < 5*time.Second {
			log.Warnf("xpi: sampling rsa cache as rate of %q (less than 5s)", conf.RSACacheConfig.StatsSampleRate)
		}
		s.rsaCacheGeneratorSleepDuration = conf.RSACacheConfig.GeneratorSleepDuration
		s.rsaCacheFetchTimeout = conf.RSACacheConfig.FetchTimeout
		s.rsaCacheSizeSampleRate = conf.RSACacheConfig.StatsSampleRate

		s.rsaCache = make(chan *rsa.PrivateKey, conf.RSACacheConfig.NumKeys)
		for i := 0; i < int(conf.RSACacheConfig.NumGenerators); i++ {
			go s.populateRsaCache(issuerKey.N.BitLen())
		}

		log.Infof("xpi: %d RSA key cache started with %d generators running every %q\n and a %q timeout", conf.RSACacheConfig.NumKeys, conf.RSACacheConfig.NumGenerators, s.rsaCacheGeneratorSleepDuration, s.rsaCacheFetchTimeout)

		if s.stats == nil {
			log.Warnf("xpi: No statsd client found to send RSA cache metrics")
		} else {
			go s.monitorRsaCacheSize()
			log.Infof("xpi: Started RSA cache monitor")
		}
	}

	return
}

// Config returns the configuration of the current signer
func (s *XPISigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:          s.ID,
		Type:        s.Type,
		Mode:        s.Mode,
		PrivateKey:  s.PrivateKey,
		Certificate: s.Certificate,
	}
}

// SignFile takes an unsigned zipped XPI file and returns a signed XPI file
func (s *XPISigner) SignFile(input []byte, options interface{}) (signedFile signer.SignedFile, err error) {
	var (
		pkcs7Manifest []byte
		manifest      []byte
		metas         = []Metafile{}
		opt           Options
		coseSig       []byte
		coseSigAlgs   []*cose.Algorithm
	)

	opt, err = GetOptions(options)
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot get options: %w", err)
	}
	cn, err := opt.CN(s)
	if err != nil {
		return nil, err
	}
	coseSigAlgs, err = opt.Algorithms()
	if err != nil {
		return nil, fmt.Errorf("xpi: error parsing cose_algorithms options: %w", err)
	}

	input, err = removeFileFromZIP(input, s.recommendationFilePath)
	if err != nil {
		return nil, fmt.Errorf("xpi: error removing recommendation file from XPI: %w", err)
	}
	if s.Mode == ModeAddOnWithRecommendation {
		recFileBytes, err := s.makeRecommendationFile(opt, cn)
		if err != nil {
			return nil, fmt.Errorf("xpi: error making recommendation file from options: %w", err)
		}
		input, err = appendFileToZIP(input, s.recommendationFilePath, recFileBytes)
		if err != nil {
			return nil, fmt.Errorf("xpi: error append recommendation file to XPI: %w", err)
		}
	}

	manifest, err = makeJARManifest(input)
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot make JAR manifest from XPI: %w", err)
	}

	// when the optional COSE Algorithms params are not provided
	// we don't need to add entries to the PKCS7 manifest for
	// cose.sig and cose.manifest metafiles and can use the
	// manifest as is
	if len(coseSigAlgs) < 1 {
		pkcs7Manifest = manifest
	} else {
		coseSig, err = s.issueCOSESignature(cn, manifest, coseSigAlgs)
		if err != nil {
			return nil, fmt.Errorf("xpi: error signing cose message: %w", err)
		}

		// add the cose files to the metafiles we'll add to the XPI
		coseMetaFiles := []Metafile{
			{coseManifestPath, manifest},
			{coseSigPath, coseSig},
		}
		metas = append(metas, coseMetaFiles...)

		// add entries for the cose files to the manifest as cose.manifest and cose.sig
		pkcs7Manifest, err = makePKCS7Manifest(input, metas)
		if err != nil {
			return nil, fmt.Errorf("xpi: error making PKCS7 manifest: %w", err)
		}
	}

	sigfile, err := makeJARSignatureFile(pkcs7Manifest)
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot make JAR manifest signature from XPI: %w", err)
	}
	p7Digest, err := opt.PK7Digest()
	if err != nil {
		return nil, fmt.Errorf("xpi: error parsing PK7 Digest: %w", err)
	}

	p7sig, err := s.signDataWithPKCS7(sigfile, cn, p7Digest)
	if err != nil {
		return nil, fmt.Errorf("xpi: failed to sign XPI: %w", err)
	}

	metas = append(metas, []Metafile{
		{pkcs7ManifestPath, pkcs7Manifest},
		{pkcs7SignatureFilePath, sigfile},
		{pkcs7SigPath, p7sig},
	}...)

	signedFile, err = repackJARWithMetafiles(input, metas)
	if err != nil {
		return nil, fmt.Errorf("xpi: failed to repack XPI: %w", err)
	}
	return signedFile, nil
}

// SignData takes an input signature file and returns a PKCS7 or COSE detached signature
func (s *XPISigner) SignData(sigfile []byte, options interface{}) (signer.Signature, error) {
	opt, err := GetOptions(options)
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot get options: %w", err)
	}
	cn, err := opt.CN(s)
	if err != nil {
		return nil, err
	}
	if len(opt.COSEAlgorithms) > 0 {
		return nil, fmt.Errorf("xpi: cannot use /sign/data for COSE signatures. Use /sign/file instead")
	}
	if !(opt.PKCS7Digest == "" || strings.ToUpper(opt.PKCS7Digest) == "SHA1") {
		return nil, fmt.Errorf("xpi: can only use SHA1 digests with /sign/data. Use /sign/file instead")
	}

	sigBytes, err := s.signDataWithPKCS7(sigfile, cn, pkcs7.OIDDigestAlgorithmSHA1)
	if err != nil {
		return nil, err
	}
	sig := new(Signature)
	sig.Data = sigBytes
	sig.Finished = true
	return sig, nil
}

func (s *XPISigner) signDataWithPKCS7(sigfile []byte, cn string, digest asn1.ObjectIdentifier) ([]byte, error) {
	eeCert, eeKey, err := s.MakeEndEntity(cn, nil)
	if err != nil {
		return nil, err
	}

	toBeSigned, err := pkcs7.NewSignedData(sigfile)
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot initialize signed data: %w", err)
	}
	toBeSigned.SetDigestAlgorithm(digest)
	err = toBeSigned.AddSignerChain(eeCert, eeKey, []*x509.Certificate{s.issuerCert}, pkcs7.SignerInfoConfig{})
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot sign: %w", err)
	}
	toBeSigned.Detach()
	p7sig, err := toBeSigned.Finish()
	if err != nil {
		return nil, fmt.Errorf("xpi: cannot finish signing data: %w", err)
	}
	return p7sig, nil
}

// Options contains specific parameters used to sign XPIs
type Options struct {
	// ID is the add-on ID which is stored in the end-entity subject CN
	ID string `json:"id"`

	// COSEAlgorithms is an optional list of strings referring to IANA algorithms to use for COSE signatures
	COSEAlgorithms []string `json:"cose_algorithms"`

	// PKCS7Digest is a string required for /sign/file referring to algorithm to use for the PKCS7 signature digest
	PKCS7Digest string `json:"pkcs7_digest"`

	// Recommendations is an optional list of strings referring to
	// recommended states to add to the recommendations file
	// for signers in ModeAddOnWithRecommendation
	Recommendations []string `json:"recommendations"`
}

// CN returns the common name
func (o *Options) CN(s *XPISigner) (cn string, err error) {
	if s != nil && s.EndEntityCN != "" {
		return s.EndEntityCN, nil
	}
	if o != nil && o.ID != "" {
		return o.ID, nil
	}
	return "", fmt.Errorf("xpi: missing common name")
}

// Algorithms validates and returns COSE algorithms
func (o *Options) Algorithms() (algs []*cose.Algorithm, err error) {
	if o == nil {
		err = fmt.Errorf("xpi: cannot get COSE Algorithms from nil Options")
	}

	for _, algStr := range o.COSEAlgorithms {
		alg := stringToCOSEAlg(algStr)
		if alg == nil {
			return nil, fmt.Errorf("xpi: invalid or unsupported COSE algorithm %q", algStr)
		}
		algs = append(algs, alg)
	}
	return
}

// RecommendationStates validates and returns allowed recommendation states
// algorithms from the request
func (o *Options) RecommendationStates(allowedRecommendationStates map[string]bool) (states []string, err error) {
	if o == nil {
		err = fmt.Errorf("xpi: cannot get recommendation states from nil Options")
	}

	for _, rec := range o.Recommendations {
		if val, ok := allowedRecommendationStates[rec]; !(ok && val) {
			return nil, fmt.Errorf("xpi: invalid or unsupported recommendation state %q", rec)
		}
		states = append(states, rec)
	}
	return
}

// PK7Digest validates and return an ASN OID for a PKCS7 digest
// algorithm or an error
func (o *Options) PK7Digest() (asn1.ObjectIdentifier, error) {
	if o == nil {
		return nil, fmt.Errorf("xpi: Cannot get PK7Digest from nil Options")
	}
	switch strings.ToUpper(o.PKCS7Digest) {
	case "SHA256":
		return pkcs7.OIDDigestAlgorithmSHA256, nil
	case "SHA1":
		return pkcs7.OIDDigestAlgorithmSHA1, nil
	default:
		return nil, fmt.Errorf("xpi: Failed to recognize PK7Digest from Options")
	}
}

// GetDefaultOptions returns default options of the signer
func (s *XPISigner) GetDefaultOptions() interface{} {
	return Options{
		ID:          "ffffffff-ffff-ffff-ffff-ffffffffffff",
		PKCS7Digest: "SHA1",
	}
}

// GetOptions takes a input interface and reflects it into a struct of options
func GetOptions(input interface{}) (options Options, err error) {
	buf, err := json.Marshal(input)
	if err != nil {
		return
	}
	err = json.Unmarshal(buf, &options)
	return
}

// Signature is a detached PKCS7 signature or COSE SignMessage
type Signature struct {
	p7          *pkcs7.PKCS7
	signMessage *cose.SignMessage
	Data        []byte
	Finished    bool
}

// Marshal returns the base64 representation of a detached PKCS7
// signature or COSE Sign Message
func (sig *Signature) Marshal() (string, error) {
	if !sig.Finished {
		return "", fmt.Errorf("xpi: cannot marshal unfinished signature")
	}
	if len(sig.Data) == 0 {
		return "", fmt.Errorf("xpi: cannot marshal empty signature data")
	}
	return base64.StdEncoding.EncodeToString(sig.Data), nil
}

// Unmarshal parses a PKCS7 struct from the base64 representation of a
// PKCS7 detached and content of the signed data or it parses a COSE
// Sign Message struct from the base64 representation of a CBOR
// encoded Sign Message
func Unmarshal(signature string, content []byte) (sig *Signature, err error) {
	sig = new(Signature)
	sig.Data, err = base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return sig, fmt.Errorf("xpi.Unmarshal: failed to decode base64 signature: %w", err)
	}

	if cose.IsSignMessage(sig.Data) {
		tmp, err := cose.Unmarshal(sig.Data)
		if err != nil {
			return sig, fmt.Errorf("xpi.Unmarshal: failed to parse COSE Sign Message: %w", err)
		}
		if msg, ok := tmp.(cose.SignMessage); ok {
			sig.signMessage = &msg
		} else {
			return sig, fmt.Errorf("xpi.Unmarshal: failed to cast COSE Sign Message: %w", err)
		}
	} else {
		sig.p7, err = pkcs7.Parse(sig.Data)
		if err != nil {
			return sig, fmt.Errorf("xpi.Unmarshal: failed to parse pkcs7 signature: %w", err)
		}
		sig.p7.Content = content
	}
	sig.Finished = true
	return
}

// VerifyWithChain verifies an xpi signature using the provided truststore
func (sig *Signature) VerifyWithChain(truststore *x509.CertPool) error {
	if !sig.Finished {
		return fmt.Errorf("xpi.VerifyWithChain: cannot verify unfinished signature")
	}
	return sig.p7.VerifyWithChain(truststore)
}

// String returns a PEM encoded PKCS7 block
func (sig *Signature) String() string {
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "PKCS7", Bytes: sig.Data})
	return string(buf.Bytes())
}

// verifyPKCS7SignatureRoundTrip checks that
//
// 1) the signed XPI includes a PKCS7 signature and signature data
// 2) the signature serializes and deserializes properly
// 3) the PKCS7 signatures
// 4) the signature cert chain verifies when an optional non-nil truststore is provided
//
func verifyPKCS7SignatureRoundTrip(signedFile signer.SignedFile, truststore *x509.CertPool) error {
	sigStrBytes, err := readFileFromZIP(signedFile, pkcs7SigPath)
	if err != nil {
		return fmt.Errorf("failed to read PKCS7 signature META-INF/mozilla.rsa: %w", err)
	}
	sigStr := base64.StdEncoding.EncodeToString(sigStrBytes)
	sigData, err := readFileFromZIP(signedFile, pkcs7SignatureFilePath)
	if err != nil {
		return fmt.Errorf("failed to read META-INF/mozilla.sf: %w", err)
	}

	// convert string format back to signature
	sig, err := Unmarshal(sigStr, sigData)
	if err != nil {
		return fmt.Errorf("failed to unmarshal PKCS7 signature: %w", err)
	}
	// verify signature on input data
	if sig.VerifyWithChain(truststore) != nil {
		return fmt.Errorf("failed to verify xpi signature: %v", sig.VerifyWithChain(truststore))
	}

	// make sure we still have the same string representation
	sigStr2, err := sig.Marshal()
	if err != nil {
		return fmt.Errorf("failed to re-marshal signature: %v", err)
	}
	if sigStr != sigStr2 {
		return fmt.Errorf("marshalling signature changed its format.\nexpected\t%q\nreceived\t%q",
			sigStr, sigStr2)
	}

	return nil
}

// verifyPKCS7Manifest checks all files occur once in the manifest and
// match their hashes
func verifyPKCS7Manifest(signedXPI signer.SignedFile) error {
	numZippedFiles, numManifestEntries, err := verifyAndCountManifest(signedXPI, pkcs7ManifestPath)
	if err != nil {
		return fmt.Errorf("error validating PK7 manifest: %w", err)
	}

	expectedMetaFilesInManifest := 3 // PK7 sig, manifest, and sigFile
	if !(numZippedFiles > numManifestEntries && numZippedFiles-numManifestEntries == expectedMetaFilesInManifest) {
		return fmt.Errorf("mismatch in # PK7 manifest entries %d and # files %d in XPI", numManifestEntries, numZippedFiles)
	}
	return nil
}

// verifyCOSEManifest checks each file occurs once in the manifest and
// its hashes match
func verifyCOSEManifest(signedXPI signer.SignedFile) error {
	numZippedFiles, numManifestEntries, err := verifyAndCountManifest(signedXPI, coseManifestPath)
	if err != nil {
		return fmt.Errorf("error validating COSE manifest: %w", err)
	}

	// 5 from PK7 sig, manifest, and sigFile; and COSE sig and manifest
	if !(numZippedFiles > numManifestEntries && numZippedFiles-numManifestEntries == 5) {
		return fmt.Errorf("mismatch in # COSE manifest entries %d and # files %d in XPI", numManifestEntries, numZippedFiles)
	}
	return nil
}

// VerifySignedFile checks the XPI's PKCS7 signature and COSE
// signatures if present
func VerifySignedFile(signedFile signer.SignedFile, truststore *x509.CertPool, opts Options) error {
	var err error
	err = verifyPKCS7Manifest(signedFile)
	if err != nil {
		return fmt.Errorf("xpi: error verifying PKCS7 manifest for signed file: %w", err)
	}
	err = verifyPKCS7SignatureRoundTrip(signedFile, truststore)
	if err != nil {
		return fmt.Errorf("xpi: error verifying PKCS7 signature for signed file: %w", err)
	}

	if len(opts.COSEAlgorithms) > 0 {
		err = verifyCOSEManifest(signedFile)
		if err != nil {
			return fmt.Errorf("xpi: error verifying COSE manifest for signed file: %w", err)
		}
		err = verifyCOSESignatures(signedFile, truststore, opts)
		if err != nil {
			return fmt.Errorf("xpi: error verifying COSE signatures for signed file: %w", err)
		}
	}

	return nil
}

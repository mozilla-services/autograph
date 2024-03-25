package contentsignaturepki // import "github.com/mozilla-services/autograph/signer/contentsignaturepki"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"
	"math/big"
	"time"

	"github.com/mozilla-services/autograph/database"
	"github.com/mozilla-services/autograph/signer"
	verifier "github.com/mozilla-services/autograph/verifier/contentsignature"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph")
}

const (
	// Type of this signer is 'contentsignaturepki'
	Type = "contentsignaturepki"

	// P256ECDSA defines an ecdsa content signature on the P-256 curve
	P256ECDSA = "p256ecdsa"

	// P256ECDSABYTESIZE defines the bytes length of a P256ECDSA signature
	P256ECDSABYTESIZE = 64

	// P384ECDSA defines an ecdsa content signature on the P-384 curve
	P384ECDSA = "p384ecdsa"

	// P384ECDSABYTESIZE defines the bytes length of a P384ECDSA signature
	P384ECDSABYTESIZE = 96

	// SignaturePrefix is a string preprended to data prior to signing
	SignaturePrefix = "Content-Signature:\x00"

	// CSNameSpace is a string that contains the namespace on which
	// content signature certificates are issued
	CSNameSpace = ".content-signature.mozilla.org"
)

// ContentSigner implements an issuer of content signatures
type ContentSigner struct {
	signer.Configuration
	IssuerPrivKey, IssuerPubKey string
	issuerPriv, eePriv          crypto.PrivateKey
	issuerPub, eePub            crypto.PublicKey
	eeLabel                     string
	rand                        io.Reader
	validity                    time.Duration
	clockSkewTolerance          time.Duration
	chainUploadLocation         string
	caCert                      string
	db                          *database.Handler
	subdomainOverride           string
}

// ecdsaAsn1Signature is a private struct to unmarshal asn1 signatures produced by crypto.Signer
type ecdsaAsn1Signature struct {
	R, S *big.Int
}

// New initializes a ContentSigner using a signer configuration
func New(conf signer.Configuration) (s *ContentSigner, err error) {
	s = new(ContentSigner)
	s.ID = conf.ID
	s.Type = conf.Type
	s.IssuerPrivKey = conf.IssuerPrivKey
	s.IssuerCert = conf.IssuerCert
	s.X5U = conf.X5U
	s.validity = conf.Validity
	s.clockSkewTolerance = conf.ClockSkewTolerance
	s.chainUploadLocation = conf.ChainUploadLocation
	s.caCert = conf.CaCert
	s.db = conf.DB
	s.subdomainOverride = conf.SubdomainOverride

	if conf.Type != Type {
		return nil, fmt.Errorf("contentsignaturepki %q: invalid type %q, must be %q", s.ID, conf.Type, Type)
	}
	if conf.ID == "" {
		return nil, fmt.Errorf("contentsignaturepki %q: missing signer ID in signer configuration", s.ID)
	}
	if conf.IssuerPrivKey == "" {
		return nil, fmt.Errorf("contentsignaturepki %q: missing issuer private key in signer configuration", s.ID)
	}
	s.rand = conf.GetRand()
	// make a temporary config since we need to retrieve the
	// issuer private key from the hsm
	tmpconf := conf
	tmpconf.PrivateKey = conf.IssuerPrivKey
	s.issuerPriv, s.issuerPub, _, err = tmpconf.GetKeys()
	if err != nil {
		return nil, fmt.Errorf("contentsignaturepki %q: failed to get keys: %w", s.ID, err)
	}
	// if validity is undef, default to 30 days
	if s.validity == 0 {
		log.Printf("contentsignaturepki %q: no validity configured, defaulting to 30 days", s.ID)
		s.validity = 720 * time.Hour
	}

	switch s.issuerPub.(type) {
	case *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("contentsignaturepki %q: invalid public key type for issuer, must be ecdsa", s.ID)
	}
	s.Mode = s.getModeFromCurve()

	err = s.initEE(conf)
	if err != nil {
		return nil, fmt.Errorf("contentsignaturepki %q: failed to initialize end-entity: %w", s.ID, err)
	}
	return
}

// initEE configures an end-entity key and certificate that will be used
// for signing. It will try to retrieve an existing one from db/hsm, and if
// no suitable candidate can be found, a new one will be created.
func (s *ContentSigner) initEE(conf signer.Configuration) error {
	err := s.findAndSetEE(conf)
	switch err {
	case nil:
		log.Printf("contentsignaturepki %q: reusing existing EE %q", s.ID, s.eeLabel)
	case database.ErrNoSuitableEEFound:
		// No suitable end-entity found, making a new chain
		log.Printf("contentsignaturepki %q: making new end-entity", s.ID)
		var tx *database.Transaction
		if s.db != nil {
			tx, err = s.db.BeginEndEntityOperations()
			if err != nil {
				return fmt.Errorf("contentsignaturepki %q: failed to begin db operations: %w", s.ID, err)
			}
		}
		// to prevent race conditions, we perform another set of the EE just in case
		// someone else created it before we managed to obtain the lock
		err = s.findAndSetEE(conf)
		switch err {
		case nil:
			// alright we found a suitable EE this time to don't make one
			goto releaseLock
		case database.ErrNoSuitableEEFound:
			// still nothing suitable, continue on
			break
		default:
			// some other error popped up, exit
			return err
		}
		// create a label and generate the key
		s.eeLabel = fmt.Sprintf("%s-%s", s.ID, time.Now().UTC().Format("20060102150405"))
		s.eePriv, s.eePub, err = conf.MakeKey(s.issuerPub, s.eeLabel)
		if err != nil {
			return fmt.Errorf("contentsignaturepki %q: failed to generate end entity: %w", s.ID, err)
		}
		// make the certificate and upload the chain
		err = s.makeAndUploadChain()
		if err != nil {
			return fmt.Errorf("contentsignaturepki %q: failed to make chain and x5u: %w", s.ID, err)
		}
		if tx != nil {
			// insert it in database
			hsmHandle := signer.GetPrivKeyHandle(s.eePriv)
			err = tx.InsertEE(s.X5U, s.eeLabel, s.ID, hsmHandle)
			if err != nil {
				return fmt.Errorf("contentsignaturepki %q: failed to insert EE into database: %w", s.ID, err)
			}
			log.Printf("contentsignaturepki %q: generated private key labeled %q with hsm handle %d and x5u %q", s.ID, s.eeLabel, hsmHandle, s.X5U)
		}
	releaseLock:
		if tx != nil {
			// close the transaction
			err = tx.End()
			if err != nil {
				return fmt.Errorf("contentsignaturepki %q: failed to commit end-entity operations in database: %w", s.ID, err)
			}
		}
	default:
		return fmt.Errorf("contentsignaturepki %q: failed to find suitable end-entity: %w", s.ID, err)
	}
	_, _, err = GetX5U(buildHTTPClient(), s.X5U)
	if err != nil {
		return fmt.Errorf("contentsignaturepki %q: failed to verify x5u: %w", s.ID, err)
	}
	return nil
}

// Config returns the configuration of the current signer
func (s *ContentSigner) Config() signer.Configuration {
	return signer.Configuration{
		ID:                  s.ID,
		Type:                s.Type,
		Mode:                s.Mode,
		PrivateKey:          s.PrivateKey,
		PublicKey:           s.PublicKey,
		IssuerPrivKey:       s.IssuerPrivKey,
		IssuerCert:          s.IssuerCert,
		X5U:                 s.X5U,
		Validity:            s.validity,
		ClockSkewTolerance:  s.clockSkewTolerance,
		ChainUploadLocation: s.chainUploadLocation,
		CaCert:              s.caCert,
	}
}

// SignData takes input data, templates it, hashes it and signs it.
// The returned signature is of type ContentSignature and ready to be Marshalled.
func (s *ContentSigner) SignData(input []byte, options interface{}) (signer.Signature, error) {
	if len(input) < 10 {
		return nil, fmt.Errorf("contentsignaturepki %q: refusing to sign input data shorter than 10 bytes", s.ID)
	}
	alg, hash := MakeTemplatedHash(input, s.Mode)
	sig, err := s.SignHash(hash, options)
	sig.(*verifier.ContentSignature).HashName = alg
	return sig, err
}

// MakeTemplatedHash returns the templated sha384 of the input data. The template adds
// the string "Content-Signature:\x00" before the input data prior to
// calculating the sha384.
//
// The name of the hash function is returned, followed by the hash bytes
func MakeTemplatedHash(data []byte, curvename string) (alg string, out []byte) {
	templated := make([]byte, len(SignaturePrefix)+len(data))
	copy(templated[:len(SignaturePrefix)], []byte(SignaturePrefix))
	copy(templated[len(SignaturePrefix):], data)
	var md hash.Hash
	switch curvename {
	case P384ECDSA:
		md = sha512.New384()
		alg = "sha384"
	default:
		md = sha256.New()
		alg = "sha256"
	}
	md.Write(templated)
	return alg, md.Sum(nil)
}

// SignHash takes an input hash and returns a signature. It assumes the input data
// has already been hashed with something like sha384
func (s *ContentSigner) SignHash(input []byte, options interface{}) (signer.Signature, error) {
	if len(input) != 32 && len(input) != 48 && len(input) != 64 {
		return nil, fmt.Errorf("contentsignaturepki %q: refusing to sign input hash. length %d, expected 32, 48 or 64", s.ID, len(input))
	}
	var (
		err  error
		csig *verifier.ContentSignature
	)
	csig = &verifier.ContentSignature{
		Len:  getSignatureLen(s.Mode),
		Mode: s.Mode,
		X5U:  s.X5U,
		ID:   s.ID,
	}

	asn1Sig, err := s.eePriv.(crypto.Signer).Sign(rand.Reader, input, nil)
	if err != nil {
		return nil, fmt.Errorf("contentsignaturepki %q: failed to sign hash: %w", s.ID, err)
	}
	var ecdsaSig ecdsaAsn1Signature
	_, err = asn1.Unmarshal(asn1Sig, &ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("contentsignaturepki %q: failed to parse signature: %w", s.ID, err)
	}
	csig.R = ecdsaSig.R
	csig.S = ecdsaSig.S
	csig.Finished = true
	return csig, nil
}

// getSignatureLen returns the size of an ECDSA signature issued by the signer,
// or -1 if the mode is unknown
//
// The signature length is double the size size of the curve field, in bytes
// (each R and S value is equal to the size of the curve field).
// If the curve field it not a multiple of 8, round to the upper multiple of 8.
func getSignatureLen(mode string) int {
	switch mode {
	case P256ECDSA:
		return P256ECDSABYTESIZE
	case P384ECDSA:
		return P384ECDSABYTESIZE
	}
	return -1
}

// getModeFromCurve returns a content signature algorithm name, or an empty string if the mode is unknown
func (s *ContentSigner) getModeFromCurve() string {
	switch s.issuerPub.(*ecdsa.PublicKey).Params().Name {
	case "P-256":
		return P256ECDSA
	case "P-384":
		return P384ECDSA
	default:
		return ""
	}
}

// GetDefaultOptions returns nil because this signer has no option
func (s *ContentSigner) GetDefaultOptions() interface{} {
	return nil
}

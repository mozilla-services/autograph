package contentsignaturepki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/pkg/errors"
	"go.mozilla.org/autograph/database"
	"go.mozilla.org/autograph/signer"
)

// findEE searches the database for an end-entity key that is currently
// valid for this signer and is not older than cfg.Validity days
func (s *ContentSigner) findEE(conf signer.Configuration) (err error) {
	var tmpX5U string
	if s.db == nil {
		// no database, no chance to find an existing key
		return database.ErrNoSuitableEEFound
	}
	// search the database for the label of an end-entity private key that is still valid.
	s.eeLabel, tmpX5U, err = s.db.GetLabelOfLatestEE(s.ID, s.validity)
	if err != nil {
		return
	}
	if tmpX5U != "" {
		s.X5U = tmpX5U
	}
	conf.PrivateKey = s.eeLabel
	s.eePriv, err = conf.GetPrivateKey()
	if err != nil {
		err = errors.Wrapf(err, "found suitable end-entity labeled %q in database but not in hsm", s.eeLabel)
		return
	}
	s.eePub = s.eePriv.(crypto.Signer).Public()
	return
}

// makeEE generates an end-entity key pair, either in memory, or in HSM & database if those are available.
//
// keyTpl is used to decide which key type should be made. In practice, the issuer's
// public key is passed in that variable such that the end-entity is of the same type.
func (s *ContentSigner) makeEE(conf signer.Configuration, keyTpl interface{}) (err error) {
	// we didn't get a key, let's make a new one
	var tx *sql.Tx
	if s.db != nil {
		// if a db is present, first create a db transaction to lock the row for update
		tx, err = s.db.Begin()
		if err != nil {
			err = errors.Wrapf(err, "failed to create transaction to update end entity for signer %q", s.ID)
		}
		// lock the table
		_, err = tx.Exec("SELECT * FROM endentities FOR UPDATE")
		if err != nil {
			err = errors.Wrap(err, "failed to lock endentities table for update")
		}
	}
	// create a label and generate the key
	s.eeLabel = fmt.Sprintf("%s-%s", s.ID, time.Now().UTC().Format("20060102"))
	s.eePriv, s.eePub, err = conf.MakeKey(keyTpl, s.eeLabel)
	if err != nil {
		err = errors.Wrap(err, "failed to generate key for end entity")
		return
	}
	if s.db != nil {
		// if a db is present, insert the label into a new row of the endentities table
		_, err = tx.Exec(`INSERT INTO endentities(label, signer_id, is_current, created_at)
					VALUES ($1, $2, $3, $4)`, s.eeLabel, s.ID, true, time.Now().UTC())
		if err != nil {
			tx.Rollback()
			err = errors.Wrap(err, "failed to insert key into database")
			return
		}
		// mark all other keys for this signer as no longer current
		_, err = tx.Exec("UPDATE endentities SET is_current=FALSE WHERE signer_id=$1 and label!=$2",
			s.ID, s.eeLabel)
		if err != nil {
			err = errors.Wrap(err, "failed to update is_current status of other keys in database")
			tx.Rollback()
			return
		}
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "failed to commit transaction in database")
			tx.Rollback()
			return
		}
	}
	return
}

// makeChainAndX5U makes a certificate using the end-entity public key,
// uploads the chain to its destination and creates an X5U download URL
func (s *ContentSigner) makeChainAndX5U() (err error) {
	var fullChain, chainName string
	fullChain, chainName, err = s.makeChain()
	if err != nil {
		return errors.Wrap(err, "failed to make chain")
	}
	err = s.upload(fullChain, chainName)
	if err != nil {
		return errors.Wrap(err, "failed to upload chain")
	}
	newX5U := s.X5U + chainName
	err = verifyX5U(newX5U)
	if err != nil {
		return errors.Wrap(err, "failed to download new chain")
	}
	s.db.UpdateX5U(newX5U, s.eeLabel, s.ID)
	s.X5U = newX5U
	return
}

// makeChain issues an end-entity certificate using the ca private key and the first
// cert of the chain (which is supposed to match the ca private key).  it
// returns the entire chain of certificate, its name (based on the ee cn &
// expiration) and an error.
func (s *ContentSigner) makeChain() (chain string, name string, err error) {
	cn := s.ID + CSNameSpace

	// cert is backdated to allow for clock skew tolerance
	notBefore := time.Now().UTC().Add(-s.clockSkewTolerance)

	// cert will be in used for `validity` number of days, but will remain
	// valid for longer than that to account for clock skew
	notAfter := time.Now().UTC().Add(s.validity + s.clockSkewTolerance)

	// the issuer is the first cert in the chain
	block, _ := pem.Decode([]byte(s.PublicKey))
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse issuer certificate from chain")
		return
	}

	crtTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"Mountain View"},
		},
		DNSNames:           []string{cn},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SignatureAlgorithm: issuer.SignatureAlgorithm,
		IsCA:               false,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		KeyUsage:           x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, crtTpl, issuer, s.eePub, s.issuerPriv)
	if err != nil {
		err = errors.Wrap(err, "failed to issue end-entity cert")
		return
	}

	var certPem bytes.Buffer
	err = pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		err = errors.Wrap(err, "failed to PEM encode end-entity cert")
		return
	}

	// verify the chain by making 2 cert pools, one for the root ca
	// and one for the intermediate, then verifying the cert chain
	root := x509.NewCertPool()
	ok := root.AppendCertsFromPEM([]byte(s.caCert))
	if !ok {
		err = errors.New("failed to load root cert")
		return
	}
	inter := x509.NewCertPool()
	inter.AddCert(issuer)
	opts := x509.VerifyOptions{
		Roots:         root,
		Intermediates: inter,
		KeyUsages:     crtTpl.ExtKeyUsage,
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		err = errors.Wrap(err, "failed to parse end-entity certificate")
		return
	}
	_, err = cert.Verify(opts)
	if err != nil {
		err = errors.Wrap(err, "failed to verify certificate")
		return
	}

	// return a chain with the EE cert first then the issuers
	chain = certPem.String() + s.PublicKey + s.caCert
	name = fmt.Sprintf("%s-%s.chain", cert.Subject.CommonName, cert.NotAfter.Format("20060102"))
	return
}
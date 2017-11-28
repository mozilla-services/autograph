// Package pkcs7 implements parsing and generation of some PKCS#7 structures.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"

	_ "crypto/sha1" // for crypto.SHA1
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
// and Enveloped Data are supported (1.2.840.113549.1.7.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	// Signed Data OIDs
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	oidDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signature Algorithms
	oidEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEncryptionAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	oidEncryptionAlgorithmDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidDigestAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Encryption Algorithms
	oidEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidEncryptionAlgorithmAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidEncryptionAlgorithmAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1), oid.Equal(oidDigestAlgorithmECDSASHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidDigestAlgorithmSHA256), oid.Equal(oidDigestAlgorithmECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestAlgorithmSHA384), oid.Equal(oidDigestAlgorithmECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidDigestAlgorithmSHA512), oid.Equal(oidDigestAlgorithmECDSASHA512):
		return crypto.SHA512, nil
	}
	return crypto.Hash(0), ErrUnsupportedAlgorithm
}

// getDigestOIDForSignatureAlgorithm takes an x509.SignatureAlgorithm
// and returns the corresponding OID digest algorithm
//
// FIXME: disabled because of bug 1357815 in sign.go
//
//func getDigestOIDForSignatureAlgorithm(digestAlg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
//	switch digestAlg {
//	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
//		return oidDigestAlgorithmSHA1, nil
//	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
//		return oidDigestAlgorithmSHA256, nil
//	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
//		return oidDigestAlgorithmSHA384, nil
//	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
//		return oidDigestAlgorithmSHA512, nil
//	}
//	return nil, fmt.Errorf("pkcs7: cannot convert hash to oid, unknown hash algorithm")
//}

// getOIDForEncryptionAlgorithm takes the private key type of the signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func getOIDForEncryptionAlgorithm(pkey interface{}, oidDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	key, ok := pkey.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkcs7: private key does not implement crypto.Signer")
	}

	pub := key.Public()

	switch pub.(type) {
	case *rsa.PublicKey:
		switch {
		default:
			return oidEncryptionAlgorithmRSA, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA1):
			return oidEncryptionAlgorithmRSASHA1, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA256):
			return oidEncryptionAlgorithmRSASHA256, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA384):
			return oidEncryptionAlgorithmRSASHA384, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA512):
			return oidEncryptionAlgorithmRSASHA512, nil
		}
	case *ecdsa.PublicKey:
		switch {
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA1):
			return oidDigestAlgorithmECDSASHA1, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA256):
			return oidDigestAlgorithmECDSASHA256, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA384):
			return oidDigestAlgorithmECDSASHA384, nil
		case oidDigestAlg.Equal(oidDigestAlgorithmSHA512):
			return oidDigestAlgorithmECDSASHA512, nil
		}
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown public key type %T", pub)

}

// Parse decodes a DER encoded PKCS7 package
func Parse(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}
	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(oidSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	case info.ContentType.Equal(oidEncryptedData):
		return parseEncryptedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

func parseEncryptedData(data []byte) (*PKCS7, error) {
	var ed encryptedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

func (raw rawCertificates) Parse() ([]*x509.Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

package contentsignature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// helper funcs  -----------------------------------------------------------------

func mustPEMToCert(s string) *x509.Certificate {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		log.Fatalf("Failed to parse certificate PEM")
	}
	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Could not parse X.509 certificate: %v", err)
	}
	return certX509
}

func mustPEMToECKey(s string) *ecdsa.PrivateKey {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		log.Fatalf("Failed to parse EC key PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Could not parse EC key: %q", err)
	}
	return key
}

// mustParseChain
func mustParseChain(chain string) (certs []*x509.Certificate) {
	certs, err := ParseChain([]byte(chain))
	if err != nil {
		log.Fatalf("error parsing chain: %q", err)
	}
	return certs
}

func mustCertsToChain(certs []*x509.Certificate) (chain []byte) {
	for _, cert := range certs {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return chain
}

// mustParseUTC
func mustParseUTC(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Fatalf("error parsing time: %q", err)
	}
	return ts
}

type signOptions struct {
	commonName                  string
	extKeyUsages                []x509.ExtKeyUsage
	keyUsage                    x509.KeyUsage
	privateKey                  *ecdsa.PrivateKey
	publicKey                   crypto.PublicKey
	isCA                        bool
	issuer                      *x509.Certificate
	notBefore                   time.Time
	notAfter                    time.Time
	permittedDNSDomainsCritical bool
	permittedDNSDomains         []string
	DNSNames                    []string
}

func signTestCert(options signOptions) *x509.Certificate {
	var (
		issuer = options.issuer
	)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:       []string{"Mozilla"},
			OrganizationalUnit: []string{"Cloud Services Autograph Unit Testing"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Mountain View"},
			CommonName:         options.commonName,
		},
		DNSNames:                    options.DNSNames,
		NotBefore:                   options.notBefore,
		NotAfter:                    options.notAfter,
		SignatureAlgorithm:          x509.ECDSAWithSHA384,
		IsCA:                        options.isCA,
		BasicConstraintsValid:       true,
		ExtKeyUsage:                 options.extKeyUsages,
		KeyUsage:                    options.keyUsage,
		PermittedDNSDomainsCritical: options.permittedDNSDomainsCritical,
		PermittedDNSDomains:         options.permittedDNSDomains,
	}
	if options.issuer == nil {
		issuer = certTpl
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTpl, issuer, options.publicKey, options.privateKey)
	if err != nil {
		log.Fatalf("Could not self sign an X.509 root certificate: %v", err)
	}
	certX509, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Could not parse X.509 certificate: %v", err)
	}
	return certX509
}

func sha2Fingerprint(cert *x509.Certificate) string {
	return strings.ToUpper(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
}

func generateTestKey() *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Could not generate private key: %v", err)
	}
	return priv
}

func generateTestRSAKey() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatalf("Could not generate private key: %v", err)
	}
	return priv
}

// fixtures -----------------------------------------------------------------

const normandyDev2021Roothash = `4C:35:B1:C3:E3:12:D9:55:E7:78:ED:D0:A7:E7:8A:38:83:04:EF:01:BF:FA:03:29:B2:46:9F:3C:C5:EC:36:04`

// firefoxPkiStageRoot is the CA root cert for the Addon stage code
// signing PKI
const firefoxPkiStageRoot = `-----BEGIN CERTIFICATE-----
MIIHYzCCBUugAwIBAgIBATANBgkqhkiG9w0BAQwFADCBqDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
ZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWduaW5n
LnJvb3QuY2ExMDAuBgkqhkiG9w0BCQEWIW9wc2VjK3N0YWdlcm9vdGFkZG9uc0Bt
b3ppbGxhLmNvbTAeFw0xNTAyMTAxNTI4NTFaFw0yNTAyMDcxNTI4NTFaMIGoMQsw
CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE0FkZG9ucyBUZXN0IFNpZ25pbmcxJDAiBgNVBAMTG3Rlc3QuYWRk
b25zLnNpZ25pbmcucm9vdC5jYTEwMC4GCSqGSIb3DQEJARYhb3BzZWMrc3RhZ2Vy
b290YWRkb25zQG1vemlsbGEuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAv/OSHh5uUMMKKuBh83kikuJ+BW4fQCHVZvADZh2qHNH8pSaME/YqMItP
5XQ1N5oLq1tRQO77AKn+eYPDAQkg+9VV+ct4u76YctcU/gvjieGKQ0fvuDH18QLD
hqa4DHgDmpCa/w+Eqzd54HaFj7ew9Bb7GZPHuZfk7Ct9fcN6kHneEj3KeuLiqzSV
VCRFV9RTlrUdsc1/VwF4A97JTXc3HJeWJO3azOlFpaJ8QHhmgXLLmB59HPeZ10Sf
9QwVGaKcn7yLuwtIA+wDhs8iwGZWcgmknW4DkkRDbQo7L+//4kVK+Yqq0HamZArm
vE4xENvbwOze4XYkCO3PwgmCotU7K5D3sMUUxkOaodlemO9OqRW8vJOJH3b6mhST
aunQR9/GOJ7sl4egrn2fOVZhBvM29lyBCKBffeQgtIMcKpeEKa4TNx4nTrWu1J9k
jHlvNeVL3FzMzJXRPl0RV71cYak+G6GnQ4fg3+4ZSSPxTvbwRJAO2xajkURxFSZo
sXcjYG8iPTSrDazj4LN2+882t4Q2/rMYpkowwLGbvJqHiw2tg9/hpLn1K4W18vcC
vFgzNRrTdKaJ/KjD17eJl8s8oPA7TiophPeezy1WzAc4mdlXS6A85b0mKDDU2A/4
3YmltjsSmizR2LnfeNs125EsCWxSUrAsnUYRO+lJOyNr7GGKGscCAwZVN6OCAZQw
ggGQMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB/wQMMAoG
CCsGAQUFBwMDMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0
aWZpY2F0ZTAzBglghkgBhvhCAQQEJhYkaHR0cDovL2FkZG9ucy5tb3ppbGxhLm9y
Zy9jYS9jcmwucGVtMB0GA1UdDgQWBBSE6l/Nb0ySL+rR9PXIo7LCDLqm9jCB1QYD
VR0jBIHNMIHKgBSE6l/Nb0ySL+rR9PXIo7LCDLqm9qGBrqSBqzCBqDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYD
VQQKExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5z
aWduaW5nLnJvb3QuY2ExMDAuBgkqhkiG9w0BCQEWIW9wc2VjK3N0YWdlcm9vdGFk
ZG9uc0Btb3ppbGxhLmNvbYIBATANBgkqhkiG9w0BAQwFAAOCAgEAck21RaAcTzbT
vmqqcCezBd5Gej6jV53HItXfF06tLLzAxKIU1loLH/330xDdOGyiJdvUATDVn8q6
5v4Kae2awON6ytWZp9b0sRdtlLsRo8EWOoRszCqiMWdl1gnGMaV7e2ycz/tR+PoK
GxHCh8rbOtG0eiVJIyRijLDjtExW8Eg+uz6Zkg1IWXqInj7Gqr23FOqD76uAfE82
YTWW3lzxpP3gL7pmV5G7ob/tIyAfrPEB4w0Nt2HEl9h7NDtKPMprrOLPkrI9eAVU
QeeI3RpAKnXOFQkqPYPXIlAaJ6qxtYa6tWHOqRyS1xKnvy/uWjEtU3tYJ5eUL1+2
vzNTdakJgkZDRdDNg0V3NYwza6BwL80VPSfqc1H6R8CU1uj+kjTlCEsoTPLeW7k5
t+lKHFMj0HZLNymgDD5f9UpI7yiOAIF0z4WKAMv/f12vnAPwmOPuOikRNOv0nNuL
RIpKO53Cd7aV5PdB0pNSPNjc6V+5IPrepALNQhKIpzoHA4oG+LlVVy4R3csPcj4e
zQQ9gt3NC2OXF4hveHfKZdCnb+BBl4S71QMYYCCTe+EDCsIGuyXWD/K2hfLD8TPW
thPX5WNsS8bwno2ccqncVLQ4PZxOIB83DFBFmAvTuBiAYWq874rneTXqInHyeCq+
819l9s72pDsFaGevmm0Us9bYuufTS5U=
-----END CERTIFICATE-----`

// firefoxPkiContentSignatureStageRootHash is the SHA2 hash of the
// firefoxPkiContentSignatureStageRoot cert raw bytes
const firefoxPkiContentSignatureStageRootHash = `3C:01:44:6A:BE:90:36:CE:A9:A0:9A:CA:A3:A5:20:AC:62:8F:20:A7:AE:32:CE:86:1C:B2:EF:B7:0F:A0:C7:45`

// firefoxPkiContentSignatureStageRoot is the CA root cert for the
// content signature stage code signing PKI
const firefoxPkiContentSignatureStageRoot = `-----BEGIN CERTIFICATE-----
MIIHbDCCBVSgAwIBAgIEYCWYOzANBgkqhkiG9w0BAQwFADCBqTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQK
ExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWdu
aW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytzdGFnZXJvb3RhZGRv
bnNAbW96aWxsYS5jb20wHhcNMjEwMjExMjA0ODU5WhcNMjQxMTE0MjA0ODU5WjCB
qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBW
aWV3MRwwGgYDVQQKExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0
LmFkZG9ucy5zaWduaW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytz
dGFnZXJvb3RhZGRvbnNAbW96aWxsYS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDKRVty/FRsO4Ech6EYleyaKgAueaLYfMSsAIyPC/N8n/P8QcH8
rjoiMJrKHRlqiJmMBSmjUZVzZAP0XJku0orLKWPKq7cATt+xhGY/RJtOzenMMsr5
eN02V3GzUd1jOShUpERjzXdaO3pnfZqhdqNYqP9ocqQpyno7bZ3FZQ2vei+bF52k
51uPioTZo+1zduoR/rT01twGtZm3QpcwU4mO74ysyxxgqEy3kpojq8Nt6haDwzrj
khV9M6DGPLHZD71QaUiz5lOhD9CS8x0uqXhBhwMUBBkHsUDSxbN4ZhjDDWpCmwaD
OtbJMUJxDGPCr9qj49QESccb367OeXLrfZ2Ntu/US2Bw9EDfhyNsXr9dg9NHj5yf
4sDUqBHG0W8zaUvJx5T2Ivwtno1YZLyJwQW5pWeWn8bEmpQKD2KS/3y2UjlDg+YM
NdNASjFe0fh6I5NCFYmFWA73DpDGlUx0BtQQU/eZQJ+oLOTLzp8d3dvenTBVnKF+
uwEmoNfZwc4TTWJOhLgwxA4uK+Paaqo4Ap2RGS2ZmVkPxmroB3gL5n3k3QEXvULh
7v8Psk4+MuNWnxudrPkN38MGJo7ju7gDOO8h1jLD4tdfuAqbtQLduLXzT4DJPA4y
JBTFIRMIpMqP9CovaS8VPtMFLTrYlFh9UnEGpCeLPanJr+VEj7ae5sc8YwIDAQAB
o4IBmDCCAZQwDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwMwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVk
IENlcnRpZmljYXRlMDMGCWCGSAGG+EIBBAQmFiRodHRwOi8vYWRkb25zLm1vemls
bGEub3JnL2NhL2NybC5wZW0wHQYDVR0OBBYEFIbYNBxOWNETXJlf2EKY7RQPGfJd
MIHZBgNVHSMEgdEwgc6AFIbYNBxOWNETXJlf2EKY7RQPGfJdoYGvpIGsMIGpMQsw
CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE0FkZG9ucyBUZXN0IFNpZ25pbmcxJDAiBgNVBAMTG3Rlc3QuYWRk
b25zLnNpZ25pbmcucm9vdC5jYTExMC8GCSqGSIb3DQEJARYic2Vjb3BzK3N0YWdl
cm9vdGFkZG9uc0Btb3ppbGxhLmNvbYIEYCWYOzANBgkqhkiG9w0BAQwFAAOCAgEA
nowyJv8UaIV7NA0B3wkWratq6FgA1s/PzetG/ZKZDIW5YtfUvvyy72HDAwgKbtap
Eog6zGI4L86K0UGUAC32fBjE5lWYEgsxNM5VWlQjbgTG0dc3dYiufxfDFeMbAPmD
DzpIgN3jHW2uRqa/MJ+egHhv7kGFL68uVLboqk/qHr+SOCc1LNeSMCuQqvHwwM0+
AU1GxhzBWDkealTS34FpVxF4sT5sKLODdIS5HXJr2COHHfYkw2SW/Sfpt6fsOwaF
2iiDaK4LPWHWhhIYa6yaynJ+6O6KPlpvKYCChaTOVdc+ikyeiSO6AakJykr5Gy7d
PkkK7MDCxuY6psHj7iJQ59YK7ujQB8QYdzuXBuLLo5hc5gBcq3PJs0fLT2YFcQHA
dj+olGaDn38T0WI8ycWaFhQfKwATeLWfiQepr8JfoNlC2vvSDzGUGfdAfZfsJJZ8
5xZxahHoTFGS0mDRfXqzKH5uD578GgjOZp0fULmzkcjWsgzdpDhadGjExRZFKlAy
iKv8cXTONrGY0fyBDKennuX0uAca3V0Qm6v2VRp+7wG/pywWwc5n+04qgxTQPxgO
6pPB9UUsNbaLMDR5QPYAWrNhqJ7B07XqIYJZSwGP5xB9NqUZLF4z+AOMYgWtDpmg
IKdcFKAt3fFrpyMhlfIKkLfmm0iDjmfmIXbDGBJw9SE=
-----END CERTIFICATE-----`

// firefoxPkiProdRootHash is the SHA2 hash of the firefoxPkiProdRoot
// cert raw bytes
const firefoxPkiProdRootHash = `97:E8:BA:9C:F1:2F:B3:DE:53:CC:42:A4:E6:57:7E:D6:4D:F4:93:C2:47:B4:14:FE:A0:36:81:8D:38:23:56:0E`

// firefoxPkiProdRoot is the CA root cert for the Content Signature
// and Addon prod code signing PKI
const firefoxPkiProdRoot = `-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`

// P384ECDSA test signer from signer/contentsignature/contentsignature_test.go TestSign
const testSignerP384PEM = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
/5Cp6z37rpp781N4haUOIauM14P4KUw=
-----END EC PRIVATE KEY-----`

var (
	badPEMContent = strings.Replace(testSignerP384PEM, "EC PRIVATE KEY", "CERTIFICATE", -1)

	testRootKey    = generateTestKey()
	testInterKey   = generateTestKey()
	testLeafKey    = mustPEMToECKey(testSignerP384PEM)
	testLeafRSAKey = generateTestRSAKey()
	testRoot       = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(-3 * 24 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})
	testRootExpired = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(-time.Hour),
	})
	testRootNotYetValid = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		keyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now().Add(2 * time.Hour),
		notAfter:     time.Now().Add(4 * time.Hour),
	})
	testInter = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRoot,
		notBefore:                   time.Now().Add(-2 * 24 * time.Hour),
		notAfter:                    time.Now().Add(time.Hour),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})
	testInterExpired = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRoot,
		notBefore:                   time.Now().Add(-2 * time.Hour),
		notAfter:                    time.Now().Add(-time.Hour),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})
	testInterNotYetValid = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRoot,
		notBefore:                   time.Now().Add(2 * time.Hour),
		notAfter:                    time.Now().Add(4 * time.Hour),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})
	testLeaf = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})
	testLeafExpired = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(-time.Hour),
	})
	testLeafNotYetValid = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(2 * time.Hour),
		notAfter:     time.Now().Add(4 * time.Hour),
	})
	testLeafInvalidDNSName = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})
	testLeafRSAPub = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafRSAKey.PublicKey,
		isCA:         false,
		issuer:       testInter,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})

	testRootNonCA = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         false,
		issuer:       nil, // self-sign
		notBefore:    time.Now(),
		notAfter:     time.Now().Add(time.Hour),
	})
	testInterNonCA = signTestCert(signOptions{
		commonName:                  "autograph unit test content signing intermediate",
		extKeyUsages:                []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		privateKey:                  testRootKey,
		publicKey:                   &testInterKey.PublicKey,
		isCA:                        true,
		issuer:                      testRootNonCA,
		notBefore:                   time.Now().Add(-2 * 24 * time.Hour),
		notAfter:                    time.Now().Add(time.Hour),
		permittedDNSDomainsCritical: true,
		permittedDNSDomains:         []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	})
	testLeafNonCA = signTestCert(signOptions{
		commonName:   "example.content-signature.mozilla.org",
		DNSNames:     []string{"example.content-signature.mozilla.org"},
		extKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		keyUsage:     x509.KeyUsageDigitalSignature,
		privateKey:   testInterKey,
		publicKey:    &testLeafKey.PublicKey,
		isCA:         false,
		issuer:       testInterNonCA,
		notBefore:    time.Now().Add(-2 * time.Hour),
		notAfter:     time.Now().Add(time.Hour),
	})

	testRootNoExt = signTestCert(signOptions{
		commonName:   "autograph unit test self-signed root",
		extKeyUsages: []x509.ExtKeyUsage{},
		privateKey:   testRootKey,
		publicKey:    &testRootKey.PublicKey,
		isCA:         true,
		issuer:       nil, // self-sign
		notBefore:    time.Now(),
		notAfter:     time.Now().Add(time.Hour),
	})
)

// This chain has an expired end-entity certificate
var ExpiredEndEntityChain = `-----BEGIN CERTIFICATE-----
MIIEnTCCBCSgAwIBAgIEAQAAFzAKBggqhkjOPQQDAzCBpjELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMSUwIwYDVQQDExxDb250ZW50
IFNpZ25pbmcgSW50ZXJtZWRpYXRlMSEwHwYJKoZIhvcNAQkBFhJmb3hzZWNAbW96
aWxsYS5jb20wHhcNMTcwNTA5MTQwMjM3WhcNMTcxMTA3MTQwMjM3WjCBrzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEg
Q29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZu
b3JtYW5keS5jb250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3
DQEJARYUc2VjdXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAShRFsGyg6DkUX+J2mMDM6cLK8V6HawjGVlQ/w5H5fHiGJDMrkl4ktnN+O37mSs
dReHcVxxpPNEpIfkWQ2TFmJgOUzqi/CzO06APlAJ9mnIcaobgdqRQxoTchFEyzUx
nTijggIWMIICEjAdBgNVHQ4EFgQUKnGLJ9po8ea5qUNjJyV/c26VZfswgaoGA1Ud
IwSBojCBn4AUiHVymVvwUPJguD2xCZYej3l5nu6hgYGkfzB9MQswCQYDVQQGEwJV
UzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxs
YSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3Qt
Y2EtcHJvZHVjdGlvbi1hbW+CAxAABjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBFBgNVHR8EPjA8MDqgOKA2hjRo
dHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNkbi5tb3ppbGxhLm5ldC9jYS9jcmwu
cGVtMEMGCWCGSAGG+EIBBAQ2FjRodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNk
bi5tb3ppbGxhLm5ldC9jYS9jcmwucGVtME8GCCsGAQUFBwEBBEMwQTA/BggrBgEF
BQcwAoYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5jZG4ubW96aWxsYS5uZXQv
Y2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQtc2lnbmF0dXJl
Lm1vemlsbGEub3JnMAoGCCqGSM49BAMDA2cAMGQCMGeeyXYM3+r1fcaXzd90PwGb
h9nrl1fZNXrCu17lCPn2JntBVh7byT3twEbr+Hmv8gIwU9klAW6yHLG/ZpAZ0jdf
38Rciz/FDEAdrzH2QlYAOw+uDdpcmon9oiRgIxzwNlUe
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFfjCCA2agAwIBAgIDEAAGMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYTAlVT
MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3ppbGxh
IEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMWcm9vdC1j
YS1wcm9kdWN0aW9uLWFtbzAeFw0xNzA1MDQwMDEyMzlaFw0xOTA1MDQwMDEyMzla
MIGmMQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEv
MC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2Ux
JTAjBgNVBAMTHENvbnRlbnQgU2lnbmluZyBJbnRlcm1lZGlhdGUxITAfBgkqhkiG
9w0BCQEWEmZveHNlY0Btb3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IA
BMCmt4C33KfMzsyKokc9SXmMSxozksQglhoGAA1KjlgqEOzcmKEkxtvnGWOA9FLo
A6U7Wmy+7sqmvmjLboAPQc4G0CEudn5Nfk36uEqeyiyKwKSAT+pZsqS4/maXIC7s
DqOCAYkwggGFMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB
/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSIdXKZW/BQ8mC4PbEJlh6PeXme7jCB
qAYDVR0jBIGgMIGdgBSzvOpYdKvhbngqsqucIx6oYyyXt6GBgaR/MH0xCzAJBgNV
BAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZN
b3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMW
cm9vdC1jYS1wcm9kdWN0aW9uLWFtb4IBATAzBglghkgBhvhCAQQEJhYkaHR0cDov
L2FkZG9ucy5hbGxpem9tLm9yZy9jYS9jcmwucGVtME4GA1UdHgRHMEWgQzAggh4u
Y29udGVudC1zaWduYXR1cmUubW96aWxsYS5vcmcwH4IdY29udGVudC1zaWduYXR1
cmUubW96aWxsYS5vcmcwDQYJKoZIhvcNAQEMBQADggIBAKWhLjJB8XmW3VfLvyLF
OOUNeNs7Aju+EZl1PMVXf+917LB//FcJKUQLcEo86I6nC3umUNl+kaq4d3yPDpMV
4DKLHgGmegRsvAyNFQfd64TTxzyfoyfNWH8uy5vvxPmLvWb+jXCoMNF5FgFWEVon
5GDEK8hoHN/DMVe0jveeJhUSuiUpJhMzEf6Vbo0oNgfaRAZKO+VOY617nkTOPnVF
LSEcUPIdE8pcd+QP1t/Ysx+mAfkxAbt+5K298s2bIRLTyNUj1eBtTcCbBbFyWsly
rSMkJihFAWU2MVKqvJ74YI3uNhFzqJ/AAUAPoet14q+ViYU+8a1lqEWj7y8foF3r
m0ZiQpuHULiYCO4y4NR7g5ijj6KsbruLv3e9NyUAIRBHOZEKOA7EiFmWJgqH1aZv
/eS7aQ9HMtPKrlbEwUjV0P3K2U2ljs0rNvO8KO9NKQmocXaRpLm+s8PYBGxby92j
5eelLq55028BSzhJJc6G+cRT9Hlxf1cg2qtqcVJa8i8wc2upCaGycZIlBSX4gj/4
k9faY4qGuGnuEdzAyvIXWMSkb8jiNHQfZrebSr00vShkUEKOLmfFHbkwIaWNK0+2
2c3RL4tDnM5u0kvdgWf0B742JskkxqqmEeZVofsOZJLOhXxO9NO/S0hM16/vf/tl
Tnsnhv0nxUR0B9wxN7XmWmq4
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`

// NB: these certs do no exactly match the result of parsing
// ExpiredEndEntityChain
var ExpiredEndEntityChainCerts = []*x509.Certificate{
	{
		Subject: pkix.Name{
			CommonName:         "normandy.content-signature.mozilla.org",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2017-05-09T14:02:37Z"),
		NotAfter:  mustParseUTC("2017-11-07T14:02:37Z"),
		IsCA:      false,
		DNSNames:  []string{"normandy.content-signature.mozilla.org"},
		KeyUsage:  x509.KeyUsageDigitalSignature,
	},
	{
		Subject: pkix.Name{
			CommonName:         "Content Signing Intermediate",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Mozilla AMO Production Signing Service"},
			Country:            []string{"US"},
			Province:           nil,
			Locality:           nil,
		},
		NotBefore:           mustParseUTC("2017-05-04T00:12:39Z"),
		NotAfter:            mustParseUTC("2019-05-04T00:12:39Z"),
		IsCA:                true,
		DNSNames:            nil,
		KeyUsage:            x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains: []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	},
	{
		Subject: pkix.Name{
			CommonName:         "root-ca-production-amo",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Mozilla AMO Production Signing Service"},
			Country:            []string{"US"},
			Province:           nil,
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2015-03-17T22:53:57Z"),
		NotAfter:  mustParseUTC("2025-03-14T22:53:57Z"),
		IsCA:      true,
		DNSNames:  nil,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	},
}

// This chain is in the wrong order: the intermediate cert is
// placed first, followed by the EE then the root
var WronglyOrderedChain = `
-----BEGIN CERTIFICATE-----
MIIFfzCCA2egAwIBAgIDEAAJMA0GCSqGSIb3DQEBDAUAMH0xCzAJBgNVBAYTAlVT
MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZNb3ppbGxh
IEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTEfMB0GA1UEAxMWcm9vdC1j
YS1wcm9kdWN0aW9uLWFtbzAiGA8yMDIwMTIzMTAwMDAwMFoYDzIwMjUwMzE0MjI1
MzU3WjCBozELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRp
b24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2
aWNlMUUwQwYDVQQDDDxDb250ZW50IFNpZ25pbmcgSW50ZXJtZWRpYXRlL2VtYWls
QWRkcmVzcz1mb3hzZWNAbW96aWxsYS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAQklaclq89BKPcYIfUdVS4JF/pZxjTVOlYVdj4QJ5xopHAngXkUggYkkHj0tmZV
EcrXrCVq1qEtB/k7wXXkU4HN9rX7WcUkksClDJmUQ2qabzP7i20q3epGNq57RE2p
3hKjggGJMIIBhTAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUB
Af8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUoB1KF0+Mwis1RfFj8dpwcKfO+OEw
gagGA1UdIwSBoDCBnYAUs7zqWHSr4W54KrKrnCMeqGMsl7ehgYGkfzB9MQswCQYD
VQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMm
TW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMT
FnJvb3QtY2EtcHJvZHVjdGlvbi1hbW+CAQEwMwYJYIZIAYb4QgEEBCYWJGh0dHA6
Ly9hZGRvbnMuYWxsaXpvbS5vcmcvY2EvY3JsLnBlbTBOBgNVHR4ERzBFoEMwIIIe
LmNvbnRlbnQtc2lnbmF0dXJlLm1vemlsbGEub3JnMB+CHWNvbnRlbnQtc2lnbmF0
dXJlLm1vemlsbGEub3JnMA0GCSqGSIb3DQEBDAUAA4ICAQALeUuF/7hcmM/LFnK6
6a5lBQk5z5JBr2bNNvKVs/mtdIcVKcxjWxOBM5rorZiM5UWE7BmAm8E7gFCCq30y
ZnNn6BO04z5LtDRHxa3IGhgECloyOJUSi9xxFxe5p5wJzFdArl7happSOUwOi+z2
aDqS6uTJWubIY4Uz7h7S2UkUm52CTYnvpioS7eQoovvrlUsgIhkkIwDQnu7RWSej
6nkc5o5SNwAJWsQvxIko32AxhvPmmtv1T/mtXY488TJ0VoBZ6lRkJJIxIJ48pGHJ
+YRt1tzO2aqCEs9pNPGWfhrpcDc2mu4fvlSX1elWYiGrpQBVbdEJlDkGAD0AC8on
/7ybD2pEdh7pViVLV78Md+DNNquqqNhRJpn65k4lhvgDLHYvLNOrrtAmcmQonNdU
OSumIuqcGk7dm/7gr9lrwAm8V8/GwDyzTgi4wNA4vwln3c7iMFGLL/b2piEQCSl+
mqL1LeWJV+8rkbi8l2T0QIBwjDgR97ZxpLPwmUdDNiGAWeEFxn0jU9CQtQKjOj84
VPZUM7aSHhVQ0bQpnjua7IWvLKK7F2fOo3PmuLacnnfyrzr2C/Le5k6EK/0q2cKf
P6JzDWwt8werc6E3C6z3jbUdAwgNpv/fGz8gQBPf7NeiYkqMUNB2Z3aF8He8Jg15
Abv+2+rSOLpBsTU67AHzMKJ8hw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEnTCCBCSgAwIBAgIEAQAAFzAKBggqhkjOPQQDAzCBpjELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMSUwIwYDVQQDExxDb250ZW50
IFNpZ25pbmcgSW50ZXJtZWRpYXRlMSEwHwYJKoZIhvcNAQkBFhJmb3hzZWNAbW96
aWxsYS5jb20wHhcNMTcwNTA5MTQwMjM3WhcNMTcxMTA3MTQwMjM3WjCBrzELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEg
Q29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZu
b3JtYW5keS5jb250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3
DQEJARYUc2VjdXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAShRFsGyg6DkUX+J2mMDM6cLK8V6HawjGVlQ/w5H5fHiGJDMrkl4ktnN+O37mSs
dReHcVxxpPNEpIfkWQ2TFmJgOUzqi/CzO06APlAJ9mnIcaobgdqRQxoTchFEyzUx
nTijggIWMIICEjAdBgNVHQ4EFgQUKnGLJ9po8ea5qUNjJyV/c26VZfswgaoGA1Ud
IwSBojCBn4AUiHVymVvwUPJguD2xCZYej3l5nu6hgYGkfzB9MQswCQYDVQQGEwJV
UzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxs
YSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3Qt
Y2EtcHJvZHVjdGlvbi1hbW+CAxAABjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQE
AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBFBgNVHR8EPjA8MDqgOKA2hjRo
dHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNkbi5tb3ppbGxhLm5ldC9jYS9jcmwu
cGVtMEMGCWCGSAGG+EIBBAQ2FjRodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmNk
bi5tb3ppbGxhLm5ldC9jYS9jcmwucGVtME8GCCsGAQUFBwEBBEMwQTA/BggrBgEF
BQcwAoYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5jZG4ubW96aWxsYS5uZXQv
Y2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQtc2lnbmF0dXJl
Lm1vemlsbGEub3JnMAoGCCqGSM49BAMDA2cAMGQCMGeeyXYM3+r1fcaXzd90PwGb
h9nrl1fZNXrCu17lCPn2JntBVh7byT3twEbr+Hmv8gIwU9klAW6yHLG/ZpAZ0jdf
38Rciz/FDEAdrzH2QlYAOw+uDdpcmon9oiRgIxzwNlUe
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`

// NB: these certs do no exactly match the result of parsing
// WronglyOrderedChain
var WronglyOrderedChainCerts = []*x509.Certificate{
	{
		Subject: pkix.Name{
			CommonName:         "Content Signing Intermediate/emailAddress=foxsec@mozilla.com",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Mozilla AMO Production Signing Service"},
			Country:            []string{"US"},
			Province:           nil,
			Locality:           nil,
		},
		NotBefore:           mustParseUTC("2020-12-31T00:00:00Z"),
		NotAfter:            mustParseUTC("2025-03-14T22:53:57Z"),
		IsCA:                true,
		DNSNames:            nil,
		KeyUsage:            x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains: []string{".content-signature.mozilla.org", "content-signature.mozilla.org"},
	},
	{
		Subject: pkix.Name{
			CommonName:         "normandy.content-signature.mozilla.org",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2017-05-09T14:02:37Z"),
		NotAfter:  mustParseUTC("2017-11-07T14:02:37Z"),
		IsCA:      false,
		DNSNames:  []string{"normandy.content-signature.mozilla.org"},
		KeyUsage:  x509.KeyUsageDigitalSignature,
	},
	{
		Subject: pkix.Name{
			CommonName:         "root-ca-production-amo",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Mozilla AMO Production Signing Service"},
			Country:            []string{"US"},
			Province:           nil,
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2015-03-17T22:53:57Z"),
		NotAfter:  mustParseUTC("2025-03-14T22:53:57Z"),
		IsCA:      true,
		DNSNames:  nil,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	},
}

var NormandyDevChain2021Intermediate = `-----BEGIN CERTIFICATE-----
MIIHijCCBXKgAwIBAgIEAQAABDANBgkqhkiG9w0BAQwFADCBvzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSYwJAYDVQQK
Ex1Db250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEmMCQGA1UEAxMdZGV2LmNv
bnRlbnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG9w0BCQEWLGNsb3Vkc2Vj
K2RldnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEuY29tMB4XDTE2MDcwNjIx
NDkyNloXDTIxMDcwNTIxNDkyNlowazELMAkGA1UEBhMCVVMxEDAOBgNVBAoTB0Fs
bGl6b20xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMTEwLwYDVQQDEyhEZXZ6aWxs
YSBTaWduaW5nIFNlcnZpY2VzIEludGVybWVkaWF0ZSAxMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAypIfUURYgWzGw8G/1Pz9zW+Tsjirx2owThiv2gys
wJiWL/9/2gzKOrYDEqlDUudfA/BjVRtT9+NbYgnhaCkNfADOAacWS83aMhedAqhP
bVd5YhGQdpijI7f1AVTSb0ehrU2nhOZHvHX5Tk2fbRx3ryefIazNTLFGpiMBbsNv
tSI/+fjW8s0MhKNqlLnk6a9mZKo0mEy7HjGYV8nzsgI17rKLx/s2HG4TFG0+JQzc
UGlum3Tg58ritDzWdyKIkmKNZ48oLBX99Qc8j8B1UyiLv6TZmjVX0I+Ds7eSWHZk
0axLEpTyf2r7fHvN4iDNCPajw+ZpuuBfbs80Ha8b8MHvnpf9fbwiirodNQOVpY4c
t5E3Us3eYwBKdqDEbECWxCKGAS2/iVVUCNKHsg0sSxgqcwxrxyrddQRUQ0EM38DZ
F/vHt+vTdHt07kezbjJe0Kklel59uSpghA0iL4vxzbTns1fuwYOgVrNGs3acTkiB
GhFOxRXUPGtpdYmv+AaR9WlWJQY1GIEoVrinPVH7bcCwyh1CcUbHL+oAFTcmc6kZ
7azNg21tWILIRL7R0IZYQm0tF5TTwCsjVC7FuHaBtkxtVrrZqeKjvVXQ8TK5VoI0
BUQ6BKHGeTtm+0HBpheYBDy3wkOsEGbGHLEM6cMeiz6PyCXF8wXli8Qb/TjN3LHZ
e30CAwEAAaOCAd8wggHbMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGG
MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBT9huhQhcCi8KESm50M
G6h0cpuNSzCB7AYDVR0jBIHkMIHhgBSDx8s0qJaMyQCehKcuzgzVNRA75qGBxaSB
wjCBvzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFp
biBWaWV3MSYwJAYDVQQKEx1Db250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEm
MCQGA1UEAxMdZGV2LmNvbnRlbnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG
9w0BCQEWLGNsb3Vkc2VjK2RldnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEu
Y29tggEBMEIGCWCGSAGG+EIBBAQ1FjNodHRwczovL2NvbnRlbnQtc2lnbmF0dXJl
LmRldi5tb3phd3MubmV0L2NhL2NybC5wZW0wTgYIKwYBBQUHAQEEQjBAMD4GCCsG
AQUFBzAChjJodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmRldi5tb3phd3MubmV0
L2NhL2NhLnBlbTANBgkqhkiG9w0BAQwFAAOCAgEAbum0z0ccqI1Wp49VtsGmUPHA
gjPPy2Xa5NePmqY87WrGdhjN3xbLVb3hx8T2N6pqDjMY2rEynXKEOek3oJkQ3C6J
8AFP6Y93gaAlNz6EA0J0mqdW5TMI8YEYsu2ma+dQQ8wm9f/5b+/Y8qwfhztP06W5
H6IG04/RvgUwYMnSR4QvT309fu5UmCRUDzsO53ZmQCfmN94u3NxHc4S6n0Q6AKAM
kh5Ld9SQnlqqqDykzn7hYDi8nTLWc7IYqkGfNMilDEKbAl4CjnSfyEvpdFAJ9sPR
UL+kaWFSMvaqIPNpxS5OpoPZjmxEc9HHnCHxtfDHWdXTJILjijPrCdMaxOCHfIqV
5roOJggI4RZ0YM68IL1MfN4IEVOrHhKjDHtd1gcmy2KU4jfj9LQq9YTnyvZ2z1yS
lS310HG3or1K8Nnu5Utfe7T6ppX8bLRMkS1/w0p7DKxHaf4D/GJcCtM9lcSt9JpW
6ACKFikjWR4ZxczYKgApc0wcjd7XBuO5777xtOeyEUDHdDft3jiXA91dYM5UAzc3
69z/3zmaELzo0gWcrjLXh7fU9AvbU4EUF6rwzxbPGF78jJcGK+oBf8uWUCkBykDt
VsAEZI1u4EDg8e/C1nFqaH9gNMArAgquYIB9rve+hdprIMnva0S147pflWopBWcb
jwzgpfquuYnnxe0CNBA=
-----END CERTIFICATE-----`

var NormandyDevChain2021 = `-----BEGIN CERTIFICATE-----
MIIGRTCCBC2gAwIBAgIEAQAABTANBgkqhkiG9w0BAQwFADBrMQswCQYDVQQGEwJV
UzEQMA4GA1UEChMHQWxsaXpvbTEXMBUGA1UECxMOQ2xvdWQgU2VydmljZXMxMTAv
BgNVBAMTKERldnppbGxhIFNpZ25pbmcgU2VydmljZXMgSW50ZXJtZWRpYXRlIDEw
HhcNMTYwNzA2MjE1NzE1WhcNMjEwNzA1MjE1NzE1WjCBrzELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRp
b24xFzAVBgNVBAsTDkNsb3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZub3JtYW5keS5j
b250ZW50LXNpZ25hdHVyZS5tb3ppbGxhLm9yZzEjMCEGCSqGSIb3DQEJARYUc2Vj
dXJpdHlAbW96aWxsYS5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARUQqIIAiTB
GDVUWw/wk5h1IXpreq+BtE+gQr15O4tusHpCLGjOxwpHiJYnxk45fpE8JGAV19UO
hmqMUEU0k31C1EGTSZW0ducSvHrh3a8wXShZ6dxLWHItbbCGA6A7PumjggJYMIIC
VDAdBgNVHQ4EFgQUVfksSjlZ0i1TBiS1vcoObaMeXn0wge8GA1UdIwSB5zCB5IAU
/YboUIXAovChEpudDBuodHKbjUuhgcWkgcIwgb8xCzAJBgNVBAYTAlVTMQswCQYD
VQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UEChMdQ29udGVu
dCBTaWduYXR1cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5jb250ZW50LXNp
Z25hdHVyZS5yb290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNlYytkZXZyb290
Y29udGVudHNpZ25hdHVyZUBtb3ppbGxhLmNvbYIEAQAABDAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzBEBgNVHR8E
PTA7MDmgN6A1hjNodHRwczovL2NvbnRlbnQtc2lnbmF0dXJlLmRldi5tb3phd3Mu
bmV0L2NhL2NybC5wZW0wQgYJYIZIAYb4QgEEBDUWM2h0dHBzOi8vY29udGVudC1z
aWduYXR1cmUuZGV2Lm1vemF3cy5uZXQvY2EvY3JsLnBlbTBOBggrBgEFBQcBAQRC
MEAwPgYIKwYBBQUHMAKGMmh0dHBzOi8vY29udGVudC1zaWduYXR1cmUuZGV2Lm1v
emF3cy5uZXQvY2EvY2EucGVtMDEGA1UdEQQqMCiCJm5vcm1hbmR5LmNvbnRlbnQt
c2lnbmF0dXJlLm1vemlsbGEub3JnMA0GCSqGSIb3DQEBDAUAA4ICAQCwb+8JTAB7
ZfQmFqPUIV2cQQv696AaDPQCtA9YS4zmUfcLMvfZVAbK397zFr0RMDdLiTUQDoeq
rBEmPXhJRPiv6JAK4n7Jf6Y6XfXcNxx+q3garR09Vm/0CnEq/iV+ZAtPkoKIO9kr
Nkzecd894yQCF4hIuPQ5qtMySeqJmH3Dp13eq4T0Oew1Bu32rNHuBJh2xYBkWdun
aAw/YX0I5EqZBP/XA6gbiA160tTK+hnpnlMtw/ljkvfhHbWpICD4aSiTL8L3vABQ
j7bqjMKR5xDkuGWshZfcmonpvQhGTye/RZ1vz5IzA3VOJt1mz5bdZlitpaOm/Yv0
x6aODz8GP/PiRWFQ5CW8Uf/7pGc5rSyvnfZV2ix8EzFlo8cUtuN1fjrPFPOFOLvG
iiB6S9nlXiKBGYIDdd8V8iC5xJpzjiAWJQigwSNzuc2K30+iPo3w0zazkwe5V8jW
gj6gItYxh5xwVQTPHD0EOd9HvV1ou42+rH5Y+ISFUm25zz02UtUHEK0BKtL0lmdt
DwVq5jcHn6bx2/iwUtlKvPXtfM/6JjTJlkLZLtS7U5/pwcS0owo9zAL0qg3bdm16
+v/olmPqQFLUHmamJTzv3rojj5X/uVdx1HMM3wBjV9tRYoYaZw9RIInRmM8Z1pHv
JJ+CIZgCyd5vgp57BKiodRZcgHoCH+BkOQ==
-----END CERTIFICATE-----
` + NormandyDevChain2021Intermediate + `
-----BEGIN CERTIFICATE-----
MIIH3DCCBcSgAwIBAgIBATANBgkqhkiG9w0BAQwFADCBvzELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MSYwJAYDVQQKEx1D
b250ZW50IFNpZ25hdHVyZSBEZXYgU2lnbmluZzEmMCQGA1UEAxMdZGV2LmNvbnRl
bnQtc2lnbmF0dXJlLnJvb3QuY2ExOzA5BgkqhkiG9w0BCQEWLGNsb3Vkc2VjK2Rl
dnJvb3Rjb250ZW50c2lnbmF0dXJlQG1vemlsbGEuY29tMB4XDTE2MDcwNjE4MTUy
MloXDTI2MDcwNDE4MTUyMlowgb8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEW
MBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UEChMdQ29udGVudCBTaWduYXR1
cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5jb250ZW50LXNpZ25hdHVyZS5y
b290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNlYytkZXZyb290Y29udGVudHNp
Z25hdHVyZUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAJcPcXhD8MzF6OTn5qZ0L7lX1+PEgLKhI9g1HxxDYDVup4Zm0kZhPGmFSlml
6eVO99OvvHdAlHhQGCIG7h+w1cp66mWjfpcvtQH23uRoKZfiW3jy1jUWrvdXolxR
t1taZosjzo+9OP8TvG6LpJj7AvqUiYD4wYnQJtt0jNRN4d6MUfQwiavSS5uTBuxd
ZJ4TsPvEI+Iv4A4PSobSzxkg79LTMvsGtDLQv7nN5hMs9T18EL5GnIKoqnSQCU0d
n2CN7S3QiQ+cbORWsSYqCTj1gUbFh6X3duEB/ypLcyWFbqeJmPHikjY8q8pLjZSB
IYiTJYLyvYlKdM5QleC/xuBNnMPCftrwwLHjWE4Dd7C9t7k0R5xyOetuiHLCwOcQ
tuckp7RgFKoviMNv3gdkzwVapOklcsaRkRscv6OMTKJNsdJVIDLrPF1wMABhbEQB
64BL0uL4lkFtpXXbJzQ6mgUNQveJkfUWOoB+cA/6GtI4J0aQfvQgloCYI6jxNn/e
Nvk5OV9KFOhXS2dnDft3wHU46sg5yXOuds1u6UrOoATBNFlkS95m4zIX1Svu091+
CKTiLK85+ZiFtAlU2bPr3Bk3GhL3Z586ae6a4QUEx6SPQVXc18ezB4qxKqFc+avI
ylccYMRhVP+ruADxtUM5Vy6x3U8BwBK5RLdecRx2FEBDImY1AgMBAAGjggHfMIIB
2zAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAK
BggrBgEFBQcDAzAdBgNVHQ4EFgQUg8fLNKiWjMkAnoSnLs4M1TUQO+YwgewGA1Ud
IwSB5DCB4YAUg8fLNKiWjMkAnoSnLs4M1TUQO+ahgcWkgcIwgb8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEmMCQGA1UE
ChMdQ29udGVudCBTaWduYXR1cmUgRGV2IFNpZ25pbmcxJjAkBgNVBAMTHWRldi5j
b250ZW50LXNpZ25hdHVyZS5yb290LmNhMTswOQYJKoZIhvcNAQkBFixjbG91ZHNl
YytkZXZyb290Y29udGVudHNpZ25hdHVyZUBtb3ppbGxhLmNvbYIBATBCBglghkgB
hvhCAQQENRYzaHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5l
dC9jYS9jcmwucGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6
Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJ
KoZIhvcNAQEMBQADggIBAAAQ+fotZE79FfZ8Lz7eiTUzlwHXCdSE2XD3nMROu6n6
uLTBPrf2C+k+U1FjKVvL5/WCUj6hIzP2X6Sb8+o0XHX9mKN0yoMORTEYJOnazYPK
KSUUFnE4vGgQkr6k/31gGRMTICdnf3VOOAlUCQ5bOmGIuWi401E3sbd85U+TJe0A
nHlU+XjtfzlqcBvQivdbA0s+GEG55uRPvn952aTBEMHfn+2JqKeLShl4AtUAfu+h
6md3Z2HrEC7B3GK8ekWPu0G/ZuWTuFvOimZ+5C8IPRJXcIR/siPQl1x6dpTCew6t
lPVcVuvg6SQwzvxetkNrGUe2Wb2s9+PK2PUvfOS8ee25SNmfG3XK9qJpqGUhzSBX
T8QQgyxd0Su5G7Wze7aaHZd/fqIm/G8YFR0HiC2xni/lnDTXFDPCe+HCnSk0bH6U
wpr6I1yK8oZ2IdnNVfuABGMmGOhvSQ8r7//ea9WKhCsGNQawpVWVioY7hpyNAJ0O
Vn4xqG5f6allz8lgpwAQ+AeEEClHca6hh6mj9KhD1Of1CC2Vx52GHNh/jMYEc3/g
zLKniencBqn3Y2XH2daITGJddcleN09+a1NaTkT3hgr7LumxM8EVssPkC+z9j4Vf
Gbste+8S5QCMhh00g5vR9QF8EaFqdxCdSxrsA4GmpCa5UQl8jtCnpp2DLKXuOh72
-----END CERTIFICATE-----`

// NB: these certs do no exactly match the result of parsing
// NormandyDevChain2021
var NormandyDevChain2021Certs = []*x509.Certificate{
	{
		Subject: pkix.Name{
			CommonName:         "normandy.content-signature.mozilla.org",
			Organization:       []string{"Mozilla Corporation"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2016-07-06T21:57:15Z"),
		NotAfter:  mustParseUTC("2021-07-05T21:57:15Z"),
		IsCA:      false,
		DNSNames:  []string{"normandy.content-signature.mozilla.org"},
		KeyUsage:  x509.KeyUsageDigitalSignature,
	},
	{
		Subject: pkix.Name{
			CommonName:         "Devzilla Signing Services Intermediate 1",
			Organization:       []string{"Allizom"},
			OrganizationalUnit: []string{"Cloud Services"},
			Country:            []string{"US"},
			Province:           nil,
			Locality:           nil,
		},
		NotBefore: mustParseUTC("2016-07-06T21:49:26Z"),
		NotAfter:  mustParseUTC("2021-07-05T21:49:26Z"),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:      true,
		DNSNames:  nil,
	},
	{
		Subject: pkix.Name{
			CommonName:         "dev.content-signature.root.ca",
			Organization:       []string{"Content Signature Dev Signing"},
			OrganizationalUnit: nil,
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"Mountain View"},
		},
		NotBefore: mustParseUTC("2016-07-06T18:15:22Z"),
		NotAfter:  mustParseUTC("2026-07-04T18:15:22Z"),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:      true,
		DNSNames:  nil,
	},
}

// Tests -----------------------------------------------------------------

func Test_ParseChain(t *testing.T) {
	tests := []struct {
		name       string
		chain      []byte
		wantCerts  []*x509.Certificate
		wantErr    bool
		wantErrStr []string
	}{
		{
			name:      "NormandyDevChain2021 parses",
			chain:     []byte(NormandyDevChain2021),
			wantCerts: NormandyDevChain2021Certs,
			wantErr:   false,
		},
		{
			name:      "ExpiredEndEntityChain parses",
			chain:     []byte(ExpiredEndEntityChain),
			wantCerts: ExpiredEndEntityChainCerts,
			wantErr:   false,
		},
		{
			name:      "WronglyOrderedChain parses",
			chain:     []byte(WronglyOrderedChain),
			wantCerts: WronglyOrderedChainCerts,
			wantErr:   false,
		},
		// failing test cases.
		{
			name:       "empty chain fails",
			chain:      []byte(""),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"failed to PEM decode EE/leaf certificate from chain"},
		},
		{
			name:       "EE bad PEM type fails",
			chain:      []byte(testSignerP384PEM),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"failed to PEM decode EE/leaf certificate from chain"},
		},
		{
			name:      "EE bad PEM content fails",
			chain:     []byte(badPEMContent),
			wantCerts: []*x509.Certificate{},
			wantErr:   true,
			wantErrStr: []string{
				"error parsing EE/leaf certificate from chain: asn1: structure error: tags don't match",
				"error parsing EE/leaf certificate from chain: x509: malformed tbs certificate",
			},
		},
		{
			name:       "inter bad PEM type fails",
			chain:      []byte(firefoxPkiStageRoot + "\nthis is not a PEM"),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"failed to PEM decode intermediate certificate from chain"},
		},
		{
			name:      "inter bad PEM content fails",
			chain:     []byte(firefoxPkiStageRoot + "\n" + badPEMContent),
			wantCerts: []*x509.Certificate{},
			wantErr:   true,
			wantErrStr: []string{
				"failed to parse intermediate certificate from chain: asn1: structure error: tags don't match",
				"failed to parse intermediate certificate from chain: x509: malformed tbs certificate",
			},
		},
		{
			name:       "root bad PEM type fails",
			chain:      []byte(firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\nthis is not a PEM"),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"failed to PEM decode root certificate from chain"},
		},
		{
			name:      "inter bad PEM content fails",
			chain:     []byte(firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\n" + badPEMContent),
			wantCerts: []*x509.Certificate{},
			wantErr:   true,
			wantErrStr: []string{
				"failed to parse root certificate from chain: asn1: structure error: tags don't match",
				"failed to parse root certificate from chain: x509: malformed tbs certificate",
			},
		},
		{
			name:       "trailing data fails",
			chain:      []byte(firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\n!!!!extra"),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"found trailing data after root certificate in chain"},
		},
		{
			name:       "extra cert fails",
			chain:      []byte(firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot + "\n" + firefoxPkiStageRoot),
			wantCerts:  []*x509.Certificate{},
			wantErr:    true,
			wantErrStr: []string{"found trailing data after root certificate in chain"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCerts, err := ParseChain(tt.chain)
			if tt.wantErr && (err != nil) {
				anyMatches := false
				for _, result := range tt.wantErrStr {
					if strings.HasPrefix(err.Error(), result) {
						anyMatches = true
					}
				}
				if !anyMatches {
					t.Errorf("ParseChain() error = '%s'", err)
				}
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			for i, cert := range gotCerts {
				if cert.IsCA != tt.wantCerts[i].IsCA {
					t.Errorf("ParseChain() certs[%d].IsCA = %#v, want %#v", i, gotCerts[i].IsCA, tt.wantCerts[i].IsCA)
				}
				if !reflect.DeepEqual(cert.Subject.CommonName, tt.wantCerts[i].Subject.CommonName) {
					t.Errorf("ParseChain() certs[%d].Subject.CommonName = %#v, want %#v", i, gotCerts[i].Subject.CommonName, tt.wantCerts[i].Subject.CommonName)
				}
				if !reflect.DeepEqual(cert.Subject.Country, tt.wantCerts[i].Subject.Country) {
					t.Errorf("ParseChain() certs[%d].Subject.Country = %#v, want %#v", i, gotCerts[i].Subject.Country, tt.wantCerts[i].Subject.Country)
				}
				if !reflect.DeepEqual(cert.Subject.Province, tt.wantCerts[i].Subject.Province) {
					t.Errorf("ParseChain() certs[%d].Subject.Province = %#v, want %#v", i, gotCerts[i].Subject.Province, tt.wantCerts[i].Subject.Province)
				}
				if !reflect.DeepEqual(cert.Subject.Locality, tt.wantCerts[i].Subject.Locality) {
					t.Errorf("ParseChain() certs[%d].Subject.Locality = %#v, want %#v", i, gotCerts[i].Subject.Locality, tt.wantCerts[i].Subject.Locality)
				}
				if !reflect.DeepEqual(cert.Subject.Organization, tt.wantCerts[i].Subject.Organization) {
					t.Errorf("ParseChain() certs[%d].Subject.Organization = %#v, want %#v", i, gotCerts[i].Subject.Organization, tt.wantCerts[i].Subject.Organization)
				}
				if !reflect.DeepEqual(cert.Subject.OrganizationalUnit, tt.wantCerts[i].Subject.OrganizationalUnit) {
					t.Errorf("ParseChain() certs[%d].Subject.OrganizationalUnit = %#v, want %#v", i, gotCerts[i].Subject.OrganizationalUnit, tt.wantCerts[i].Subject.OrganizationalUnit)
				}
				if !reflect.DeepEqual(cert.DNSNames, tt.wantCerts[i].DNSNames) {
					t.Errorf("ParseChain() certs[%d].DNSNames = %#v, want %#v", i, gotCerts[i].DNSNames, tt.wantCerts[i].DNSNames)
				}
				if cert.NotBefore != tt.wantCerts[i].NotBefore {
					t.Errorf("ParseChain() certs[%d].NotBefore = %s, want %s", i, gotCerts[i].NotBefore, tt.wantCerts[i].NotBefore)
				}
				if cert.NotAfter != tt.wantCerts[i].NotAfter {
					t.Errorf("ParseChain() certs[%d].NotAfter = %s, want %s", i, gotCerts[i].NotAfter, tt.wantCerts[i].NotAfter)
				}
				if !reflect.DeepEqual(cert.KeyUsage, tt.wantCerts[i].KeyUsage) {
					t.Errorf("ParseChain() certs[%d].KeyUsage = %+v, want %+v", i, gotCerts[i].KeyUsage, tt.wantCerts[i].KeyUsage)
				}
				if !reflect.DeepEqual(cert.PermittedDNSDomains, tt.wantCerts[i].PermittedDNSDomains) {
					t.Errorf("ParseChain() certs[%d].PermittedDNSDomains = %+v, want %+v", i, gotCerts[i].PermittedDNSDomains, tt.wantCerts[i].PermittedDNSDomains)
				}
				if !reflect.DeepEqual(cert.ExcludedDNSDomains, tt.wantCerts[i].ExcludedDNSDomains) {
					t.Errorf("ParseChain() certs[%d].ExcludedDNSDomains = %+v, want %+v", i, gotCerts[i].ExcludedDNSDomains, tt.wantCerts[i].ExcludedDNSDomains)
				}
			}
			// TODO: test remaining attributes
			// if !reflect.DeepEqual(gotCerts, tt.wantCerts) {
			// 	t.Errorf("ParseChain() = %#v, want %#v", gotCerts, tt.wantCerts)
			// }
		})
	}
}

func Test_verifyRoot(t *testing.T) {
	type args struct {
		rootHash string
		cert     *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "verify Firefox prod root",
			args: args{
				rootHash: firefoxPkiProdRootHash,
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: false,
		},
		{
			name: "verify Firefox stage root",
			args: args{
				rootHash: firefoxPkiContentSignatureStageRootHash,
				cert:     mustPEMToCert(firefoxPkiContentSignatureStageRoot),
			},
			wantErr: false,
		},
		{
			name: "verify sign-signed root",
			args: args{
				rootHash: sha2Fingerprint(testRoot),
				cert:     testRoot,
			},
			wantErr: false,
		},
		// error testcases
		{
			name: "root not self-signed errs",
			args: args{
				rootHash: sha2Fingerprint(mustPEMToCert(NormandyDevChain2021Intermediate)),
				cert:     mustPEMToCert(NormandyDevChain2021Intermediate),
			},
			wantErr: true,
		},
		{
			name: "root not CA errs",
			args: args{
				rootHash: sha2Fingerprint(testRootNonCA),
				cert:     testRootNonCA,
			},
			wantErr: true,
		},
		{
			name: "invalid empty root hash errs",
			args: args{
				rootHash: "",
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: true,
		},
		{
			name: "invalid root hash all colons errs",
			args: args{
				rootHash: ":::::::",
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: true,
		},
		{
			name: "invalid root hash errs",
			args: args{
				rootHash: "foo",
				cert:     mustPEMToCert(firefoxPkiProdRoot),
			},
			wantErr: true,
		},
		{
			name: "root without code signing ext errs",
			args: args{
				rootHash: sha2Fingerprint(testRootNoExt),
				cert:     testRootNoExt,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyRoot(tt.args.rootHash, tt.args.cert); (err != nil) != tt.wantErr {
				t.Errorf("verifyRoot() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_VerifyChain(t *testing.T) {
	type args struct {
		rootHash    string
		certs       []*x509.Certificate
		currentTime time.Time
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		errSubStr string
	}{
		{
			name: "valid chain NormandyDevChain2021 passes",
			args: args{
				rootHash:    normandyDev2021Roothash,
				certs:       mustParseChain(NormandyDevChain2021),
				currentTime: mustParseUTC("2020-05-09T14:02:37Z"),
			},
			wantErr:   false,
			errSubStr: "",
		},
		{
			name: "valid test chain passes",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeaf, testInter, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   false,
			errSubStr: "",
		},
		// failing test cases.
		{
			name: "short chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{NormandyDevChain2021Certs[2]},
				currentTime: mustParseUTC("2020-05-09T14:02:37Z"),
			},
			wantErr:   true,
			errSubStr: "can only verify 3 certificate chain, got 1 certs",
		},
		{
			name: "long chain with extra root fails",
			args: args{
				rootHash: sha2Fingerprint(testRoot),
				certs: []*x509.Certificate{
					NormandyDevChain2021Certs[0],
					NormandyDevChain2021Certs[1],
					NormandyDevChain2021Certs[2],
					NormandyDevChain2021Certs[2],
				},
				currentTime: mustParseUTC("2020-05-09T14:02:37Z"),
			},
			wantErr:   true,
			errSubStr: "can only verify 3 certificate chain, got 4 certs",
		},
		{
			name: "wrongly ordered chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       mustParseChain(WronglyOrderedChain),
				currentTime: mustParseUTC("2021-05-09T14:02:37Z"),
			},
			wantErr:   true,
			errSubStr: "is not signed by parent certificate",
		},
		{
			name: "invalid root non-CA chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRootNonCA),
				certs:       []*x509.Certificate{testLeafNonCA, testInterNonCA, testRootNonCA},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: " x509: invalid signature: parent certificate cannot sign this kind of certificate",
		},
		{
			name: "root hash mismatch fails",
			args: args{
				rootHash:    "invalid hash",
				certs:       []*x509.Certificate{testLeaf, testInter, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "is root but fails validation",
		},
		{
			name: "invalid DNS name fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeafInvalidDNSName, testInter, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \"example.org\" is not permitted by any constraint",
		},
		// failing validity NotAfter / NotBefore test cases.
		{
			name: "expired end-entity chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeafExpired, testInter, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "expired",
		},
		{
			name: "not yet valid end-entity chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeafNotYetValid, testInter, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "is not yet valid",
		},
		{
			name: "expired intermediate chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeaf, testInterExpired, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "expired",
		},
		{
			name: "not yet valid intermediate chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeaf, testInterNotYetValid, testRoot},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "is not yet valid",
		},
		{
			name: "expired root chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeaf, testInter, testRootExpired},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "expired",
		},
		{
			name: "not yet valid root chain fails",
			args: args{
				rootHash:    sha2Fingerprint(testRoot),
				certs:       []*x509.Certificate{testLeaf, testInter, testRootNotYetValid},
				currentTime: time.Now(),
			},
			wantErr:   true,
			errSubStr: "is not yet valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyChain(tt.args.rootHash, tt.args.certs, tt.args.currentTime)

			if tt.wantErr == false && err != nil { // unexpected error
				t.Errorf("VerifyChain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr == true && err == nil { // unexpected pass
				t.Errorf("VerifyChain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == true && !strings.Contains(err.Error(), tt.errSubStr) {
				t.Fatalf("VerifyChain() expected to fail with '%s' but failed with: '%v'", tt.errSubStr, err.Error())
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		input     []byte
		certChain []byte
		signature string
		rootHash  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test valid content signature response ok",
			args: args{
				input:     signerTestData,
				certChain: mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRoot}),
				signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
				rootHash:  sha2Fingerprint(testRoot),
			},
			wantErr: false,
		},
		// failing test cases.
		{
			name: "default args fails",
			args: args{
				input:     []byte(""),
				certChain: []byte(""),
				signature: "",
				rootHash:  "",
			},
			wantErr: true,
		},
		{
			name: "invalid key type fails",
			args: args{
				input:     []byte(""),
				certChain: mustCertsToChain([]*x509.Certificate{testLeafRSAPub, testInter, testRoot}),
				signature: "",
				rootHash:  "",
			},
			wantErr: true,
		},
		{
			name: "signature unmarshal fails",
			args: args{
				input:     []byte(""),
				certChain: mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRoot}),
				signature: "",
				rootHash:  "",
			},
			wantErr: true,
		},
		{
			name: "data verification fails",
			args: args{
				input:     []byte(""),
				certChain: mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRoot}),
				signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
				rootHash:  "",
			},
			wantErr: true,
		},
		{
			name: "chain verification fails",
			args: args{
				input:     signerTestData,
				certChain: mustCertsToChain([]*x509.Certificate{testLeaf, testInter, testRootExpired}),
				signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
				rootHash:  sha2Fingerprint(testRoot),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Verify(tt.args.input, tt.args.certChain, tt.args.signature, tt.args.rootHash); (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

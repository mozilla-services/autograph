package cose

import (
	"fmt"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

var (
	dsaPrivateKey = dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: FromBase64Int("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF"),
				Q: FromBase64Int("E1D3391245933D68A0714ED34BBCB7A1F422B9C1"),
				G: FromBase64Int("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA"),
			},
			Y: FromBase64Int("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"),
		},
		X: FromBase64Int("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A"),
	}
	ecdsaPrivateKey = ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     FromBase64Int("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"),
			Y:     FromBase64Int("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"),
		},
		D: FromBase64Int("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"),
	}
	rsaPrivateKey = rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
			E: 3,
		},
		D: fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}
)

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)

	if !ok {
		panic("bad number: " + base10)
	}

	return i
}


func TestNewSigner(t *testing.T) {
	assert := assert.New(t)

	_, err := NewSigner(ES256, nil)
	assert.Nil(err)

	_, err = NewSigner(PS256, nil)
	assert.Nil(err)

	edDSA := getAlgByNameOrPanic("EdDSA")

	signer, err := NewSigner(edDSA, nil)
	assert.NotNil(err)
	assert.Equal(err.Error(), ErrUnknownPrivateKeyType.Error())

	edDSA.privateKeyType = KeyTypeECDSA
	signer, err = NewSigner(edDSA, nil)
	assert.NotNil(err)
	assert.Equal(err.Error(), "No ECDSA curve found for algorithm")

	signer, err = NewSigner(PS256, RSAOptions{Size: 2050})
	assert.Nil(err)
	rkey := signer.PrivateKey.(*rsa.PrivateKey)
	keySize := rkey.D.BitLen()
	bitSizeDiff := 2050 - keySize
	assert.True(bitSizeDiff <= 8, fmt.Sprintf("generated key size %d not within 8 bits of expected size 2050", keySize))

	_, err = NewSigner(PS256, RSAOptions{Size: 128})
	assert.NotNil(err)
	assert.Equal(err.Error(), "error generating rsa signer private key RSA key size must be at least 2048")

	_, err = NewSignerFromKey(ES256, &ecdsaPrivateKey)
	assert.Nil(err, "Error creating signer with ecdsaPrivateKey")

	_, err = NewSignerFromKey(ES256, &rsaPrivateKey)
	assert.Nil(err, "Error creating signer with rsaPrivateKey")

	_, err = NewSignerFromKey(ES256, &dsaPrivateKey)
	assert.Equal(ErrUnknownPrivateKeyType, err, "Did not error creating signer with unsupported dsaPrivateKey")
}

func TestSignerPublic(t *testing.T) {
	assert := assert.New(t)

	ecdsaSigner, err := NewSignerFromKey(ES256, &ecdsaPrivateKey)
	assert.Nil(err, "Error creating signer with ecdsaPrivateKey")

	rsaSigner, err := NewSignerFromKey(ES256, &rsaPrivateKey)
	assert.Nil(err, "Error creating signer with rsaPrivateKey")

	ecdsaSigner.Public()
	rsaSigner.Public()

	ecdsaSigner.PrivateKey = dsaPrivateKey
	assert.Panics(func () { ecdsaSigner.Public() })
}

func TestSignerSignErrors(t *testing.T) {
	assert := assert.New(t)

	signer, err := NewSigner(ES256, nil)
	assert.Nil(err, "Error creating ES256 signer")

	hasher := signer.alg.HashFunc.New()
	_, _ = hasher.Write([]byte("ahoy")) // Write() on hash never fails
	digest := hasher.Sum(nil)

	signer.alg.privateKeyType = KeyTypeUnsupported
	_, err = signer.Sign(rand.Reader, digest)
	assert.NotNil(err)
	assert.Equal(err.Error(), "Key type must be ECDSA")
	signer.alg.privateKeyType = KeyTypeECDSA


	signer, err = NewSigner(PS256, nil)
	assert.Nil(err, "Error creating PS256 signer")

	signer.alg.privateKeyType = KeyTypeUnsupported
	_, err = signer.Sign(rand.Reader, digest)
	assert.NotNil(err)
	assert.Equal(err.Error(), "Key type must be RSA")
	signer.alg.privateKeyType = KeyTypeRSA

	weakKey, err := rsa.GenerateKey(rand.Reader, 128)
	assert.Nil(err, "Error creating weak RSA key")
	signer.PrivateKey = weakKey
	_, err = signer.Sign(rand.Reader, digest)
	assert.NotNil(err)
	assert.Equal(err.Error(), "RSA key must be at least 2048 bits long")
}

func TestVerifyRSASuccess(t *testing.T) {
	assert := assert.New(t)

	signer, err := NewSigner(PS256, nil)
	assert.Nil(err, "Error creating signer")

	hasher := signer.alg.HashFunc.New()
	_, _ = hasher.Write([]byte("ahoy")) // Write() on hash never fails
	digest := hasher.Sum(nil)

	signatureBytes, err := signer.Sign(rand.Reader, digest)
	assert.Nil(err)

	verifier := signer.Verifier()
	err = verifier.Verify(digest, signatureBytes)
	assert.Nil(err)
}

func TestVerifyInvalidAlgErrors(t *testing.T) {
	assert := assert.New(t)

	signer, err := NewSignerFromKey(ES256, &ecdsaPrivateKey)
	assert.Nil(err, "Error creating signer")

	verifier := signer.Verifier()

	verifier.alg.Value = 20
	err = verifier.Verify([]byte(""), []byte(""))
	assert.Equal(ErrInvalidAlg, err)

	verifier.alg.Value = -7

	verifier.publicKey = rsaPrivateKey.Public()
	verifier.alg = PS256
	err = verifier.Verify([]byte(""), []byte(""))
	assert.NotNil(err)
	assert.Equal("verification failed rsa.VerifyPSS err crypto/rsa: verification error", err.Error())

	verifier.publicKey = dsaPrivateKey.PublicKey
	verifier.alg = ES256
	err = verifier.Verify([]byte(""), []byte(""))
	assert.NotNil(err)
	assert.Equal("Unrecognized public key type", err.Error())

	verifier.publicKey = ecdsaPrivateKey.Public()
	verifier.alg = ES256
	verifier.alg.privateKeyECDSACurve = nil
	err = verifier.Verify([]byte(""), []byte(""))
	assert.NotNil(err)
	assert.Equal("Could not find an elliptic curve for the ecdsa algorithm", err.Error())

	verifier.alg.privateKeyECDSACurve = elliptic.P256()
}

func TestFromBase64IntErrors(t *testing.T) {
	assert := assert.New(t)
	assert.Panics(func () { FromBase64Int("z") })
}

func TestSignVerifyWithoutMessage(t *testing.T) {
	assert := assert.New(t)

	signer, err := NewSigner(ES256, nil)
	assert.Nil(err, "Error creating ES256 signer")

	verifier := signer.Verifier()

	hasher := signer.alg.HashFunc.New()
	_, _ = hasher.Write([]byte("ahoy")) // Write() on hash never fails
	digest := hasher.Sum(nil)

	sigs, err := Sign(rand.Reader, digest, []ByteSigner{signer})
	assert.Nil(err)

	err = Verify(digest, sigs, []ByteVerifier{verifier})
	assert.Nil(err)

	err = Verify(digest, sigs, []ByteVerifier{})
	assert.NotNil(err)
	assert.Equal(err.Error(), "Wrong number of signatures 1 and verifiers 0")
}

func TestI2OSPCorrectness(t *testing.T) {
	assert := assert.New(t)

	// negative int
	assert.Panics(func () { I2OSP(big.NewInt(int64(-1)), 2) })

	// not enough bytes in output / "integer too large"
	assert.Panics(func () { I2OSP(big.NewInt(int64(0)), 0) })
	assert.Panics(func () { I2OSP(big.NewInt(int64(1)), 0) })
	assert.Panics(func () { I2OSP(big.NewInt(int64(256)), 1) })

	assert.Equal(I2OSP(big.NewInt(int64(0)), 2), []byte("\x00\x00"))
	assert.Equal(I2OSP(big.NewInt(int64(1)), 2), []byte("\x00\x01"))
	assert.Equal(I2OSP(big.NewInt(int64(255)), 2), []byte("\x00\xFF"))
	assert.Equal(I2OSP(big.NewInt(int64(256)), 2), []byte("\x01\x00"))
	assert.Equal(I2OSP(big.NewInt(int64(65535)), 2), []byte("\xFF\xFF"))

}

func TestI2OSPTiming(t *testing.T) {
	assert := assert.New(t)

	var (
		toleranceNS = int64(500) // i.e. 0.5 microseconds
		zero = big.NewInt(int64(0))
		biggerN = rsaPrivateKey.Primes[0]
		biggerNSize = len(biggerN.Bytes())
		call_args = []struct{
			N *big.Int
			Size int
		}{
			{zero, biggerNSize},
			{biggerN, biggerNSize},
		}
		elapsed_times []time.Duration
	)

	for _, args := range call_args {
		start := time.Now()
		I2OSP(args.N, args.Size)
		elapsed_times = append(elapsed_times, time.Since(start))
	}
	assert.Equal(len(call_args), len(elapsed_times))

	diff := int64(elapsed_times[0]) - int64(elapsed_times[1])
	if diff < 0 {
		diff = -diff
	}
	assert.True(diff < toleranceNS)
}

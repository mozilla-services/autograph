package contentsignature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"log"
	"math/big"
	"reflect"
	"testing"
)

// helper funcs  -----------------------------------------------------------------

func mustBigIntFromDecimalString(s string) *big.Int {
	n, ok := big.NewInt(0).SetString(s, 10)
	if !ok {
		log.Fatalf("failed to convert %s to big int", s)
	}
	return n
}

func mustDecodeHexString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("failed to decode hex string %s to bytes", s)
	}
	return b
}

// fixtures --------------------------------------------------------------

var (
	// from signer/contentsignature/contentsignature_test.go TestSign
	signerTestData = []byte("foobarbaz1234abcd")

	p256TestSig = &ContentSignature{
		R:        mustBigIntFromDecimalString("62909702126755073161249936578520261285964055865546934671113657432774849950157"),
		S:        mustBigIntFromDecimalString("30559927079695968215018070878464328164176070041378591122567041460364132574773"),
		HashName: "sha256",
		Mode:     "p256ecdsa",
		X5U:      "",
		ID:       "",
		Len:      64,
		Finished: true,
	}
	p384TestSig = &ContentSignature{
		R:        mustBigIntFromDecimalString("25920589312451551818559626767476922317217633145615568746572798912184410409902866527161616588296492756386189696060451"),
		S:        mustBigIntFromDecimalString("28210502812388841842522738679512519041668180649087645905259177260095000465474300888386313361778093884370722950365201"),
		HashName: "sha384",
		Mode:     "p384ecdsa",
		X5U:      "",
		ID:       "",
		Len:      96,
		Finished: true,
	}
	p521TestSig = &ContentSignature{
		R:        mustBigIntFromDecimalString("4646476664527617645941630225174709716850049149725353056943824849449843640252251197065601102039208646719010730687701233201185001625186775785774002588460423236"),
		S:        mustBigIntFromDecimalString("1404016930457956301674587914836594763521686195945104894183479324476177014864689510664290222914854912594609934251721782786584615945638878682397815690212480403"),
		HashName: "sha512",
		Mode:     "p521ecdsa",
		X5U:      "",
		ID:       "",
		Len:      132,
		Finished: true,
	}
)

// Tests -----------------------------------------------------------------

func TestContentSignature_Marshal(t *testing.T) {
	tests := []struct {
		name       string
		sig        *ContentSignature
		wantStr    string
		wantErr    bool
		wantErrStr string
	}{
		{
			name:       "marshal p256 ok",
			sig:        p256TestSig,
			wantStr:    "ixWhLKosDeaHn4sd_F094_Cby1rQc6I9AhMj1_8lcc1DkE5G4ruDcwUjH1FOiMM71AQzRDY68jm0-xr0mh1mNQ",
			wantErr:    false,
			wantErrStr: "n/a",
		},
		{
			name:       "p384 signature ok",
			sig:        p384TestSig,
			wantStr:    "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
			wantErr:    false,
			wantErrStr: "n/a",
		},
		{
			name:       "p521 signature ok",
			sig:        p521TestSig,
			wantStr:    "AVqM0NbiKRu9xcVk2yvE0OUfPiNI6Dph0Omgw5eSU6Hpr8HU9aFWgkbWfQMyFjYxDto5WItUqrDbXfgrIbe-bphEAGi3Y80jUZSshnfkI6o_0DSFj6SsmiMYO7FCis6CwXNzG5R9DpGjXsahASdQXcf7Xj2DEviII6H4pHfR_jwUWRWT",
			wantErr:    false,
			wantErrStr: "n/a",
		},
		// failing test cases.
		{
			name: "Marshal unfinished sig errs",
			sig: &ContentSignature{
				Finished: false,
			},
			wantStr:    "",
			wantErr:    true,
			wantErrStr: "contentsignature.Marshal: unfinished cannot be encoded",
		},
		{
			name: "Marshal invalid signature length errs",
			sig: &ContentSignature{
				Finished: true,
				Len:      1,
			},
			wantStr:    "",
			wantErr:    true,
			wantErrStr: "contentsignature.Marshal: invalid signature length 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStr, err := tt.sig.Marshal()
			if tt.wantErr && (err != nil) && err.Error() != tt.wantErrStr {
				t.Errorf("Unmarshal() error.Error() = '%s', wanted wantErrStr '%s'", err, tt.wantErrStr)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ContentSignature.Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotStr != tt.wantStr {
				t.Errorf("ContentSignature.Marshal() = %v, want %v", gotStr, tt.wantStr)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	type args struct {
		signature string
	}
	tests := []struct {
		name       string
		args       args
		wantSig    *ContentSignature
		wantErr    bool
		wantErrStr string
	}{
		{
			name: "p256 signature ok",
			args: args{
				signature: "ixWhLKosDeaHn4sd_F094_Cby1rQc6I9AhMj1_8lcc1DkE5G4ruDcwUjH1FOiMM71AQzRDY68jm0-xr0mh1mNQ",
			},
			wantSig:    p256TestSig,
			wantErr:    false,
			wantErrStr: "n/a",
		},
		{
			name: "p384 signature ok",
			args: args{
				signature: "qGjS1QmB2xANizjJqrGmIPoojzjBrTV5kgi01p1ELnfKwH4E3UDTZRf-9K7PCEwjt0mOzd1bBmRBKcnWZNFAMvAduBwfAPHFGpX-YKBoRSLHuA6QuiosEydnZEs5ykAR",
			},
			wantSig:    p384TestSig,
			wantErr:    false,
			wantErrStr: "n/a",
		},
		{
			name: "p521 signature ok",
			args: args{
				signature: "AVqM0NbiKRu9xcVk2yvE0OUfPiNI6Dph0Omgw5eSU6Hpr8HU9aFWgkbWfQMyFjYxDto5WItUqrDbXfgrIbe-bphEAGi3Y80jUZSshnfkI6o_0DSFj6SsmiMYO7FCis6CwXNzG5R9DpGjXsahASdQXcf7Xj2DEviII6H4pHfR_jwUWRWT",
			},
			wantSig:    p521TestSig,
			wantErr:    false,
			wantErrStr: "n/a",
		},
		// failing testcases
		{
			name: "empty signature errors",
			args: args{
				signature: "",
			},
			wantSig:    nil,
			wantErr:    true,
			wantErrStr: "contentsignature: signature cannot be shorter than 30 characters, got 0",
		},
		{
			name: "short signature errors",
			args: args{
				signature: "stilltooooshort",
			},
			wantSig:    nil,
			wantErr:    true,
			wantErrStr: "contentsignature: signature cannot be shorter than 30 characters, got 15",
		},
		{
			name: "invalid base64 signature errors",
			args: args{
				signature: `69d63fd587971092b5cb930f3e41e9331f0584c5660dbf13060045feae024621\0\+====`,
			},
			wantSig:    nil,
			wantErr:    true,
			wantErrStr: "contentsignature: error decoding illegal base64 data at input byte 64",
		},
		{
			name: "unknown signature length errors",
			args: args{
				signature: "gZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaIgZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaI",
			},
			wantSig:    nil,
			wantErr:    true,
			wantErrStr: "contentsignature: unknown signature length 192",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSig, err := Unmarshal(tt.args.signature)
			if tt.wantErr && (err != nil) && err.Error() != tt.wantErrStr {
				t.Errorf("Unmarshal() error.Error() = '%s', wanted wantErrStr '%s'", err, tt.wantErrStr)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotSig, tt.wantSig) {
				t.Errorf("Unmarshal() = %v, want %v", gotSig, tt.wantSig)
			}
		})
	}
}

func TestContentSignature_VerifyHash(t *testing.T) {
	type args struct {
		hash   []byte
		pubKey *ecdsa.PublicKey
	}
	tests := []struct {
		name string
		sig  *ContentSignature
		args args
		want bool
	}{
		{
			name: "verify p256 with hashed test data",
			sig:  p256TestSig,
			args: args{
				hash: mustDecodeHexString("4ee8adc2df47cf373e1f76a6c21337ceada8be0ce065e50b87e18e8018dbf207"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     mustBigIntFromDecimalString("22553365886807321974704376035318458672319825144968346123404118269995097711781"),
					Y:     mustBigIntFromDecimalString("108244837256420658593099768393894446089592395710437410913712129226183066280052"),
				},
			},
			want: true,
		},
		{
			name: "verify p384 with hashed test data",
			sig:  p384TestSig,
			args: args{
				hash: mustDecodeHexString("de26bbd0ca62d01c25da2bdf4cc9e3a74b2febde46a1fefc80f3c5551ba43d82d68af4f4daf51141848667b34412ecdb"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P384(),
					X:     mustBigIntFromDecimalString("36710462446480588216284689807627817014646721200492924145398531433235091994318991197136051265123969581598624769673277"),
					Y:     mustBigIntFromDecimalString("13321657710580770815189509910471560427735973610987090311580468484926183799307630222506225442637593506669214941325644"),
				},
			},
			want: true,
		},
		{
			name: "verify p521 with hashed test data",
			sig:  p521TestSig,
			args: args{
				hash: mustDecodeHexString("858aadfa55e677ec54ac32886beabf48ecbb47ad0ac89dfac52a1765a10ee3367dd4fa2c222635426dbe1a515c38140140c4b7c4a61ab345527e57917696b200"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: true,
		},
		// failing test cases.
		{
			name: "verify p521 with pubkey with wrong curve",
			sig:  p521TestSig,
			args: args{
				hash: mustDecodeHexString("858aadfa55e677ec54ac32886beabf48ecbb47ad0ac89dfac52a1765a10ee3367dd4fa2c222635426dbe1a515c38140140c4b7c4"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: false,
		},
		{
			name: "verify p521 with invalid short hash",
			sig:  p521TestSig,
			args: args{
				hash: mustDecodeHexString("858aadfa55e677ec54ac32886beabf48ecbb47ad0ac89dfac52a1765a10ee3367dd4fa2c222635426dbe1a515c38140140c4b7c4"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: false,
		},
		{
			name: "verify p521 with invalid doubled hash",
			sig:  p521TestSig,
			args: args{
				hash: mustDecodeHexString("858aadfa55e677ec54ac32886beabf48ecbb47ad0ac89dfac52a1765a10ee3367dd4fa2c222635426dbe1a515c38140140c4b7c4a61ab345527e57917696b200858aadfa55e677ec54ac32886beabf48ecbb47ad0ac89dfac52a1765a10ee3367dd4fa2c222635426dbe1a515c38140140c4b7c4a61ab345527e57917696b200"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sig.VerifyHash(tt.args.hash, tt.args.pubKey); got != tt.want {
				t.Errorf("ContentSignature.VerifyHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContentSignature_VerifyData(t *testing.T) {
	type args struct {
		input  []byte
		pubKey *ecdsa.PublicKey
	}
	tests := []struct {
		name string
		sig  *ContentSignature
		args args
		want bool
	}{
		{
			name: "verify p256 with test data",
			sig:  p256TestSig,
			args: args{
				input: signerTestData,
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     mustBigIntFromDecimalString("22553365886807321974704376035318458672319825144968346123404118269995097711781"),
					Y:     mustBigIntFromDecimalString("108244837256420658593099768393894446089592395710437410913712129226183066280052"),
				},
			},
			want: true,
		},
		{
			name: "verify p384 with test data",
			sig:  p384TestSig,
			args: args{
				input: signerTestData,
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P384(),
					X:     mustBigIntFromDecimalString("36710462446480588216284689807627817014646721200492924145398531433235091994318991197136051265123969581598624769673277"),
					Y:     mustBigIntFromDecimalString("13321657710580770815189509910471560427735973610987090311580468484926183799307630222506225442637593506669214941325644"),
				},
			},
			want: true,
		},
		{
			name: "verify p521 with test data",
			sig:  p521TestSig,
			args: args{
				input: signerTestData,
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: true,
		},
		// failing test cases.
		{
			name: "verify p521 with invalid empty data fails",
			sig:  p521TestSig,
			args: args{
				input: []byte(""),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: false,
		},
		{
			name: "verify p521 with invalid other data fails",
			sig:  p521TestSig,
			args: args{
				input: []byte("foobarbaz !!!!"),
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
					X:     mustBigIntFromDecimalString("286552129222061894591899553727916711846697303481941651268255086723851847297946360274929851689688740326236568882843713781062271837109982630496462930539210780"),
					Y:     mustBigIntFromDecimalString("4465986104604937627280307749790047390503295541438697600342307857260719588592376747937866471348953390906248103628086397664284123962827478845690817485707485531"),
				},
			},
			want: false,
		},
		{
			name: "verify p384 with P-256 curve pubkey fails",
			sig:  p384TestSig,
			args: args{
				input: signerTestData,
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     mustBigIntFromDecimalString("36710462446480588216284689807627817014646721200492924145398531433235091994318991197136051265123969581598624769673277"),
					Y:     mustBigIntFromDecimalString("13321657710580770815189509910471560427735973610987090311580468484926183799307630222506225442637593506669214941325644"),
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sig.VerifyData(tt.args.input, tt.args.pubKey); got != tt.want {
				t.Errorf("ContentSignature.VerifyData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContentSignature_String(t *testing.T) {
	tests := []struct {
		name string
		sig  *ContentSignature
		want string
	}{
		{
			name: "p256 str ok",
			sig:  p256TestSig,
			want: "ID= Mode=p256ecdsa Len=64 HashName=sha256 X5U= Finished=true R=62909702126755073161249936578520261285964055865546934671113657432774849950157 S=30559927079695968215018070878464328164176070041378591122567041460364132574773",
		},
		{
			name: "p384 str ok",
			sig:  p384TestSig,
			want: "ID= Mode=p384ecdsa Len=96 HashName=sha384 X5U= Finished=true R=25920589312451551818559626767476922317217633145615568746572798912184410409902866527161616588296492756386189696060451 S=28210502812388841842522738679512519041668180649087645905259177260095000465474300888386313361778093884370722950365201",
		},
		{
			name: "p521 str ok",
			sig:  p521TestSig,
			want: "ID= Mode=p521ecdsa Len=132 HashName=sha512 X5U= Finished=true R=4646476664527617645941630225174709716850049149725353056943824849449843640252251197065601102039208646719010730687701233201185001625186775785774002588460423236 S=1404016930457956301674587914836594763521686195945104894183479324476177014864689510664290222914854912594609934251721782786584615945638878682397815690212480403",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sig.String(); got != tt.want {
				t.Errorf("ContentSignature.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

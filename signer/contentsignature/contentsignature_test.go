// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package contentsignature_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	sig := new(ecdsaSignature)
	siglen := 96
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.UnmarshalText([]byte("6259915849506081953195822778836906638312880422565351933025739850554626487283192654040697419197598947387738806787988"))
	sig.S.UnmarshalText([]byte("5943508783332546705852262942555715397696959766757176458821265258714412617334569990327433520177942823437637818778521"))
	for _, format := range []string{"", "rs_base64", "rs_base64url", "der_base64", "der_base64url"} {
		str, err := encode(sig, siglen, format)
		if err != nil {
			t.Error(err)
		}
		t.Log(str)
		sig2, err := decode(str, format)
		if err != nil {
			t.Error(err)
		}
		if sig.R.String() != sig2.R.String() || sig.S.String() != sig2.S.String() {
			t.Errorf("failed to encode/decode ecdsa signature in format %q", format)
		}
	}
}

func TestEncodeDecodeWithPadding(t *testing.T) {
	TESTCASES := []struct {
		siglen int
		R      string
		S      string
	}{
		{96, "2128066202487217241539270666680448722972693699940038599787429812251636356699680994967769608052734582226276770140879", "108241770093221671004852343318847354670379493045829426776218162732683913479472713406018140729513260136708922285166"},
		{96, "111072053423331555492457222311902329496194472749479844347044796559168697529752903003136003847320923581342328976742", "27407168111906593754315382063905994340883263312680042518128418929507621149854352250321363323835060648900578339084406"},
		{96, "8785674129730864930499752157730675177314024034613814144278953415721326426726774412625213492567185922012617440733352", "23049031040197223126992382691786449731136998814239966806935666296303914636458655229985399407408184235392126750899"},
	}
	for _, testcase := range TESTCASES {
		sig := new(ecdsaSignature)
		siglen := testcase.siglen
		sig.R, sig.S = new(big.Int), new(big.Int)
		sig.R.UnmarshalText([]byte(testcase.R))
		sig.S.UnmarshalText([]byte(testcase.S))
		for _, format := range []string{"", "rs_base64", "rs_base64url", "der_base64", "der_base64url"} {
			str, err := encode(sig, siglen, format)
			if err != nil {
				t.Error(err)
			}
			t.Log(str)
			sig2, err := decode(str, format)
			if err != nil {
				t.Error(err)
			}
			if sig.R.String() != sig2.R.String() || sig.S.String() != sig2.S.String() {
				t.Errorf("failed to encode/decode ecdsa signature in format %q", format)
			}
		}
	}
}
func TestFromB64URL(t *testing.T) {
	TESTCASES := []struct {
		expectError string
		b64         string
		sig         []byte
	}{
		{"illegal base64 data at input byte 0", "{{{{{{", nil},
		{"", "XBKzej3i6TAFZc3VZsuCekn-4dYWJBE4-b3OOtKrOV-JIzIvAnAhnOV1aj-kEm07kh-FciIxV-Xk2QUQlRQzHO7oW7E4mXkMKkbbAcvL0CFrItTObhfhKnBnpAE9ql1O", []byte("\x5c\x12\xb3\x7a\x3d\xe2\xe9\x30\x05\x65\xcd\xd5\x66\xcb\x82\x7a\x49\xfe\xe1\xd6\x16\x24\x11\x38\xf9\xbd\xce\x3a\xd2\xab\x39\x5f\x89\x23\x32\x2f\x02\x70\x21\x9c\xe5\x75\x6a\x3f\xa4\x12\x6d\x3b\x92\x1f\x85\x72\x22\x31\x57\xe5\xe4\xd9\x05\x10\x95\x14\x33\x1c\xee\xe8\x5b\xb1\x38\x99\x79\x0c\x2a\x46\xdb\x01\xcb\xcb\xd0\x21\x6b\x22\xd4\xce\x6e\x17\xe1\x2a\x70\x67\xa4\x01\x3d\xaa\x5d\x4e")},
	}
	for _, testcase := range TESTCASES {
		s, err := fromBase64URL(testcase.b64)
		if testcase.expectError == "" && err != nil {
			t.Errorf("failed to load signature from base64 data: %v", err)
		}
		if testcase.expectError != "" && testcase.expectError != err.Error() {
			t.Errorf("expected to fail with error %q but got error %q", testcase.expectError, err)
		}
		if testcase.expectError == "" && err == nil {
			if !bytes.Equal(testcase.sig, s) {
				t.Errorf("decoded base64 data doesn't match expected data")
			}
		}
	}
}

func TestEncodeUnknownFormat(t *testing.T) {
	sig := new(ecdsaSignature)
	siglen := 96
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.UnmarshalText([]byte("6259915849506081953195822778836906638312880422565351933025739850554626487283192654040697419197598947387738806787988"))
	sig.S.UnmarshalText([]byte("5943508783332546705852262942555715397696959766757176458821265258714412617334569990327433520177942823437637818778521"))
	_, err := encode(sig, siglen, "somethingrandom")
	if fmt.Sprintf("%v", err) != `unknown encoding format "somethingrandom"` {
		t.Errorf("expected to fail with unknown format, but didn't")
	}
}

func TestDecodeUnknownFormat(t *testing.T) {
	_, err := decode("blah", "somethingrandom")
	if fmt.Sprintf("%v", err) != `unknown decoding format "somethingrandom"` {
		t.Errorf("expected to fail with unknown format, but didn't")
	}
}

func TestBadDecodeString(t *testing.T) {
	_, err := decode("{{{{{{{{", "")
	if err == nil {
		t.Errorf("expected to fail decoding, but didn't")
	}
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

func encode(sig *ecdsaSignature, format string) (str string, err error) {
	if len(format) < 4 {
		format = "rs_base64url"
	}
	if strings.HasPrefix(format, "rs_base64") {
		// return default rs_base64url format
		rs := make([]byte, len(sig.R.Bytes())+len(sig.S.Bytes()))
		copy(rs[:len(sig.R.Bytes())], sig.R.Bytes())
		copy(rs[len(sig.S.Bytes()):], sig.S.Bytes())
		str = base64.StdEncoding.EncodeToString(rs)
		if format == "rs_base64url" {
			str = b64Tob64url(str)
		}
		return str, nil
	}
	if strings.HasPrefix(format, "der_base64") {
		der, err := asn1.Marshal(*sig)
		if err != nil {
			return "", fmt.Errorf("asn1 marshalling failed with error: %v", err)
		}
		str = base64.StdEncoding.EncodeToString(der)
		if format == "der_base64url" {
			str = b64Tob64url(str)
		}
		return str, nil
	}
	return "", fmt.Errorf("unknown encoding format %q", format)
}

func decode(str, format string) (sig *ecdsaSignature, err error) {
	sig = new(ecdsaSignature)
	if len(format) < 4 {
		format = "rs_base64url"
	}
	str = b64urlTob64(str)
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(format, "rs_base64") {
		sig.R, sig.S = new(big.Int), new(big.Int)
		sig.R.SetBytes(data[:len(data)/2])
		sig.S.SetBytes(data[len(data)/2:])
		return sig, nil
	}
	if strings.HasPrefix(format, "der_base64") {
		_, err = asn1.Unmarshal(data, sig)
		return sig, err
	}
	return nil, fmt.Errorf("unknown decoding format %q", format)
}

func toBase64URL(b []byte) string {
	return b64Tob64url(base64.StdEncoding.EncodeToString(b))
}

func b64Tob64url(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "+", "-", -1)
	s = strings.Replace(s, "/", "_", -1)
	s = strings.TrimRight(s, "=")
	return s
}

func fromBase64URL(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(b64urlTob64(s))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func b64urlTob64(s string) string {
	// convert base64url characters back to regular base64 alphabet
	s = strings.Replace(s, "-", "+", -1)
	s = strings.Replace(s, "_", "/", -1)
	if l := len(s) % 4; l > 0 {
		s += strings.Repeat("=", 4-l)
	}
	return s
}

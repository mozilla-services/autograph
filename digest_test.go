// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestDigests(t *testing.T) {
	testcases := []struct {
		data string
		alg  string
		hash string
	}{
		{"Y2FyaWJvdSBtYXVyaWNl", "sha1", "cdfb88bb038964089b52b94e88b39745bc23abcb"},
		{"Y2FyaWJvdSBtYXVyaWNl", "sha256", "a78d8e78679297792ddb0eaddf6d8c1cf7b0a3cdc3800d2b5e1b688e0b1e2440"},
		{"Y2FyaWJvdSBtYXVyaWNl", "sha384", "acf2c13ce3f92314d03807d2ec51ef61a29a70ed1e7d61b71a8b30ae9264a5c75bafa75fbd0d6e2ed082c3c683a76404"},
		{"Y2FyaWJvdSBtYXVyaWNl", "sha512", "b0c58b23bc9241dbb2ecac5f816bcdcc51ade30ce8ec3f117b6dc2c6d02eca841cdfc838135dfd522b374248946111320791758bcd3dab8fde4b1e750fd5a6ec"},
	}
	for _, testcase := range testcases {
		data, err := base64.StdEncoding.DecodeString(testcase.data)
		if err != nil {
			t.Fatalf("failed to decode test data: %v", err)
		}
		hashed, err := digest(data, testcase.alg)
		if err != nil {
			t.Fatalf("failed to digest test data: %v", err)
		}
		if testcase.hash != fmt.Sprintf("%x", hashed) {
			t.Fatalf("hashed data does not match test case: %q!=%q",
				fmt.Sprintf("%x", hashed), testcase.hash)
		}
	}
}

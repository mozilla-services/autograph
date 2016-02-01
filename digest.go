// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

func digest(data []byte, alg string) (hashed []byte, err error) {
	var md hash.Hash
	switch alg {
	case "sha1":
		md = sha1.New()
	case "sha256":
		md = sha256.New()
	case "sha384":
		md = sha512.New384()
	case "sha512":
		md = sha512.New()
	default:
		return nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	md.Write(data)
	hashed = md.Sum(nil)
	return
}

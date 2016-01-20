// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"crypto/rand"
	"math/big"
	"strconv"
)

// id returns a 128bits random id encoded in base36
func id() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	x, y := new(big.Int), new(big.Int)
	x.SetBytes(b[:8])
	y.SetBytes(b[8:])
	return strconv.FormatUint(x.Uint64(), 36) + strconv.FormatUint(y.Uint64(), 36)
}

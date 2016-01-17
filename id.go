// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import (
	"strconv"
	"sync"
	"time"
)

type id struct {
	value float64
	sync.Mutex
}

var globalID id

// GenID() returns a float64 ID number that is unique to this process. The ID is initialized
// at the number of seconds since MIG's creation date, shifted 16 bits to the right and incremented
// by one every time a new ID is requested. The resulting value must fit in 53 bits of precision
// provided by the float64 type.
func genID() float64 {
	globalID.Lock()
	defer globalID.Unlock()
	if globalID.value < 1 {
		// if id hasn't been initialized yet, set it to number of seconds since
		// MIG's inception, plus one
		tmpid := int64(time.Since(time.Unix(1367258400, 0)).Seconds() + 1)
		tmpid = tmpid << 16
		globalID.value = float64(tmpid)
		return globalID.value
	}
	globalID.value++
	return globalID.value

}

// GenHexID returns a string with an hexadecimal encoded ID
func genB32ID() string {
	id := genID()
	return strconv.FormatUint(uint64(id), 36)
}

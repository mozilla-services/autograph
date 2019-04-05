// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Julien Vehent jvehent@mozilla.com [:ulfr]

package main

import "testing"

func TestId(t *testing.T) {
	t.Parallel()

	const (
		minSize = 20
		maxSize = 27
	)
	x, y, z := id(), id(), id()
	if x == y || x == z || y == z {
		t.Fatalf("found identical ids, randomness fail")
	}
	if len(x) < minSize || len(x) > maxSize || len(y) < minSize || len(y) > maxSize || len(z) < minSize || len(z) > maxSize {
		t.Fatalf("ids have wrong length, should be 25/26, got: %s:%d, %s:%d, %s:%d",
			x, len(x), y, len(y), z, len(z))
	}
}

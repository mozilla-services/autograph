// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package apple

import _ "embed"

// testMachO is a small, unsigned arm64 Mach-O executable used as the test file
// for application-mode signers (exercised by the monitor via GetTestFile).
//
//go:embed testdata/macho
var testMachO []byte

// testPkg is a small, unsigned XAR/.pkg installer used as the test file for
// installer-mode signers (exercised by the monitor via GetTestFile).
//
//go:embed testdata/installer.pkg
var testPkg []byte

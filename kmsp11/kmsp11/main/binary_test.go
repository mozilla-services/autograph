// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package binarytest

import (
	"debug/elf"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/prototext"

	"cloud.google.com/kms/integrations/kmsp11/tools/p11fn/p11fnpb"
)

var (
	minBinarySizeMB = flag.Int64("min_binary_size_mb", 4,
		"the minimum size of the libkmsp11.so binary, in megabytes")
	maxBinarySizeMB = flag.Int64("max_binary_size_mb", 16,
		"the maximum size of the libkmsp11.so binary, in megabytes")
	expectOpenSSL = flag.Bool("expect_openssl", false,
		"whether or not OpenSSL is an expected dependency")
)

func resolveRunfile(t *testing.T, name string) string {
	t.Helper()

	filename, err := bazel.Runfile(name)
	if err != nil {
		t.Fatalf("error locating runfile %s: %v", name, err)
	}
	return filename
}

// loadBinary loads libkmsp11.so as a file.
func loadBinary(t *testing.T) *os.File {
	t.Helper()

	bin, err := os.Open(resolveRunfile(t, "kmsp11/main/libkmsp11.so"))
	if err != nil {
		t.Fatalf("error opening binary: %v", err)
	}
	return bin
}

func TestBinarySize(t *testing.T) {
	// Yeah, this is just a change detector. And the values here weren't really
	// chosen scientifically. But it seems like it would be good to know if our
	// binary failed expectations in this way.
	info, err := loadBinary(t).Stat()
	if err != nil {
		t.Fatalf("error retrieving file statistics: %v", err)
	}

	if info.Size() < *minBinarySizeMB*1024*1024 ||
		info.Size() > *maxBinarySizeMB*1024*1024 {
		t.Errorf("unexpected file size %d bytes, want >= %d MB and <= %dMB",
			info.Size(), *minBinarySizeMB, *maxBinarySizeMB)
	}
}

// loadELFBinary loads libkmsp11.so as an ELF binary.
func loadELFBinary(t *testing.T) *elf.File {
	t.Helper()

	elfBin, err := elf.NewFile(loadBinary(t))
	if err != nil {
		t.Fatalf("error opening ELF binary: %v", err)
	}
	return elfBin
}

// loadP11FunctionNames returns the list of PKCS#11 C_* functions, sorted by name.
func loadP11FunctionNames(t *testing.T) []string {
	t.Helper()

	f, err := ioutil.ReadFile(resolveRunfile(t, "kmsp11/tools/p11fn/function_defs.textproto"))
	if err != nil {
		t.Fatalf("error reading function list textproto: %v", err)
	}

	list := new(p11fnpb.CkFuncList)
	if err := prototext.Unmarshal(f, list); err != nil {
		log.Fatalf("error parsing function list textproto: %+v", err)
	}

	names := make([]string, len(list.Functions))
	for i, v := range list.Functions {
		names[i] = v.Name
	}
	sort.Strings(names)
	return names
}

// globalExportedSymbolNames returns a sorted list of symbol names exported
// from the binary.
func globalExportedSymbolNames(t *testing.T) []string {
	t.Helper()

	sym, err := loadELFBinary(t).DynamicSymbols()
	if err != nil {
		t.Fatalf("error reading dynamic symbols table: %v", err)
	}

	var s []string
	for _, v := range sym {
		// Symbols without a value should not be included.
		if v.Value == 0 {
			continue
		}
		// Symbols without global binding should not be included.
		if elf.ST_BIND(v.Info) != elf.STB_GLOBAL {
			continue
		}
		// Symbols without default visibility should not be included.
		if elf.ST_VISIBILITY(v.Other) != elf.STV_DEFAULT {
			continue
		}
		// We've found a matching symbol.
		s = append(s, v.Name)
	}

	sort.Strings(s)
	return s
}

func TestExportedSymbols_LinuxAndFreeBSD(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "freebsd":
		break
	default:
		t.Skip("this test only runs on linux and freebsd")
	}

	if diff := cmp.Diff(loadP11FunctionNames(t), globalExportedSymbolNames(t)); diff != "" {
		t.Errorf("exported symbol names produced unexpected diff (-want +got):\n%s", diff)
	}
}

func TestImportedSymbolsLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test only runs on linux")
	}

	// These should be the only libraries from which we import symbols.
	// True for deps that are part of glibc.
	allowedDeps := map[string]bool{
		"ld-linux-x86-64.so.2": false,
		"libc.so.6":            true,
		"libm.so.6":            true,
		"libpthread.so.0":      true,
	}

	if *expectOpenSSL {
		allowedDeps["libcrypto.so.1.0.0"] = false
		allowedDeps["libssl.so.1.0.0"] = false
	}

	// We target GLIBC >= 2.17, so all symbols we import must be <= 2.17.
	// Version strings for imported symbols should look like one of these:
	// - GLIBC_2.2.4
	// - GLIBC_2.14
	versionRegexp := regexp.MustCompile("^GLIBC_2\\.(\\d+)(\\.\\d+)?$")

	symbols, err := loadELFBinary(t).ImportedSymbols()
	if err != nil {
		t.Fatalf("error loading imported symbols: %v", err)
	}

	for _, sym := range symbols {
		if glibc, ok := allowedDeps[sym.Library]; !ok {
			t.Errorf("unexpected library dependency for imported symbol: %v", sym)
			continue
		} else if !glibc {
			continue
		}

		sm := versionRegexp.FindStringSubmatchIndex(sym.Version)
		if sm == nil {
			t.Errorf("unexpected symbol version for imported symbol: %v", sym)
			continue
		}
		minor, err := strconv.Atoi(sym.Version[sm[2]:sm[3]])
		if err != nil {
			t.Errorf("unable to parse symbol minor version for imported symbol: %v", sym)
			continue
		}

		if minor > 17 {
			t.Errorf("unexpected imported symbol dependency on GLIBC > 2.17: %v", sym)
		}
	}
}

func TestImportedLibrariesFreeBSD(t *testing.T) {
	if runtime.GOOS != "freebsd" {
		t.Skip("this test only runs on freebsd")
	}

	want := []string{
		"libc++.so.1", "libc.so.7", "libcxxrt.so.1",
		"libgcc_s.so.1", "libm.so.5", "libthr.so.3"}
	if *expectOpenSSL {
		want = append(want, "libcrypto.so.111", "libssl.so.111")
	}
	sort.Strings(want)

	got, err := loadELFBinary(t).ImportedLibraries()
	if err != nil {
		t.Fatalf("error loading imported library list: %v", err)
	}
	sort.Strings(got)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("imported libraries produced unexpected diff (-want +got):\n%s", diff)
	}
}

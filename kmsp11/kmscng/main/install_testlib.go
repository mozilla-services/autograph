// Copyright 2023 Google LLC
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

// Package installtestlib contains utilties for dealing with windows installers.
//
// Useful doc: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec
package installtestlib

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/bazelbuild/rules_go/go/tools/bazel"
	"golang.org/x/text/encoding/unicode"
)

const msiRunfile = "kmscng/main/kmscng.msi"

// MustInstall causes a fatal error if kmscng.msi cannot be installed.
func MustInstall(t *testing.T, ctx context.Context) {
	t.Helper()
	if log, err := RunInstaller(ctx, "/i", msiRunfile); err != nil {
		t.Fatalf("error installing: %v\ndetailed log:\n%s", err, log)
	}
}

// MustUninstall causes a fatal error if kmscng.msi cannot be uninstalled.
func MustUninstall(t *testing.T, ctx context.Context) {
	t.Helper()
	if log, err := RunInstaller(ctx, "/x", msiRunfile); err != nil {
		t.Fatalf("error uninstalling: %v\ndetailed log:\n%s", err, log)
	}
}

// MustNotUninstall causes a fatal error if kmscng.msi is uninstalled unexpectedly.
func MustNotUninstall(t *testing.T, ctx context.Context) {
	t.Helper()
	if log, err := RunInstaller(ctx, "/x", msiRunfile); err == nil {
		t.Fatalf("uninstall succeeded unexpectedly: %v\ndetailed log:\n%s", err, log)
	}
}

// RunInstaller runs msiexec with the provided cmd (like "/i" or `/x") followed
// by the runfile path to an msi installer.
func RunInstaller(ctx context.Context, cmd, msiRunfile string) (detailedLog string, err error) {
	msiLoc, err := bazel.Runfile(msiRunfile)
	if err != nil {
		return "", fmt.Errorf("error locating runfile %s: %v", msiRunfile, err)
	}
	// Bazel runfiles paths contain forward slashes; msiexec can't cope.
	msiLoc = strings.ReplaceAll(msiLoc, "/", "\\")

	log, err := os.CreateTemp("", "log")
	if err != nil {
		return "", fmt.Errorf("creating log temp file: %v", err)
	}
	defer os.Remove(log.Name())
	log.Close() // log gets written by msiexec, not us

	msiexecArgs := []string{cmd, msiLoc, "/qn", "/l*v", log.Name()}
	if os.Getenv("KOKORO_JOB_NAME") != "" {
		// In CI envs, reduce test flakiness by disabling rollbacks and not saving copies of deleted files.
		msiexecArgs = append(msiexecArgs,
			"MSIFASTINSTALL=3",  // https://learn.microsoft.com/en-us/windows/win32/msi/msifastinstall
			"DISABLEROLLBACK=1", // https://learn.microsoft.com/en-us/windows/win32/msi/-disablerollback
		)
	}

	err = exec.CommandContext(ctx, "msiexec.exe", msiexecArgs...).Run()
	d, logErr := readUTF16(log.Name())
	if logErr != nil {
		return "", fmt.Errorf("cannot read installer log: %v", logErr)
	}
	return d, err
}

// readUTF16 reads the UTF-16 file at path to a	Go string.
func readUTF16(path string) (string, error) {
	if f, err := os.Open(path); err != nil {
		return "", err
	} else if utf16, err := io.ReadAll(f); err != nil {
		return "", err
	} else if utf8, err := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder().Bytes(utf16); err != nil {
		return "", err
	} else {
		return string(utf8), nil
	}
}

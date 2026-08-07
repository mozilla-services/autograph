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

package installtest

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"installtestlib"
)

const (
	libraryFile  = "C:\\Windows\\System32\\kmscng.dll"
	providerName = "Google Cloud KMS Provider"
	registryKey  = "HKLM\\System\\CurrentControlSet\\Control\\Cryptography\\Providers\\" +
		providerName + "\\UM\\00010001"

	fileRenamesKey    = "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\FileRenameOperations"
	pendingRenamesKey = "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations"

	minVersionRunfile = "kmscng/main/kmscng_v0.msi"
	maxVersionRunfile = "kmscng/main/kmscng_v255.msi"
	versionTestFile   = "C:\\Windows\\System32\\kmscng_version.txt"
)

func fileExists(t *testing.T, ctx context.Context, filename string) bool {
	t.Helper()

	// TODO(b/283099145): remove this logic and replace with a fix once we understand why this is flaky.
	if out, err := exec.CommandContext(ctx, "reg", "query", fileRenamesKey, "/s").CombinedOutput(); err != nil {
		t.Logf("reg query %s /s failed with error=%v", fileRenamesKey, err)
	} else {
		t.Logf("req query %s /s output:\n%s", fileRenamesKey, string(out))
	}
	if out, err := exec.CommandContext(ctx, "reg", "query", pendingRenamesKey, "/s").CombinedOutput(); err != nil {
		t.Logf("reg query %s /s failed with error=%v", pendingRenamesKey, err)
	} else {
		t.Logf("req query %s /s output:\n%s", pendingRenamesKey, string(out))
	}

	if _, err := os.Stat(filename); err == nil {
		return true
	} else if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("os.Stat(%q) err=%v, want nil or fs.ErrNotExist", filename, err)
	}
	return false
}

func regExists(t *testing.T, ctx context.Context) bool {
	t.Helper()
	out, err := exec.CommandContext(ctx, "reg", "query", registryKey).CombinedOutput()
	if err == nil {
		return true
	}
	if !strings.Contains(string(out), "unable to find the specified registry key") {
		t.Fatalf("querying registry command: %v", err)
	}
	return false
}

func TestInstallUninstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustInstall(t, ctx)

	if !regExists(t, ctx) {
		t.Errorf("registry key %q is missing", registryKey)
	}
	if !fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q is missing", libraryFile)
	}

	installtestlib.MustUninstall(t, ctx)

	if regExists(t, ctx) {
		t.Errorf("registry key %q unexpectedly exists", registryKey)
	}
	if fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q unexpectedly exists", libraryFile)
	}
}

func TestInstallUninstallInstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustInstall(t, ctx)
	installtestlib.MustUninstall(t, ctx)
	installtestlib.MustInstall(t, ctx)
	defer installtestlib.MustUninstall(t, ctx)

	if !regExists(t, ctx) {
		t.Errorf("registry key %q is missing", registryKey)
	}
	if !fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q is missing", libraryFile)
	}
}

func TestDoubleInstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustInstall(t, ctx)
	installtestlib.MustInstall(t, ctx)
	defer installtestlib.MustUninstall(t, ctx)

	if !regExists(t, ctx) {
		t.Errorf("registry key %q is missing", registryKey)
	}
	if !fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q is missing", libraryFile)
	}
}

func TestUninstallWithoutInstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustNotUninstall(t, ctx)

	if regExists(t, ctx) {
		t.Errorf("registry key %q unexpectedly exists", registryKey)
	}
	if fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q unexpectedly exists", libraryFile)
	}
}

func TestUninstallRemovesRegistryEntryWhenDllIsMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustInstall(t, ctx)

	if err := os.Remove(libraryFile); err != nil {
		t.Fatalf("unable to remove library file: %v", err)
	}

	installtestlib.MustUninstall(t, ctx)

	if regExists(t, ctx) {
		t.Errorf("registry key %q unexpectedly exists", registryKey)
	}
}

func TestUninstallRemovesDllWhenRegistryEntryIsMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	installtestlib.MustInstall(t, ctx)

	if out, err := exec.CommandContext(ctx, "reg", "delete", registryKey, "/va", "/f").Output(); err != nil {
		t.Errorf("unable to delete registry key: %v\ndetailed error: %s", err, string(out))
	}

	installtestlib.MustUninstall(t, ctx)

	if fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q unexpectedly exists", libraryFile)
	}
}

func TestUpgradeFromOlderVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Install an older version.
	if log, err := installtestlib.RunInstaller(ctx, "/i", minVersionRunfile); err != nil {
		t.Fatalf("error installing: %v\ndetailed log:\n%s", err, log)
	}
	if !fileExists(t, ctx, versionTestFile) {
		t.Errorf("file %q is missing", versionTestFile)
	}

	// Update to the current version, and remove when we're done.
	installtestlib.MustInstall(t, ctx)
	defer installtestlib.MustUninstall(t, ctx)

	// Artifacts from the current version should exist.
	if !regExists(t, ctx) {
		t.Errorf("registry key %q is missing", registryKey)
	}
	if !fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q is missing", libraryFile)
	}

	// Artifacts from the previous version should be missing.
	if fileExists(t, ctx, versionTestFile) {
		t.Errorf("file %q is unexpectedly present", versionTestFile)
	}
}

func TestUpgradeToNewerVersion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Install the current version.
	installtestlib.MustInstall(t, ctx)
	// Upgrade to a newer version.
	if log, err := installtestlib.RunInstaller(ctx, "/i", maxVersionRunfile); err != nil {
		t.Fatalf("error upgrading: %v\ndetailed log:\n%s", err, log)
	}
	// Uninstall when we're done.
	defer func() {
		if log, err := installtestlib.RunInstaller(ctx, "/x", maxVersionRunfile); err != nil {
			t.Fatalf("error uninstalling: %v\ndetailed log:\n%s", err, log)
		}
	}()

	// Artifacts from the current version should not exist.
	if regExists(t, ctx) {
		t.Errorf("registry key %q is unexpectedly present", registryKey)
	}
	if fileExists(t, ctx, libraryFile) {
		t.Errorf("library file %q is unexpectedly present", libraryFile)
	}

	// Artifacts from the newer version should exist.
	if !fileExists(t, ctx, versionTestFile) {
		t.Errorf("file %q is missing", versionTestFile)
	}
}

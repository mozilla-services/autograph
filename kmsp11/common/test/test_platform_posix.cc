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

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "common/test/test_platform.h"

namespace cloud_kms {

void SetEnvVariable(const char* name, const char* value) {
  setenv(name, value, 1);
}

void ClearEnvVariable(const char* name) { unsetenv(name); }

absl::Status SetMode(const char* filename, int mode) {
  if (chmod(filename, mode) != 0) {
    return absl::PermissionDeniedError(absl::StrFormat(
        "unable to change mode of file %s: error %d", filename, errno));
  }
  return absl::OkStatus();
}

absl::StatusOr<void*> LoadLibrarySymbol(const char* library_filename,
                                        const char* symbol_name) {
  void* library = dlopen(library_filename, RTLD_LAZY | RTLD_NODELETE);
  if (!library) {
    return absl::UnknownError(
        absl::StrCat("failed to load ", library_filename));
  }

  void* symbol = dlsym(library, symbol_name);
  if (!symbol) {
    return absl::NotFoundError(absl::StrFormat(
        "symbol %s not found in library %s", symbol_name, library_filename));
  }
  return symbol;
}

}  // namespace cloud_kms

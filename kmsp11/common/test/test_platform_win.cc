// Copyright 2022 Google LLC
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

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <libloaderapi.h>
#include <process.h>

#include <system_error>

#include "absl/strings/str_format.h"
#include "common/test/test_platform.h"

namespace cloud_kms {

void SetEnvVariable(const char* name, const char* value) {
  _putenv_s(name, value);
}

void ClearEnvVariable(const char* name) { _putenv_s(name, ""); }

absl::Status SetMode(const char* filename, int mode) {
  return absl::UnimplementedError("SetMode is not implemented on Windows");
}

absl::StatusOr<void*> LoadLibrarySymbol(const char* library_filename,
                                        const char* symbol_name) {
  HMODULE library = LoadLibrary(library_filename);
  if (!library) {
    return absl::UnknownError(
        absl::StrFormat("failed to load library %s: %s", library_filename,
                        std::system_category().message(GetLastError())));
  }

  void* symbol = GetProcAddress(library, symbol_name);
  if (!symbol) {
    return absl::NotFoundError(
        absl::StrFormat("symbol %s not found in library %s: %s", symbol_name,
                        std::system_category().message(GetLastError())));
  }
  return symbol;
}

}  // namespace cloud_kms

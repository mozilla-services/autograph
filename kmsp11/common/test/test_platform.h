/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_TEST_TEST_PLATFORM_H_
#define COMMON_TEST_TEST_PLATFORM_H_

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace cloud_kms {

// Set the named environment variable to the provided value, replacing any
// existing value.
void SetEnvVariable(const char* name, const char* value);

// Set the named environment variable to the provided value, replacing any
// existing value.
inline void SetEnvVariable(const std::string& name, const std::string& value) {
  return SetEnvVariable(name.c_str(), value.c_str());
}

// Remove the named variable from the environment, if it exists.
void ClearEnvVariable(const char* name);

// Remove the named variable from the environment, if it exists.
inline void ClearEnvVariable(const std::string& name) {
  ClearEnvVariable(name.c_str());
}

// Set the file mode at the provided path. Note that this always returns
// Unimplemented on Windows.
absl::Status SetMode(const char* filename, int mode);

// Dynamically load the provided library, and locate the enclosed symbol.
absl::StatusOr<void*> LoadLibrarySymbol(const char* library_filename,
                                        const char* symbol_name);

}  // namespace cloud_kms

#endif  // COMMON_TEST_TEST_PLATFORM_H_

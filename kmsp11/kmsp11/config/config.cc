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

#include "kmsp11/config/config.h"

#include <cstdlib>

#include "common/platform.h"
#include "common/status_macros.h"
#include "kmsp11/config/protoyaml.h"
#include "kmsp11/util/errors.h"
#include "yaml-cpp/yaml.h"

namespace cloud_kms::kmsp11 {
namespace {

// Exceptions are disallowed by our style guide. Wrap YAML::LoadFile (which may
// throw) in a noexcept function, and convert thrown exceptions to a reasonable
// absl::Status.
absl::StatusOr<YAML::Node> ParseYamlFile(
    const std::string& file_path) noexcept {
  try {
    return YAML::LoadFile(file_path);
  } catch (const YAML::Exception& e) {
    return NewInvalidArgumentError(
        absl::StrFormat("error parsing file at %s: %s", file_path, e.what()),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }
}

}  // namespace

absl::StatusOr<LibraryConfig> LoadConfigFromEnvironment() {
  char* env_value = std::getenv(kConfigEnvVariable);
  if (!env_value) {
    return FailedPreconditionError(
        absl::StrFormat(
            "cannot load configuration: environment variable %s is not set",
            kConfigEnvVariable),
        CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }
  return LoadConfigFromFile(env_value);
}

absl::StatusOr<LibraryConfig> LoadConfigFromFile(
    const std::string& config_path) {
  ASSIGN_OR_RETURN(YAML::Node node, ParseYamlFile(config_path));
  LibraryConfig config;
  RETURN_IF_ERROR(YamlToProto(node, &config));

  // Checking permissions after we loaded the file, which is weird, but not
  // harmful. This allows better/more specific error messages on
  // missing/malformed file paths, and ought to be replaced for beta. (See
  // b/157499181).
  absl::Status status = EnsureWriteProtected(config_path.c_str());
  if (!status.ok()) {
    SetErrorRv(status, CKR_GENERAL_ERROR);
    return status;
  }

  return config;
}

}  // namespace cloud_kms::kmsp11

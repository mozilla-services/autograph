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

#include "kmscng/config/config.h"

#include <cstdlib>

#include "absl/strings/str_format.h"
#include "common/platform.h"
#include "common/status_macros.h"
#include "kmscng/config/protoyaml.h"
#include "kmscng/util/errors.h"
#include "yaml-cpp/yaml.h"

namespace cloud_kms::kmscng {
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
        NTE_FAIL, SOURCE_LOCATION);
  }
}

}  // namespace

absl::StatusOr<ProviderConfig> LoadConfigFromFile(
    const std::string& config_path) {
  ASSIGN_OR_RETURN(YAML::Node node, ParseYamlFile(config_path));
  ProviderConfig config;
  RETURN_IF_ERROR(YamlToProto(node, &config));

  // TODO(b/157499181): Add config file permissions check.

  return config;
}

}  // namespace cloud_kms::kmscng

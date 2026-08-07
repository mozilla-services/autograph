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

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/test/proto_parser.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/test/matchers.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::HasSubstr;

class ConfigFileTest : public testing::Test {
 protected:
  ConfigFileTest() : config_path_(std::tmpnam(nullptr)){};
  virtual ~ConfigFileTest() { std::remove(config_path_.c_str()); }

  std::string config_path_;
};

TEST_F(ConfigFileTest, SingleToken) {
  std::ofstream(config_path_) << R"(---
resources:
  - crypto_key_version: projects/foo/locations/global/keyRings/bar/cryptoKeys/baz/cryptoKeyVersions/1
)";

  ASSERT_OK_AND_ASSIGN(ProviderConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(
      config, EqualsProto<ProviderConfig>(ParseTestProto(R"pb(
        resources {
          crypto_key_version: "projects/foo/locations/global/keyRings/bar/cryptoKeys/baz/cryptoKeyVersions/1"
        })pb")));
}

TEST_F(ConfigFileTest, MultipleTokens) {
  std::ofstream(config_path_) << R"(---
resources:
  - crypto_key_version: projects/foo/locations/global/keyRings/bar/cryptoKeys/ck/cryptoKeyVersions/1
  - crypto_key_version: projects/foo/locations/global/keyRings/baz/cryptoKeys/ck/cryptoKeyVersions/1
  - crypto_key_version: projects/foo/locations/global/keyRings/qux/cryptoKeys/ck/cryptoKeyVersions/1
)";

  ASSERT_OK_AND_ASSIGN(ProviderConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(
      config, EqualsProto<ProviderConfig>(ParseTestProto(R"pb(
        resources {
          crypto_key_version: "projects/foo/locations/global/keyRings/bar/cryptoKeys/ck/cryptoKeyVersions/1"
        }
        resources {
          crypto_key_version: "projects/foo/locations/global/keyRings/baz/cryptoKeys/ck/cryptoKeyVersions/1"
        }
        resources {
          crypto_key_version: "projects/foo/locations/global/keyRings/qux/cryptoKeys/ck/cryptoKeyVersions/1"
        })pb")));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMalformedConfig) {
  std::ofstream(config_path_) << "this is not yaml";
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ConfigFileTest, LocationProvidedOnMalformedConfig) {
  std::ofstream(config_path_) << R"(---
resources:
  - crypto_key_version: foo/bar/baz
  - fake_field: oops
)";

  absl::StatusOr<ProviderConfig> result = LoadConfigFromFile(config_path_);
  EXPECT_THAT(result.status().message(), HasSubstr("line 3, column 4"));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMissingConfig) {
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace cloud_kms::kmscng

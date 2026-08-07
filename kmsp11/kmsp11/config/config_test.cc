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

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/test/proto_parser.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"

namespace cloud_kms::kmsp11 {
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
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"pb(
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/bar"
                })pb")));
}

TEST_F(ConfigFileTest, MultipleTokens) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
  - key_ring: projects/foo/locations/global/keyRings/baz
  - key_ring: projects/foo/locations/global/keyRings/qux
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"pb(
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/bar"
                }
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/baz"
                }
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/qux"
                })pb")));
}

TEST_F(ConfigFileTest, TokenWithLabel) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
    label: bar
)";

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromFile(config_path_));
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"pb(
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/bar"
                  label: "bar"
                })pb")));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMalformedConfig) {
  std::ofstream(config_path_) << "this is not yaml";
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ConfigFileTest, LocationProvidedOnMalformedConfig) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: foo/bar/baz
  - fake_field: oops
)";

  absl::StatusOr<LibraryConfig> result = LoadConfigFromFile(config_path_);
  EXPECT_THAT(result.status().message(), HasSubstr("line 3, column 4"));
}

TEST_F(ConfigFileTest, InvalidArgumentOnMissingConfig) {
  EXPECT_THAT(LoadConfigFromFile(config_path_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentSuccess) {
  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";
  SetEnvVariable(kConfigEnvVariable, config_path_);
  absl::Cleanup c = [] { ClearEnvVariable(kConfigEnvVariable); };

  ASSERT_OK_AND_ASSIGN(LibraryConfig config, LoadConfigFromEnvironment());
  EXPECT_THAT(config, EqualsProto<LibraryConfig>(ParseTestProto(R"pb(
                tokens {
                  key_ring: "projects/foo/locations/global/keyRings/bar"
                })pb")));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentMissing) {
  absl::StatusOr<LibraryConfig> result = LoadConfigFromEnvironment();
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(result.status().message(), HasSubstr(kConfigEnvVariable));
}

TEST_F(ConfigFileTest, LoadConfigFromEnvironmentInlineFailure) {
  std::string config = R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
)";
  SetEnvVariable(kConfigEnvVariable, config);
  absl::Cleanup c = [] { ClearEnvVariable(kConfigEnvVariable); };

  absl::StatusOr<LibraryConfig> result = LoadConfigFromEnvironment();
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(result.status().message(), HasSubstr("bad file"));
}

TEST_F(ConfigFileTest, LoadConfigFileBadPermissions) {
#ifdef _WIN32
  GTEST_SKIP() << "file permissions checks are not yet supported on windows";
#endif

  std::ofstream(config_path_) << R"(---
tokens:
  - key_ring: projects/foo/locations/global/keyRings/bar
    label: bar
)";
  EXPECT_OK(SetMode(config_path_.c_str(), 0777));

  absl::StatusOr<LibraryConfig> result = LoadConfigFromFile(config_path_);
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(result.status().message(),
              HasSubstr("excessive write permissions"));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

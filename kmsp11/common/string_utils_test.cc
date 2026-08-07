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

#include "common/string_utils.h"

#include <fstream>

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"

namespace cloud_kms {
namespace {

using ::testing::HasSubstr;

TEST(ReadFileToStringTest, FileContentMatches) {
  // TODO: convert to std::filesystem when all build envs support it.
  // This leaks temp files as-is.
  std::string file_path = std::tmpnam(nullptr);
  std::string content = "here is some content";
  std::ofstream(file_path) << content;

  EXPECT_THAT(ReadFileToString(file_path), IsOkAndHolds(content));
}

TEST(ReadFileToStringTest, NonExistentFileReturnsFailedPrecondition) {
  std::string file_path = std::tmpnam(nullptr);
  EXPECT_THAT(ReadFileToString(file_path),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("failed to read file")));
}

TEST(ZeroInitializationTest, ZeroInitializedSuccess) {
  std::vector<uint8_t> data(16, '\0');
  EXPECT_TRUE(IsZeroInitialized(data));
}

TEST(ZeroInitializationTest, NotZeroInitializedFails) {
  std::vector<uint8_t> data(16, '\1');
  EXPECT_FALSE(IsZeroInitialized(data));
}

TEST(ZeroInitializationTest, FirstByteNotZeroFails) {
  std::vector<uint8_t> data(16, '\0');
  data[0] = '\1';
  EXPECT_FALSE(IsZeroInitialized(data));
}

TEST(ZeroInitializationTest, OnlyFirstByteZeroFails) {
  std::vector<uint8_t> data(16, '\1');
  data[0] = '\0';
  EXPECT_FALSE(IsZeroInitialized(data));
}

}  // namespace
}  // namespace cloud_kms

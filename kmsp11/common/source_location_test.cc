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

#include "common/source_location.h"

#include "common/test/matchers.h"
#include "gmock/gmock.h"

namespace cloud_kms {
namespace {

TEST(SourceLocationTest, FixedToString) {
  SourceLocation s(42, "/foo/bar/baz.cc");
  EXPECT_EQ(s.ToString(), "baz.cc:42");
}

TEST(SourceLocationTest, MacroLineNumber) {
  // hardcoding a line number would be a better test, but is likely too brittle
  // to be wortwhile.
  int expected = __LINE__ + 1;
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_EQ(s.line(), expected);
}

TEST(SourceLocationTest, MacroFileName) {
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_THAT(s.file_name(), MatchesStdRegex(".*source_location_test.cc"));
}

TEST(SourceLocationTest, MacroToString) {
  // as above, hardcoding a line number would be a better test, but is likely
  // too brittle to be worthwhile.
  int expected_line = __LINE__ + 1;
  SourceLocation s = SOURCE_LOCATION;
  EXPECT_EQ(s.ToString(),
            absl::StrFormat("source_location_test.cc:%d", expected_line));
}

}  // namespace
}  // namespace cloud_kms

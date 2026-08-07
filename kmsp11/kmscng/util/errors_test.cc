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

#include "kmscng/util/errors.h"

#include "gtest/gtest.h"
#include "kmscng/test/matchers.h"

namespace cloud_kms::kmscng {
namespace {

TEST(NewErrorTest, ErrorCodeMatches) {
  EXPECT_THAT(NewError(absl::StatusCode::kPermissionDenied, "", NTE_BAD_LEN,
                       SOURCE_LOCATION),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(NewErrorTest, FailureOnOkStatus) {
  EXPECT_DEATH(absl::Status s = NewError(absl::StatusCode::kOk, "", NTE_BAD_LEN,
                                         SOURCE_LOCATION),
               "cannot be called with code=OK");
}

TEST(NewErrorTest, MessageMatches) {
  absl::Status status = NewError(absl::StatusCode::kAborted, "foobarbaz",
                                 NTE_BAD_LEN, SOURCE_LOCATION);
  EXPECT_THAT(status.message(), MatchesStdRegex(".*foobarbaz.*"));
}

TEST(NewErrorTest, SsMatches) {
  absl::Status status =
      NewError(absl::StatusCode::kAborted, "", NTE_BAD_KEY, SOURCE_LOCATION);
  EXPECT_EQ(GetErrorSs(status), NTE_BAD_KEY);
}

TEST(NewErrorTest, FailureOnErrorSuccess) {
  EXPECT_DEATH(
      absl::Status s = NewError(absl::StatusCode::kAborted, "foobarbaz",
                                ERROR_SUCCESS, SOURCE_LOCATION),
      "cannot be called with ss=ERROR_SUCCESS");
}

TEST(NewErrorTest, SourceLocationIncluded) {
  SourceLocation s(42, "/path/to/file.cc");
  absl::Status status =
      NewError(absl::StatusCode::kAborted, "message", NTE_BAD_LEN, s);
  EXPECT_THAT(status.message(), MatchesStdRegex(".*" + s.ToString() + ".*"));
}

}  // namespace
}  // namespace cloud_kms::kmscng

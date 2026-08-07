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

#include "kmscng/test/matchers.h"

#include <string_view>

#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::Not;

TEST(StatusSsIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusSsIs(ERROR_SUCCESS));
}

TEST(StatusSsIsTest, OkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(3), StatusSsIs(ERROR_SUCCESS));
}

TEST(StatusSsIsTest, DefaultNotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), StatusSsIs(kDefaultErrorStatus));
}

TEST(StatusSsIsTest, DefaultNotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::CancelledError("cancelled")),
              StatusSsIs(kDefaultErrorStatus));
}

TEST(StatusSsIsTest, CustomNotOkStatus) {
  absl::Status status = absl::AbortedError("aborted");
  SetErrorSs(status, NTE_INVALID_HANDLE);
  EXPECT_THAT(status, StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(StatusSsIsTest, CustomNotOkStatusOr) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorSs(s, NTE_INVALID_PARAMETER);
  EXPECT_THAT(absl::StatusOr<int>(s), StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(StatusSsIsTest, InnerMatcher) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorSs(s, NTE_BAD_FLAGS);
  EXPECT_THAT(s,
              StatusSsIs(testing::AnyOf(NTE_INVALID_PARAMETER, NTE_BAD_FLAGS)));
}

}  // namespace
}  // namespace cloud_kms::kmscng

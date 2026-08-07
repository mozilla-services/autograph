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

#include "kmsp11/test/matchers.h"

#include <string_view>

#include "absl/status/statusor.h"
#include "common/test_message.pb.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::Not;

TEST(StatusRvIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusRvIs(CKR_OK));
}

TEST(StatusRvIsTest, OkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(3), StatusRvIs(CKR_OK));
}

TEST(StatusRvIsTest, DefaultNotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), StatusRvIs(kDefaultErrorCkRv));
}

TEST(StatusRvIsTest, DefaultNotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::CancelledError("cancelled")),
              StatusRvIs(kDefaultErrorCkRv));
}

TEST(StatusRvIsTest, CustomNotOkStatus) {
  absl::Status status = absl::AbortedError("aborted");
  SetErrorRv(status, CKR_DEVICE_ERROR);
  EXPECT_THAT(status, StatusRvIs(CKR_DEVICE_ERROR));
}

TEST(StatusRvIsTest, CustomNotOkStatusOr) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorRv(s, CKR_HOST_MEMORY);
  EXPECT_THAT(absl::StatusOr<int>(s), StatusRvIs(CKR_HOST_MEMORY));
}

TEST(StatusRvIsTest, InnerMatcher) {
  absl::Status s = absl::CancelledError("cancelled");
  SetErrorRv(s, CKR_DATA_LEN_RANGE);
  EXPECT_THAT(
      s, StatusRvIs(testing::AnyOf(CKR_FUNCTION_FAILED, CKR_DATA_LEN_RANGE)));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

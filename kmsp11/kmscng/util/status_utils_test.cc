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

#include "kmscng/util/status_utils.h"

#include <windows.h>

#include "absl/status/status.h"
#include "gmock/gmock.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(SetErrorSsTest, SetErrorSsOnErrorStatus) {
  absl::Status s = absl::ResourceExhaustedError("foo");
  EXPECT_NO_FATAL_FAILURE(SetErrorSs(s, NTE_BAD_KEY));
}

TEST(SetErrorSsTest, SetErrorSsOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorSs(s, NTE_BAD_LEN), "attempting to set ss=");
}

TEST(SetErrorSsTest, SetOkSsOnErrorStatus) {
  absl::Status s = absl::OutOfRangeError("bar");
  EXPECT_DEATH(SetErrorSs(s, ERROR_SUCCESS),
               "attempting to set ss=0 for status OUT_OF_RANGE");
}

TEST(SetErrorSsTest, SetOkSsOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorSs(s, ERROR_SUCCESS),
               "attempting to set ss=0 for status OK");
}

TEST(SetErrorSsTest, OkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_EQ(GetErrorSs(s), ERROR_SUCCESS);
}

TEST(GetErrorSsTest, DefaultError) {
  EXPECT_EQ(GetErrorSs(absl::AbortedError("foo")), NTE_FAIL);
}

TEST(GetErrorSsTest, RetrieveSetValue) {
  absl::Status s = absl::UnknownError("foo");
  SetErrorSs(s, NTE_BAD_LEN);
  EXPECT_EQ(GetErrorSs(s), NTE_BAD_LEN);
}

TEST(StatusPayloadTest, StatusToStringIsReadable) {
  ASSERT_EQ(NTE_BAD_LEN, 0x80090004);

  absl::Status s = absl::FailedPreconditionError("session is closed");
  SetErrorSs(s, NTE_BAD_LEN);

  EXPECT_THAT(s.ToString(), AllOf(HasSubstr("session is closed"),
                                  HasSubstr("SECURITY_STATUS=0x80090004")));
}

}  // namespace
}  // namespace cloud_kms::kmscng

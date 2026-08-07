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

#include "kmsp11/util/status_utils.h"

#include "absl/status/status.h"
#include "gmock/gmock.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(SetErrorRvTest, SetErrorRvOnErrorStatus) {
  absl::Status s = absl::ResourceExhaustedError("foo");
  EXPECT_NO_FATAL_FAILURE(SetErrorRv(s, CKR_INFORMATION_SENSITIVE));
}

TEST(SetErrorRvTest, SetErrorRvOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorRv(s, CKR_ARGUMENTS_BAD),
               "attempting to set rv=7 for status OK");
}

TEST(SetErrorRvTest, SetOkRvOnErrorStatus) {
  absl::Status s = absl::OutOfRangeError("bar");
  EXPECT_DEATH(SetErrorRv(s, CKR_OK),
               "attempting to set rv=0 for status OUT_OF_RANGE");
}

TEST(SetErrorRvTest, SetOkRvOnOkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_DEATH(SetErrorRv(s, CKR_OPERATION_NOT_INITIALIZED),
               "attempting to set rv=145 for status OK");
}

TEST(SetErrorRvTest, OkStatus) {
  absl::Status s = absl::OkStatus();
  EXPECT_EQ(GetCkRv(s), CKR_OK);
}

TEST(GetCkRvTest, DefaultError) {
  EXPECT_EQ(GetCkRv(absl::AbortedError("foo")), CKR_FUNCTION_FAILED);
}

TEST(GetCkRvTest, RetrieveSetValue) {
  absl::Status s = absl::UnknownError("foo");
  SetErrorRv(s, CKR_ATTRIBUTE_TYPE_INVALID);
  EXPECT_EQ(GetCkRv(s), CKR_ATTRIBUTE_TYPE_INVALID);
}

TEST(GetCkRvTest, RetrieveVendorDefinedSetValue) {
  CK_RV custom_value = CKR_VENDOR_DEFINED | 0x1E100;
  absl::Status s = absl::UnknownError("foo");
  SetErrorRv(s, custom_value);
  EXPECT_EQ(GetCkRv(s), custom_value);
}

TEST(StatusPayloadTest, StatusToStringIsReadable) {
  ASSERT_EQ(CKR_SESSION_CLOSED, 0xb0);

  absl::Status s = absl::FailedPreconditionError("session is closed");
  SetErrorRv(s, CKR_SESSION_CLOSED);

  EXPECT_THAT(s.ToString(),
              AllOf(HasSubstr("session is closed"), HasSubstr("CK_RV=0xb0")));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

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

#include "kmscng/util/logging.h"

#include <filesystem>

#include "absl/cleanup/cleanup.h"
#include "absl/log/log.h"
#include "absl/strings/escaping.h"
#include "common/string_utils.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "grpc/grpc.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/errors.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

TEST(LoggingTest, StandardErrorIsEmptyWhenNoLogMessageAreEmitted) {
  CaptureStderr();

  LogAndResolve("foo", absl::OkStatus());

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST(LoggingTest, LogAndResolveWritesToStandardError) {
  CaptureStderr();
  absl::Status error = absl::InvalidArgumentError("foobarbaz");

  LogAndResolve("foo", error);

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(error.ToString()));
}

TEST(LoggingTest, UninitializedLogsInfoToStandardError) {
  CaptureStderr();

  std::string message = "Here is a sample message";
  LOG(INFO) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, UninitializedLogsWarningToStandardError) {
  CaptureStderr();

  std::string message = "Here is a sample message";
  LOG(WARNING) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, UninitializedLogsErrorToStandardError) {
  CaptureStderr();

  std::string message = "Here is a sample message";
  LOG(ERROR) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, UninitializedLogsFatalToStandardError) {
  std::string message = "Here is a sample message";
  EXPECT_DEATH({ LOG(FATAL) << message; }, HasSubstr(message));
}

}  // namespace
}  // namespace cloud_kms::kmscng

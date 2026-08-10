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

#include "kmsp11/util/logging.h"

#include <filesystem>

#include "absl/cleanup/cleanup.h"
#include "absl/log/absl_log.h"
#include "common/platform.h"
#include "common/test/test_status_macros.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "grpc/grpc.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

TEST(LoggingTest, StandardErrorIsEmptyWhenNoLogMessageAreEmitted) {
  CaptureStderr();

  ASSERT_OK(InitializeLogging("", ""));
  ShutdownLogging();

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST(LoggingTest, LogAndResolveWithUninitializedLoggerWritesToStandardError) {
  CaptureStderr();
  absl::Status error = absl::InvalidArgumentError("foobarbaz");

  LogAndResolve("foo", error);

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(error.ToString()));
}

TEST(LoggingTest, NoDirectoryLogsInfoToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(INFO) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsWarningToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(WARNING) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsErrorToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(ERROR) << message;

  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

TEST(LoggingTest, NoDirectoryLogsFatalToStandardError) {
  ASSERT_OK(InitializeLogging("", ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  EXPECT_DEATH({ LOG(FATAL) << message; }, HasSubstr(message));
}

TEST(LoggingTest, FilenameSuffixIgnoredWhenNoDirectoryIsSpecified) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging("", "foobar"));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  LOG(ERROR) << message;
  EXPECT_THAT(GetCapturedStderr(), HasSubstr(message));
}

class LogDirectoryTest : public testing::Test {
 protected:
  void SetUp() override {
    log_directory_ =
        std::filesystem::temp_directory_path().append(RandomId()).string();
    ASSERT_TRUE(std::filesystem::create_directory(log_directory_));
  }

  void TearDown() override {
    std::error_code code;
    std::filesystem::remove_all(log_directory_, code);
    ASSERT_EQ(code.value(), 0);
  }

  std::vector<std::filesystem::directory_entry> LogDirectoryEntries() {
    std::filesystem::recursive_directory_iterator iter(log_directory_);
    return std::vector<std::filesystem::directory_entry>(
        std::filesystem::begin(iter), std::filesystem::end(iter));
  }

  std::string log_directory_;
};

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogInfoToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(INFO) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogWarningToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(WARNING) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedDoesNotLogErrorToStandardError) {
  CaptureStderr();
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(ERROR) << "Here is a sample message";

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, DirectorySpecifiedLogsFatalToStandardError) {
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  std::string message = "Here is a sample message";
  EXPECT_DEATH({ LOG(FATAL) << message; }, HasSubstr(message));
}

TEST_F(LogDirectoryTest, LogFilenameMatchesExpectedPattern) {
  ASSERT_OK(InitializeLogging(log_directory_, ""));
  absl::Cleanup c = ShutdownLogging;

  LOG(WARNING) << "Here is a sample message";

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(files[0].path().filename().string(),
              MatchesStdRegex("libkmsp11\\.log-\\d{8}-\\d{6}\\.\\d+"));
}

TEST_F(LogDirectoryTest, LogFilenameMatchesExpectedPatternWithSuffix) {
  ASSERT_OK(InitializeLogging(log_directory_, "foobar"));
  absl::Cleanup c = ShutdownLogging;

  LOG(ERROR) << "Here is a sample message";

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(files[0].path().filename().string(),
              MatchesStdRegex("libkmsp11\\.log-foobar-\\d{8}-\\d{6}\\.\\d+"));
}

TEST_F(LogDirectoryTest, SingleFileContainsAllLogLevels) {
  std::string info_message = "Info message";
  std::string warning_message = "Warning message";
  std::string error_message = "Error message";

  {
    // Using a separate scope to ensure logfiles are flushed.
    ASSERT_OK(InitializeLogging(log_directory_, ""));
    absl::Cleanup c = ShutdownLogging;

    LOG(INFO) << info_message;
    LOG(WARNING) << warning_message;
    LOG(ERROR) << error_message;
  }

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(
      ReadFileToString(files[0].path().string()),
      IsOkAndHolds(AllOf(HasSubstr(error_message), HasSubstr(warning_message),
                         HasSubstr(info_message))));
}

TEST_F(LogDirectoryTest, GrpcErrorsAreLoggedToGlogDestination) {
  std::string error_message = "Error message";
  std::string info_message = "Info message";
  std::string debug_message = "Debug message";
  CaptureStderr();

  // In customer code, this would be set using the GRPC_VERBOSITY environment
  // variable. However, that environment variable is only read once per process,
  // so isn't reliable in the context of unit tests that share a process.
  gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
  absl::Cleanup c = [] { gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR); };

  {
    // Using a separate scope to ensure logfiles are flushed.
    ASSERT_OK(InitializeLogging(log_directory_, ""));
    absl::Cleanup c = ShutdownLogging;

    grpc_init();
    gpr_log(GPR_ERROR, "%s", error_message.c_str());
    gpr_log(GPR_INFO, "%s", info_message.c_str());
    gpr_log(GPR_DEBUG, "%s", debug_message.c_str());
  }

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(
      ReadFileToString(files[0].path().string()),
      IsOkAndHolds(AllOf(HasSubstr(error_message), HasSubstr(info_message),
                         HasSubstr(debug_message))));
  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(LogDirectoryTest, AbseilErrorsAreLoggedToGlogDestination) {
  std::string message = "Here is my test message";
  CaptureStderr();

  ASSERT_OK(InitializeLogging(log_directory_, ""));
  ABSL_LOG(WARNING) << message;
  ShutdownLogging();

  std::vector<std::filesystem::directory_entry> files = LogDirectoryEntries();
  ASSERT_THAT(files, SizeIs(1));
  EXPECT_THAT(ReadFileToString(files[0].path().string()),
              IsOkAndHolds((HasSubstr(message))));
  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

}  // namespace
}  // namespace cloud_kms::kmsp11

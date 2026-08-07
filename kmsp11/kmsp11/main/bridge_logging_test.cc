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

#include <filesystem>
#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/platform.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;

class BridgeLoggingTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto client = fake_server_->NewClient();
    kr_ = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr_);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
    ck = CreateCryptoKeyOrDie(client.get(), kr_.name(), RandomId(), ck, false);

    root_directory_ =
        std::filesystem::temp_directory_path().append(RandomId()).string();
    ASSERT_TRUE(std::filesystem::create_directories(root_directory_));

    config_file_ = absl::StrCat(root_directory_, "/config.yaml");
    std::ofstream(config_file_)
        << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                           kr_.name(), fake_server_->listen_addr());

    init_args_ = {0};
    init_args_.flags = CKF_OS_LOCKING_OK;
    init_args_.pReserved = const_cast<char*>(config_file_.c_str());
  }

  void TearDown() override {
    std::error_code code;
    std::filesystem::remove_all(root_directory_, code);
    ASSERT_EQ(code.value(), 0);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  kms_v1::KeyRing kr_;
  std::string root_directory_;
  std::string config_file_;
  CK_C_INITIALIZE_ARGS init_args_;
};

TEST_F(BridgeLoggingTest, InitializationWarningsAreLogged) {
  // Create a key that will be skipped at init time (purpose==ENCRYPT_DECRYPT)
  auto fake_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_protection_level(kms_v1::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr_.name(), "ck", ck, true);

  testing::internal::CaptureStderr();
  ASSERT_OK(Initialize(&init_args_));
  ASSERT_OK(Finalize(nullptr));

  EXPECT_THAT(testing::internal::GetCapturedStderr(),
              HasSubstr("unsupported purpose"));
}

TEST_F(BridgeLoggingTest, LoggingIsInitializedBeforeKmsCallsAreMade) {
  // Create a key that will be skipped at init time (purpose==ENCRYPT_DECRYPT)
  auto fake_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_protection_level(kms_v1::HSM);
  ck = CreateCryptoKeyOrDie(fake_client.get(), kr_.name(), "ck", ck, true);

  testing::internal::CaptureStderr();
  ASSERT_OK(Initialize(&init_args_));
  ASSERT_OK(Finalize(nullptr));

  EXPECT_THAT(testing::internal::GetCapturedStderr(),
              Not(HasSubstr("WARNING: Logging before InitGoogleLogging()")));
}

TEST_F(BridgeLoggingTest,
       InitializationWithLogDirectoryDoesNotEmitToStandardError) {
  std::string log_directory = absl::StrCat(root_directory_, "/log");
  ASSERT_TRUE(std::filesystem::create_directory(log_directory));

  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "log_directory: " << log_directory << std::endl;
  testing::internal::CaptureStderr();

  ASSERT_OK(Initialize(&init_args_));
  ASSERT_OK(Finalize(nullptr));

  EXPECT_THAT(testing::internal::GetCapturedStderr(), IsEmpty());
}

TEST_F(BridgeLoggingTest, GrpcErrorEventEmittedWithDefaultVerbosity) {
  std::string log_directory = absl::StrCat(root_directory_, "/log");
  ASSERT_TRUE(std::filesystem::create_directory(log_directory));
  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "log_directory: " << log_directory << std::endl;

  ASSERT_OK(Initialize(&init_args_));
  // Default verbosity is ERROR.
  EXPECT_EQ(gpr_should_log(GPR_LOG_SEVERITY_ERROR), 1);
  std::string message = "This error message should appear in the logs.";
  gpr_log("foo.cc", 42, GPR_LOG_SEVERITY_ERROR, "%s", message.c_str());
  ASSERT_OK(Finalize(nullptr));

  std::filesystem::recursive_directory_iterator log_iter(log_directory);
  std::vector<std::filesystem::directory_entry> log_files(
      std::filesystem::begin(log_iter), std::filesystem::end(log_iter));

  ASSERT_THAT(log_files, SizeIs(1));
  EXPECT_THAT(ReadFileToString(log_files[0].path().string()),
              IsOkAndHolds(HasSubstr(message)));
}

TEST_F(BridgeLoggingTest, GrpcDebugEventNotEmittedWithDefaultVerbosity) {
  std::string log_directory = absl::StrCat(root_directory_, "/log");
  ASSERT_TRUE(std::filesystem::create_directory(log_directory));
  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "log_directory: " << log_directory << std::endl;

  ASSERT_OK(Initialize(&init_args_));
  // Default verbosity is ERROR.
  EXPECT_EQ(gpr_should_log(GPR_LOG_SEVERITY_DEBUG), 0);
  std::string message = "This message shouldn't appear in the logs.";
  gpr_log("foo.cc", 42, GPR_LOG_SEVERITY_DEBUG, "%s", message.c_str());
  ASSERT_OK(Finalize(nullptr));

  std::filesystem::recursive_directory_iterator log_iter(log_directory);
  std::vector<std::filesystem::directory_entry> log_files(
      std::filesystem::begin(log_iter), std::filesystem::end(log_iter));

  ASSERT_THAT(log_files, SizeIs(1));
  EXPECT_THAT(ReadFileToString(log_files[0].path().string()),
              IsOkAndHolds(Not(HasSubstr(message))));
}

TEST_F(BridgeLoggingTest, GrpcDebugEventEmittedWhenVerbosityIsDebug) {
  std::string log_directory = absl::StrCat(root_directory_, "/log");
  ASSERT_TRUE(std::filesystem::create_directory(log_directory));
  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "log_directory: " << log_directory << std::endl;

  // In customer code, this would be set using the GRPC_VERBOSITY environment
  // variable. However, that environment variable is only read once per process,
  // the first time grpc_init() is invoked, so isn't reliable in the context of
  // unit tests that share a process with numerous grpc clients.
  gpr_set_log_verbosity(GPR_LOG_SEVERITY_DEBUG);
  absl::Cleanup c = [] { gpr_set_log_verbosity(GPR_LOG_SEVERITY_ERROR); };

  ASSERT_OK(Initialize(&init_args_));
  EXPECT_EQ(gpr_should_log(GPR_LOG_SEVERITY_DEBUG), 1);
  std::string message = "This message should appear in the logs.";
  gpr_log("foo.cc", 42, GPR_LOG_SEVERITY_DEBUG, "%s", message.c_str());
  ASSERT_OK(Finalize(nullptr));

  std::filesystem::recursive_directory_iterator log_iter(log_directory);
  std::vector<std::filesystem::directory_entry> log_files(
      std::filesystem::begin(log_iter), std::filesystem::end(log_iter));

  ASSERT_THAT(log_files, SizeIs(1));
  EXPECT_THAT(ReadFileToString(log_files[0].path().string()),
              IsOkAndHolds(HasSubstr(message)));
}

TEST_F(BridgeLoggingTest, ExistingSslErrorIsClearedAndLogged) {
  std::string log_directory = absl::StrCat(root_directory_, "/log");
  ASSERT_TRUE(std::filesystem::create_directory(log_directory));
  std::ofstream(config_file_, std::ofstream::out | std::ofstream::app)
      << "log_directory: " << log_directory << std::endl;

  {
    ASSERT_OK(Initialize(&init_args_));
    absl::Cleanup c = [] { ASSERT_OK(Finalize(nullptr)); };

    // Add an OpenSSL error to the stack, and invoke a P11 function through the
    // front door.
    ASSERT_FALSE(EC_KEY_new_by_curve_name(NID_rsa));
    ASSERT_NE(ERR_peek_error(), 0);
    CK_INFO info;
    ASSERT_EQ(C_GetInfo(&info), CKR_OK);
  }

  std::filesystem::recursive_directory_iterator log_iter(log_directory);
  std::vector<std::filesystem::directory_entry> log_files(
      std::filesystem::begin(log_iter), std::filesystem::end(log_iter));

  ASSERT_THAT(log_files, SizeIs(1));
  EXPECT_THAT(
      ReadFileToString(log_files[0].path().string()),
      IsOkAndHolds(HasSubstr("Found an existing OpenSSL error on the stack")));
  EXPECT_EQ(ERR_peek_error(), 0);
}

}  // namespace
}  // namespace cloud_kms::kmsp11

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

#include "kmsp11/main/bridge.h"

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/openssl.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/test/common_setup.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsSupersetOf;
using ::testing::Not;

TEST(BridgeTest, InitializeFromArgs) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };
  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  EXPECT_OK(Finalize(nullptr));
}

TEST(BridgeTest, InitializeFailsOnSecondCall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  EXPECT_THAT(Initialize(&init_args),
              StatusRvIs(CKR_CRYPTOKI_ALREADY_INITIALIZED));
}

TEST(BridgeTest, InitializeFromEnvironment) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  SetEnvVariable(kConfigEnvVariable, config_file);
  absl::Cleanup c = [] { ClearEnvVariable(kConfigEnvVariable); };

  EXPECT_OK(Initialize(nullptr));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST(BridgeTest, InitArgsWithoutReservedLoadsFromEnv) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  SetEnvVariable(kConfigEnvVariable, config_file);
  absl::Cleanup c = [] { ClearEnvVariable(kConfigEnvVariable); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  EXPECT_OK(Initialize(&init_args));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST(BridgeTest, InitializeFailsWithoutConfig) {
  EXPECT_THAT(Initialize(nullptr),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(BridgeTest, InitializeSucceedsWithEmptyArgs) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  SetEnvVariable(kConfigEnvVariable, config_file);
  absl::Cleanup c = [] { ClearEnvVariable(kConfigEnvVariable); };
  CK_C_INITIALIZE_ARGS init_args = {0};

  EXPECT_OK(Initialize(&init_args));
  // Finalize so that other tests see an uninitialized state
  EXPECT_OK(Finalize(nullptr));
}

TEST(BridgeTest, InitializeFailsWithArgsNoOsLocking) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  int temp = 7337;
  init_args.flags = 0;
  init_args.LockMutex = (CK_LOCKMUTEX)&temp;

  EXPECT_THAT(Initialize(&init_args), StatusRvIs(CKR_CANT_LOCK));
}

TEST(BridgeTest, InitializeFailsWithArgsNoThreads) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK | CKF_LIBRARY_CANT_CREATE_OS_THREADS;

  EXPECT_THAT(Initialize(&init_args), StatusRvIs(CKR_NEED_TO_CREATE_THREADS));
}

TEST(BridgeTest, InitializeFailsWithArgsNoConfig) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;

  EXPECT_THAT(Initialize(&init_args),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("cannot load configuration")));
}

TEST(BridgeTest, FinalizeFailsWithoutInitialize) {
  EXPECT_THAT(Finalize(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetInfoSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };
  CK_INFO info;
  EXPECT_OK(GetInfo(&info));
}

TEST(BridgeTest, GetInfoFailsWithoutInitialize) {
  EXPECT_THAT(GetInfo(nullptr), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetInfoFailsNullPtr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(GetInfo(nullptr), StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GetFunctionListSuccess) {
  CK_FUNCTION_LIST* function_list;
  EXPECT_OK(GetFunctionList(&function_list));
}

TEST(BridgeTest, FunctionListValidPointers) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  CK_FUNCTION_LIST* f;
  EXPECT_OK(GetFunctionList(&f));

  EXPECT_EQ(f->C_Initialize(&init_args), CKR_OK);
  CK_INFO info;
  EXPECT_EQ(f->C_GetInfo(&info), CKR_OK);
  EXPECT_EQ(f->C_Finalize(nullptr), CKR_OK);
}

TEST(BridgeTest, GetFunctionListFailsNullPtr) {
  EXPECT_THAT(GetFunctionList(nullptr), StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GetSlotListFailsNotInitialized) {
  EXPECT_THAT(GetSlotList(false, nullptr, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetSlotListReturnsSlots) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  // Initialize two keyrings and create a configuration file.
  auto client = fake_server->NewClient();
  kms_v1::KeyRing kr1, kr2;
  kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
  kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         kr1.name(), kr2.name(), fake_server->listen_addr());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  std::vector<CK_SLOT_ID> slots(2);
  CK_ULONG slots_size = slots.size();
  EXPECT_OK(GetSlotList(false, slots.data(), &slots_size));
  EXPECT_EQ(slots_size, 2);
  EXPECT_THAT(slots, ElementsAre(0, 1));
}

TEST(BridgeTest, GetSlotListReturnsSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  // Initialize two keyrings and create a configuration file.
  auto client = fake_server->NewClient();
  kms_v1::KeyRing kr1, kr2;
  kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
  kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         kr1.name(), kr2.name(), fake_server->listen_addr());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_ULONG slots_size;
  EXPECT_OK(GetSlotList(false, nullptr, &slots_size));
  EXPECT_EQ(slots_size, 2);
}

TEST(BridgeTest, GetSlotListFailsBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  // Initialize two keyrings and create a configuration file.
  auto client = fake_server->NewClient();
  kms_v1::KeyRing kr1, kr2;
  kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
  kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         kr1.name(), kr2.name(), fake_server->listen_addr());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  std::vector<CK_SLOT_ID> slots(1);
  CK_ULONG slots_size = slots.size();
  EXPECT_THAT(GetSlotList(false, slots.data(), &slots_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(slots_size, 2);
}

TEST(BridgeTest, GetSlotInfoSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SLOT_INFO info;
  EXPECT_OK(GetSlotInfo(0, &info));

  // Sanity check for any piece of information we set
  EXPECT_EQ(info.flags & CKF_TOKEN_PRESENT, CKF_TOKEN_PRESENT);
}

TEST(BridgeTest, GetSlotInfoFailsNotInitialized) {
  EXPECT_THAT(GetSlotInfo(0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetSlotInfoFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(GetSlotInfo(2, nullptr), StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, GetTokenInfoSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_TOKEN_INFO info;
  EXPECT_OK(GetTokenInfo(0, &info));

  // Sanity check for any piece of information we set
  EXPECT_EQ(info.flags & CKF_TOKEN_INITIALIZED, CKF_TOKEN_INITIALIZED);
}

TEST(BridgeTest, GetTokenInfoFailsNotInitialized) {
  EXPECT_THAT(GetTokenInfo(0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetTokenInfoFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(GetTokenInfo(2, nullptr), StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, OpenSession) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_NE(handle, CK_INVALID_HANDLE);
}

TEST(BridgeTest, OpenSessionFailsNotInitialized) {
  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(0, 0, nullptr, nullptr, &handle),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, OpenSessionFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(2, CKF_SERIAL_SESSION, nullptr, nullptr, &handle),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, OpenSessionFailsNotSerial) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_THAT(OpenSession(0, 0, nullptr, nullptr, &handle),
              StatusRvIs(CKR_SESSION_PARALLEL_NOT_SUPPORTED));
}

TEST(BridgeTest, OpenSessionReadWrite) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));

  EXPECT_EQ(info.state, CKS_RW_PUBLIC_SESSION);
  EXPECT_EQ(info.flags & CKF_RW_SESSION, CKF_RW_SESSION);
}

TEST(BridgeTest, CloseSessionSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_OK(CloseSession(handle));
}

TEST(BridgeTest, CloseSessionFailsNotInitialized) {
  EXPECT_THAT(CloseSession(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, CloseSessionFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_THAT(CloseSession(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, CloseSessionFailsAlreadyClosed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));
  EXPECT_OK(CloseSession(handle));

  EXPECT_THAT(CloseSession(handle), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, CloseAllSessionsSuccessfullyClosesCorrectSessions) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  // Initialize two keyrings and create a configuration file.
  auto client = fake_server->NewClient();
  kms_v1::KeyRing kr1, kr2;
  kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
  kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
    label: "foo"
  - key_ring: "%s"
    label: "bar"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         kr1.name(), kr2.name(), fake_server->listen_addr());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE h1, h2, h3, h4;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &h1));
  EXPECT_OK(OpenSession(1, CKF_SERIAL_SESSION, nullptr, nullptr, &h2));
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &h3));
  EXPECT_OK(OpenSession(1, CKF_SERIAL_SESSION, nullptr, nullptr, &h4));
  EXPECT_OK(CloseAllSessions(0));

  EXPECT_THAT(CloseSession(h1), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
  EXPECT_OK(CloseSession(h2));
  EXPECT_THAT(CloseSession(h3), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
  EXPECT_OK(CloseSession(h4));
}

TEST(BridgeTest, CloseAllSessionsFailsNotInitialized) {
  EXPECT_THAT(CloseAllSessions(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, CloseAllSessionFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(CloseAllSessions(1337), StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, GetSessionInfoSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));

  // Sanity check for any piece of information
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST(BridgeTest, GetSessionInfoFailsNotInitialized) {
  CK_SESSION_INFO info;
  EXPECT_THAT(GetSessionInfo(0, &info),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetSessionInfoFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_INFO info;
  EXPECT_THAT(GetSessionInfo(0, &info), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, LoginSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));
  EXPECT_EQ(info.state, CKS_RO_USER_FUNCTIONS);
}

TEST(BridgeTest, LoginAppliesToAllSessions) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle1;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle1));

  CK_SESSION_HANDLE handle2;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle2));

  EXPECT_OK(Login(handle2, CKU_USER, nullptr, 0));

  EXPECT_THAT(Login(handle1, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_USER_ALREADY_LOGGED_IN));
  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle1, &info));
  EXPECT_EQ(info.state, CKS_RO_USER_FUNCTIONS);
}

TEST(BridgeTest, LoginFailsNotInitialized) {
  EXPECT_THAT(Login(0, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, LoginFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(Login(0, CKU_USER, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, LoginFailsUserSo) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_THAT(Login(handle, CKU_SO, nullptr, 0), StatusRvIs(CKR_PIN_LOCKED));
}

TEST(BridgeTest, LogoutSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle));

  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle, &info));
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST(BridgeTest, LogoutAppliesToAllSessions) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle1;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle1));

  CK_SESSION_HANDLE handle2;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle2));

  EXPECT_OK(Login(handle2, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle1));

  EXPECT_THAT(Logout(handle2), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
  CK_SESSION_INFO info;
  EXPECT_OK(GetSessionInfo(handle2, &info));
  EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
}

TEST(BridgeTest, LogoutFailsNotInitialized) {
  EXPECT_THAT(Logout(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, LogoutFailsInvalidHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(Logout(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, LogoutFailsNotLoggedIn) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_THAT(Logout(handle), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

TEST(BridgeTest, LogoutFailsSecondCall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE handle;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &handle));

  EXPECT_OK(Login(handle, CKU_USER, nullptr, 0));
  EXPECT_OK(Logout(handle));

  EXPECT_THAT(Logout(handle), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

TEST(BridgeTest, GetMechanismListSucceeds) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_ULONG count;
  EXPECT_OK(GetMechanismList(0, nullptr, &count));

  std::vector<CK_MECHANISM_TYPE> types(count);
  EXPECT_OK(GetMechanismList(0, types.data(), &count));
  EXPECT_EQ(types.size(), count);
  EXPECT_THAT(types,
              IsSupersetOf({CKM_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_RSA_PKCS_OAEP,
                            CKM_ECDSA, CKM_SHA_1_HMAC, CKM_CLOUDKMS_AES_GCM}));
}

TEST(BridgeTest, GetMechanismListFailsInvalidSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  std::vector<CK_MECHANISM_TYPE> types(1);
  CK_ULONG count = 1;
  EXPECT_THAT(GetMechanismList(0, types.data(), &count),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_THAT(count, Ge(4));
}

TEST(BridgeTest, GetMechanismListFailsNotInitialized) {
  CK_ULONG count;
  EXPECT_THAT(GetMechanismList(0, nullptr, &count),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetMechanismListFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_ULONG count;
  EXPECT_THAT(GetMechanismList(5, nullptr, &count),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, GetMechanismInfo) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_MECHANISM_INFO info;
  EXPECT_OK(GetMechanismInfo(0, CKM_RSA_PKCS_PSS, &info));

  EXPECT_EQ(info.ulMinKeySize, 2048);
  EXPECT_EQ(info.ulMaxKeySize, 4096);
  EXPECT_EQ(info.flags, CKF_SIGN | CKF_VERIFY);
}

TEST(BridgeTest, GetMechanismInfoFailsInvalidMechanism) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(0, CKM_RSA_X9_31, &info),
              StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(BridgeTest, GetMechanismInfoMacKeys) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_MECHANISM_INFO info;
  EXPECT_OK(GetMechanismInfo(0, CKM_SHA256_HMAC, &info));

  EXPECT_EQ(info.ulMinKeySize, 32);
  EXPECT_EQ(info.ulMaxKeySize, 32);
  EXPECT_EQ(info.flags, CKF_SIGN | CKF_VERIFY);
}

TEST(BridgeTest, GetMechanismInfoRawEncryptionKeys) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_MECHANISM_INFO info;
  EXPECT_OK(GetMechanismInfo(0, CKM_CLOUDKMS_AES_GCM, &info));

  EXPECT_EQ(info.ulMinKeySize, 16);
  EXPECT_EQ(info.ulMaxKeySize, 32);
  EXPECT_EQ(info.flags, CKF_DECRYPT | CKF_ENCRYPT);
}

TEST(BridgeTest, GetMechanismInfoFailsNotInitialized) {
  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(0, CKM_RSA_PKCS, &info),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetMechanismInfoFailsInvalidSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_MECHANISM_INFO info;
  EXPECT_THAT(GetMechanismInfo(5, CKM_RSA_PKCS_PSS, &info),
              StatusRvIs(CKR_SLOT_ID_INVALID));
}

TEST(BridgeTest, GetAttributeValueSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_KEY_TYPE key_type;
  CK_ATTRIBUTE key_type_attr = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};
  EXPECT_OK(GetAttributeValue(session, object, &key_type_attr, 1));
  EXPECT_EQ(key_type, CKK_EC);
}

TEST(BridgeTest, GetAttributeValueFailsSensitiveAttribute) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char key_value[256];
  CK_ATTRIBUTE value_attr = {CKA_VALUE, key_value, 256};
  EXPECT_THAT(GetAttributeValue(session, object, &value_attr, 1),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_EQ(value_attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST(BridgeTest, GetAttributeValueFailsNonExistentAttribute) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char modulus[256];
  CK_ATTRIBUTE mod_attr = {CKA_MODULUS, modulus, 256};
  EXPECT_THAT(GetAttributeValue(session, object, &mod_attr, 1),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_EQ(mod_attr.ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST(BridgeTest, GetAttributeValueSuccessNoBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_ATTRIBUTE public_key = {CKA_PUBLIC_KEY_INFO, nullptr, 0};
  EXPECT_OK(GetAttributeValue(session, object, &public_key, 1));
}

TEST(BridgeTest, GetAttributeValueFailureBufferTooShort) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  char buf[2];
  CK_ATTRIBUTE ec_params = {CKA_EC_PARAMS, buf, 2};
  EXPECT_THAT(GetAttributeValue(session, object, &ec_params, 1),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_GT(ec_params.ulValueLen, 2);
}

TEST(BridgeTest, GetAttributeValueFailureAllAttributesProcessed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  CK_BBOOL decrypt, token;
  char value_buf[2], point_buf[2], modulus_buf[2];
  CK_ATTRIBUTE attr_results[5] = {
      {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
      {CKA_VALUE, value_buf, sizeof(value_buf)},
      {CKA_EC_POINT, point_buf, sizeof(point_buf)},
      {CKA_MODULUS, modulus_buf, sizeof(modulus_buf)},
      {CKA_TOKEN, &token, sizeof(token)},
  };

  EXPECT_THAT(GetAttributeValue(session, object, attr_results, 5),
              StatusRvIs(AnyOf(CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_SENSITIVE,
                               CKR_ATTRIBUTE_TYPE_INVALID)));

  // All valid attributes with sufficient buffer space were processed.
  EXPECT_EQ(decrypt, CK_FALSE);
  EXPECT_EQ(attr_results[0].ulValueLen, 1);
  EXPECT_EQ(token, CK_TRUE);
  EXPECT_EQ(attr_results[4].ulValueLen, 1);

  // Sensitive attribute is unavailable.
  EXPECT_EQ(attr_results[1].ulValueLen, CK_UNAVAILABLE_INFORMATION);
  // Buffer too small attribute is unavailable.
  EXPECT_THAT(attr_results[2].ulValueLen, CK_UNAVAILABLE_INFORMATION);
  // Not found attribute is unavailable.
  EXPECT_EQ(attr_results[3].ulValueLen, CK_UNAVAILABLE_INFORMATION);
}

TEST(BridgeTest, GetAttributeValueFailureNotInitialized) {
  EXPECT_THAT(GetAttributeValue(0, 0, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GetAttributeValueFailureInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(GetAttributeValue(0, 0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, GetAttributeValueFailureInvalidObjectHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(GetAttributeValue(session, 0, nullptr, 0),
              StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST(BridgeTest, GetAttributeValueFailureNullTemplate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE attr_template = {CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1))

  CK_OBJECT_HANDLE object;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &object, 1, &found_count));
  EXPECT_EQ(found_count, 1);

  EXPECT_THAT(GetAttributeValue(session, object, nullptr, 1),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, FindEcPrivateKey) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_KEY_TYPE key_type = CKK_EC;
  std::vector<CK_ATTRIBUTE> attrs({
      {CKA_CLASS, &obj_class, sizeof(obj_class)},
      {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
  });
  EXPECT_OK(FindObjectsInit(session, &attrs[0], attrs.size()));

  CK_OBJECT_HANDLE handles[2];
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 1);

  char label[2];
  std::vector<CK_ATTRIBUTE> found_attrs({
      {CKA_CLASS, &obj_class, sizeof(obj_class)},
      {CKA_LABEL, label, 2},
  });
  EXPECT_OK(GetAttributeValue(session, handles[0], found_attrs.data(), 2));

  EXPECT_EQ(obj_class, CKO_PRIVATE_KEY);
  EXPECT_EQ(std::string(label, 2), "ck");

  EXPECT_OK(FindObjectsFinal(session));
}

TEST(BridgeTest, FindCertificate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "generate_certs: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_SIGN,
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
  CK_ATTRIBUTE attr_template{CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE handles[2];
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 1);
}

TEST(BridgeTest, NoCertificatesWhenConfigNotSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
  CK_ATTRIBUTE attr_template{CKA_CLASS, &obj_class, sizeof(obj_class)};
  EXPECT_OK(FindObjectsInit(session, &attr_template, 1));

  CK_OBJECT_HANDLE handle;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handle, 1, &found_count));
  EXPECT_EQ(found_count, 0);
}

TEST(BridgeTest, FindObjectsInitSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
}

TEST(BridgeTest, FindObjectsInitFailsNotInitialized) {
  EXPECT_THAT(FindObjectsInit(0, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, FindObjectsInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(FindObjectsInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, FindObjectsInitFailsAttributeTemplateNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(FindObjectsInit(session, nullptr, 1),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, FindObjectsInitFailsAlreadyInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_THAT(FindObjectsInit(session, nullptr, 0),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST(BridgeTest, FindObjectsSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_OBJECT_HANDLE handle;
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handle, 1, &found_count));
  EXPECT_EQ(found_count, 0);
}

TEST(BridgeTest, FindObjectsFailsNotInitialized) {
  EXPECT_THAT(FindObjects(0, nullptr, 0, nullptr),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, FindObjectsFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(FindObjects(0, nullptr, 0, nullptr),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, FindObjectsFailsPhObjectNull) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_ULONG found_count;
  EXPECT_THAT(FindObjects(session, nullptr, 0, &found_count),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, FindObjectsFailsPulCountNull) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));

  CK_OBJECT_HANDLE handles[1];
  EXPECT_THAT(FindObjects(session, &handles[0], 1, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, FindObjectsFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_OBJECT_HANDLE obj_handle;
  CK_ULONG found_count;
  EXPECT_THAT(FindObjects(session, &obj_handle, 1, &found_count),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(BridgeTest, FindObjectsFinalSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_OK(FindObjectsFinal(session));
}

TEST(BridgeTest, FindObjectsFinalFailsNotInitialized) {
  EXPECT_THAT(FindObjectsFinal(0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, FindObjectsFinalFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(FindObjectsFinal(0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, FindObjectsFinalFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(FindObjectsFinal(session),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST(BridgeTest, FindObjectsContainsNewResultsAfterRefresh) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "refresh_interval_secs: 1" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  CK_ULONG found_count;
  std::vector<CK_OBJECT_HANDLE> objects(2);
  EXPECT_OK(FindObjects(session, objects.data(), objects.size(), &found_count));
  EXPECT_EQ(found_count, 0);
  EXPECT_OK(FindObjectsFinal(session));

  InitializeCryptoKeyAndKeyVersion(
      fake_server.get(), kr, kms_v1::CryptoKey::ASYMMETRIC_SIGN,
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  absl::SleepFor(absl::Seconds(2));

  EXPECT_OK(FindObjectsInit(session, nullptr, 0));
  EXPECT_OK(FindObjects(session, objects.data(), objects.size(), &found_count));
  EXPECT_EQ(found_count, 2);
  EXPECT_OK(FindObjectsFinal(session));
}

TEST(BridgeTest, GenerateKeyPairFailsNotInitialized) {
  EXPECT_THAT(
      GenerateKeyPair(0, nullptr, nullptr, 0, nullptr, 0, nullptr, nullptr),
      StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GenerateKeyPairFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(
      GenerateKeyPair(0, nullptr, nullptr, 0, nullptr, 0, nullptr, nullptr),
      StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, GenerateKeyPairFailsMechanismNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_ATTRIBUTE tmpl[2] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
  };
  CK_OBJECT_HANDLE handles[2];

  EXPECT_THAT(GenerateKeyPair(session, nullptr, nullptr, 0, &tmpl[0], 2,
                              &handles[0], &handles[1]),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GenerateKeyPairFailsPublicKeyTemplateMissingPointer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_HANDLE handles[2];

  EXPECT_THAT(GenerateKeyPair(session, &gen_mech, nullptr, 1, nullptr, 0,
                              &handles[0], &handles[1]),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GenerateKeyPairFailsPrivateKeyTemplateMissingPointer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_HANDLE handles[2];

  EXPECT_THAT(GenerateKeyPair(session, &gen_mech, nullptr, 0, nullptr, 1,
                              &handles[0], &handles[1]),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GenerateKeyPairFailsPublicKeyHandleNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ATTRIBUTE tmpl[2] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
  };
  CK_OBJECT_HANDLE handle;

  EXPECT_THAT(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                              nullptr, &handle),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GenerateKeyPairFailsPrivateKeyHandleNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ATTRIBUTE tmpl[2] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
  };
  CK_OBJECT_HANDLE handle;

  EXPECT_THAT(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                              &handle, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST(BridgeTest, GenerateKeyPairSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ATTRIBUTE tmpl[2] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
  };
  CK_OBJECT_HANDLE handles[2];

  EXPECT_OK(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                            &handles[0], &handles[1]));
  EXPECT_NE(handles[0], CK_INVALID_HANDLE);
  EXPECT_NE(handles[1], CK_INVALID_HANDLE);

  // Ensure that the generated keypair can be found with C_FindObjects
  CK_ULONG found_count;
  CK_OBJECT_HANDLE found_handles[2];
  EXPECT_OK(FindObjectsInit(session, &tmpl[0], 2));
  EXPECT_OK(FindObjects(session, &found_handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 2);
  EXPECT_OK(FindObjectsFinal(session));

  EXPECT_THAT(found_handles, testing::UnorderedElementsAreArray(handles));

  // Ensure that the CKV can be located with direct KMS API calls.
  auto fake_client = fake_server->NewClient();
  GetCryptoKeyVersionOrDie(
      fake_client.get(),
      kr.name() + "/cryptoKeys/" + key_id + "/cryptoKeyVersions/1");
}

TEST(BridgeTest, GenerateKeyPairSingleTenantSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::KeyRing kr;
  std::string config_file =
      CreateConfigFileWithOneKeyring(fake_server.get(), &kr);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());

  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT;
  std::string crypto_key_backend = "test";
  CK_ATTRIBUTE tmpl[4] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
      {CKA_KMS_CRYPTO_KEY_BACKEND, crypto_key_backend.data(),
       crypto_key_backend.size()}
  };
  CK_OBJECT_HANDLE handles[2];

  EXPECT_OK(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                            &handles[0], &handles[1]));
  EXPECT_NE(handles[0], CK_INVALID_HANDLE);
  EXPECT_NE(handles[1], CK_INVALID_HANDLE);

  // Ensure that the generated keypair can be found with C_FindObjects
  CK_ULONG found_count;
  CK_OBJECT_HANDLE found_handles[2];
  EXPECT_OK(FindObjectsInit(session, &tmpl[0], 2));
  EXPECT_OK(FindObjects(session, &found_handles[0], 2, &found_count));
  EXPECT_EQ(found_count, 2);
  EXPECT_OK(FindObjectsFinal(session));

  EXPECT_THAT(found_handles, testing::UnorderedElementsAreArray(handles));

  // Ensure that the CKV can be located with direct KMS API calls.
  auto fake_client = fake_server->NewClient();
  GetCryptoKeyVersionOrDie(
      fake_client.get(),
      kr.name() + "/cryptoKeys/" + key_id + "/cryptoKeyVersions/1");
}

TEST(BridgeTest,
     GenerateTwoKeyPairsSuccessWithExperimentalCreateMultipleVersions) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server.get());
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "experimental_create_multiple_versions: true" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  auto init_args = InitArgs(config_file.c_str());
  EXPECT_OK(Initialize(&init_args));
  absl::Cleanup c = [] { EXPECT_OK(Finalize(nullptr)); };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  std::string key_id = "my-great-id";
  CK_ULONG algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;

  CK_MECHANISM gen_mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ATTRIBUTE tmpl[2] = {
      {CKA_LABEL, key_id.data(), key_id.size()},
      {CKA_KMS_ALGORITHM, &algorithm, sizeof(algorithm)},
  };

  CK_OBJECT_HANDLE ckv_handles[2];
  EXPECT_OK(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                            &ckv_handles[0], &ckv_handles[1]));

  EXPECT_OK(GenerateKeyPair(session, &gen_mech, nullptr, 0, &tmpl[0], 2,
                            &ckv_handles[0], &ckv_handles[1]));
}

TEST(BridgeTest, DestroyObjectFailsNotInitialized) {
  EXPECT_THAT(DestroyObject(0, 0), StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, DestroyObjectFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(DestroyObject(0, 0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, DestroyObjectFailsInvalidObjectHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  EXPECT_THAT(DestroyObject(session, 0), StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST(BridgeTest, DestroyObjectSuccessPrivateKey) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr,
                        nullptr, &session));

  CK_OBJECT_CLASS prv = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE tmpl = {CKA_CLASS, &prv, sizeof(prv)};
  CK_OBJECT_HANDLE handle;

  EXPECT_OK(FindObjectsInit(session, &tmpl, 1));
  CK_ULONG found_count;
  EXPECT_OK(FindObjects(session, &handle, 1, &found_count));
  EXPECT_EQ(found_count, 1);
  EXPECT_OK(FindObjectsFinal(session));

  EXPECT_OK(DestroyObject(session, handle));
}

TEST(BridgeTest, GenerateRandomSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> zeroes(32, '\0');
  std::vector<uint8_t> rand(zeroes);
  EXPECT_OK(GenerateRandom(session, rand.data(), rand.size()));
  EXPECT_THAT(rand, Not(ElementsAreArray(zeroes)));
}

TEST(BridgeTest, GenerateRandomFailsNotInitialized) {
  EXPECT_THAT(GenerateRandom(0, nullptr, 0),
              StatusRvIs(CKR_CRYPTOKI_NOT_INITIALIZED));
}

TEST(BridgeTest, GenerateRandomFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(GenerateRandom(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(BridgeTest, GenerateRandomFailsNullBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  EXPECT_THAT(GenerateRandom(session, nullptr, 0),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

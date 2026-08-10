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

#include <sys/wait.h>

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/resource_helpers.h"

namespace cloud_kms::kmsp11 {
namespace {

// Forking isn't officially supported by gRPC, but it seems to mostly work, so
// we should try to get them to support it for us if feasible. Until then, this
// test ensures we don't introduce a regression that breaks forking.
TEST(ForkTest, ProviderToleratesForkAfterInitWithEnvVariableSet) {
  // This magic env variable is needed for gRPC to include fork support.
  // It is important to set this before any gRPC objects are made.
  std::string grpc_fork_env_var = "GRPC_ENABLE_FORK_SUPPORT";
  SetEnvVariable(grpc_fork_env_var, "1");
  absl::Cleanup c1 = [&] { ClearEnvVariable(grpc_fork_env_var); };

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_kms,
                       fakekms::Server::New());
  auto client = fake_kms->NewClient();

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr);

  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         kr.name(), fake_kms->listen_addr());
  absl::Cleanup c2 = [&] { std::remove(config_file.c_str()); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = const_cast<char*>(config_file.c_str());
  ASSERT_OK(Initialize(&init_args));
  absl::Cleanup c3 = [] { ASSERT_OK(Finalize(nullptr)); };

  pid_t pid = fork();
  switch (pid) {
    // fork failure
    case -1: {
      FAIL() << "Failure forking.";
    }

    // post-fork child
    case 0: {
      absl::Status init_result = Initialize(&init_args);
      // Assertions made post-fork won't get logged; CHECK-failing dumps to
      // stderr so /will/ get picked up in the test log.
      CHECK(init_result.ok()) << init_result;
      exit(0);
    }

    // post-fork parent
    default: {
      int exit_code;
      ASSERT_EQ(waitpid(pid, &exit_code, 0), pid)
          << "failure waiting for child process: " << errno;
      EXPECT_EQ(exit_code, 0);
    }
  }
}

}  // namespace
}  // namespace cloud_kms::kmsp11
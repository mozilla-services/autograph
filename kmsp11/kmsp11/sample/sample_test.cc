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

#include <libgen.h>

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/test/resource_helpers.h"
#include "tools/cpp/runfiles/runfiles.h"

extern "C" {
extern int run_sample(const char* library_path, const char* config_file_path,
                      const char* ec_p256_signing_key_id);
}

namespace cloud_kms::kmsp11 {
namespace {

constexpr char kSharedLibraryLocation[] =
    "com_google_kmstools/kmsp11/main/libkmsp11.so";

namespace kms_v1 = ::google::cloud::kms::v1;

using ::bazel::tools::cpp::runfiles::Runfiles;
using ::testing::IsEmpty;

TEST(SampleTest, SampleHealthTest) {
  std::string load_error;
  Runfiles* runfiles = Runfiles::CreateForTest(&load_error);
  EXPECT_THAT(load_error, IsEmpty());

  std::string shared_lib_path = runfiles->Rlocation(kSharedLibraryLocation);
  EXPECT_THAT(shared_lib_path, Not(IsEmpty()));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());

  auto client = fake_server->NewClient();
  kms_v1::KeyRing key_ring = CreateKeyRingOrDie(client.get(), kTestLocation,
                                                RandomId(), kms_v1::KeyRing());

  kms_v1::CryptoKey crypto_key;
  crypto_key.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  crypto_key.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  crypto_key.mutable_version_template()->set_protection_level(kms_v1::HSM);
  std::string key_id = RandomId();
  crypto_key = CreateCryptoKeyOrDie(client.get(), key_ring.name(), key_id,
                                    crypto_key, false);

  std::string config_filename = std::tmpnam(nullptr);
  std::ofstream(config_filename)
      << absl::StrFormat(R"(
tokens:
  - key_ring: "%s"
kms_endpoint: "%s"
use_insecure_grpc_channel_credentials: true
)",
                         key_ring.name(), fake_server->listen_addr());

  EXPECT_EQ(run_sample(shared_lib_path.c_str(), config_filename.c_str(),
                       key_id.c_str()),
            0);
}

}  // namespace
}  // namespace cloud_kms::kmsp11

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

#include "kmscng/object.h"

#include "common/kms_client.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/provider.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/string_utils.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

class ObjectTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto client = fake_server_->NewClient();

    kms_v1::KeyRing kr1;
    kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
    ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);

    ck = CreateCryptoKeyOrDie(client.get(), kr1.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(client.get(), ckv);

    Provider provider;
    // Set custom properties to hit fake KMS.
    EXPECT_OK(provider.SetProperty(kEndpointAddressProperty,
                                   fake_server_->listen_addr()));
    EXPECT_OK(provider.SetProperty(kChannelCredentialsProperty, "insecure"));
    ASSERT_OK_AND_ASSIGN(
        object_, Object::New(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider),
                             ckv.name()));
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  Object* object_;
};

TEST_F(ObjectTest, GetObjectPropertyAlgGroupSuccess) {
  EXPECT_THAT(object_->GetProperty(NCRYPT_ALGORITHM_GROUP_PROPERTY),
              IsOkAndHolds(WideToBytes(NCRYPT_ECDSA_ALGORITHM_GROUP)));
}

TEST_F(ObjectTest, GetObjectPropertyAlgorithmSuccess) {
  EXPECT_THAT(object_->GetProperty(NCRYPT_ALGORITHM_PROPERTY),
              IsOkAndHolds(WideToBytes(BCRYPT_ECDSA_P256_ALGORITHM)));
}

TEST_F(ObjectTest, GetObjectPropertyKeyUsageSuccess) {
  EXPECT_THAT(object_->GetProperty(NCRYPT_KEY_USAGE_PROPERTY),
              IsOkAndHolds(Uint32ToBytes(NCRYPT_ALLOW_SIGNING_FLAG)));
}

}  // namespace
}  // namespace cloud_kms::kmscng

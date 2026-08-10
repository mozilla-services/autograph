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

#include "kmscng/provider.h"

#include "absl/cleanup/cleanup.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/string_utils.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

TEST(ProviderTest, GetProviderPropertyUnsupportedProperty) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_UI_POLICY_PROPERTY),
              StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(ProviderTest, GetProviderPropertyImplTypeSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_IMPL_TYPE_PROPERTY),
              IsOkAndHolds(Uint32ToBytes(NCRYPT_IMPL_HARDWARE_FLAG)));
}

TEST(ProviderTest, GetProviderPropertyLibraryVersionSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(NCRYPT_VERSION_PROPERTY),
              IsOkAndHolds(Uint32ToBytes(kLibraryVersionHex)));
}

TEST(ProviderTest, GetProviderPropertyEndpointAddressSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(kEndpointAddressProperty),
              IsOkAndHolds("cloudkms.googleapis.com:443"));
}

TEST(ProviderTest, GetProviderPropertyChannelCredentialsSuccess) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(kChannelCredentialsProperty),
              IsOkAndHolds("default"));
}

TEST(ProviderTest, GetProviderPropertyUserProjectEmptyDefault) {
  Provider provider;

  EXPECT_THAT(provider.GetProperty(kUserProjectProperty), IsOkAndHolds(""));
}

TEST(ProviderTest, SetEndpointAddressInEnvVariable) {
  std::string address = "invalid.address";
  SetEnvVariable(kEndpointAddressEnvVariable, address);
  absl::Cleanup c = [] { ClearEnvVariable(kEndpointAddressEnvVariable); };

  Provider provider;
  EXPECT_THAT(provider.GetProperty(kEndpointAddressProperty),
              IsOkAndHolds(address));
}

TEST(ProviderTest, SetChannelCredentialsInEnvVariable) {
  std::string credentials = "unknown";
  SetEnvVariable(kChannelCredentialsEnvVariable, credentials);
  absl::Cleanup c = [] { ClearEnvVariable(kChannelCredentialsEnvVariable); };

  Provider provider;
  EXPECT_THAT(provider.GetProperty(kChannelCredentialsProperty),
              IsOkAndHolds(credentials));
}

TEST(ProviderTest, SetUserProjectInEnvVariable) {
  std::string user_project = "some-project";
  SetEnvVariable(kUserProjectEnvVariable, user_project);
  absl::Cleanup c = [] { ClearEnvVariable(kUserProjectEnvVariable); };

  Provider provider;
  EXPECT_THAT(provider.GetProperty(kUserProjectProperty),
              IsOkAndHolds(user_project));
}

TEST(ProviderTest, SetProviderPropertyUnsupportedProperty) {
  Provider provider;

  EXPECT_THAT(provider.SetProperty(NCRYPT_UI_POLICY_PROPERTY, ""),
              StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(ProviderTest, SetProviderPropertyImmutableProperty) {
  Provider provider;

  EXPECT_THAT(provider.SetProperty(NCRYPT_IMPL_TYPE_PROPERTY, ""),
              StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(ProviderTest, SetProviderPropertySuccess) {
  Provider provider;

  std::string input = "insecure";
  EXPECT_OK(provider.SetProperty(kChannelCredentialsProperty, input));
  EXPECT_THAT(provider.GetProperty(kChannelCredentialsProperty),
              IsOkAndHolds("insecure"));
}

}  // namespace
}  // namespace cloud_kms::kmscng

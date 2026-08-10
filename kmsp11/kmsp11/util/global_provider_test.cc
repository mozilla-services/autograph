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

#include "kmsp11/util/global_provider.h"

#include "absl/cleanup/cleanup.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::IsNull;

TEST(GlobalProviderTest, GetProviderBeforeSetReturnsNullptr) {
  EXPECT_THAT(GetGlobalProvider(), IsNull());
}

TEST(GlobalProviderTest, GetProviderAfterSetReturnsProvider) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider,
                       Provider::New(LibraryConfig()));
  Provider* captured_provider = provider.get();

  ASSERT_OK(SetGlobalProvider(std::move(provider)));
  absl::Cleanup c = [] { ASSERT_OK(ReleaseGlobalProvider()); };

  EXPECT_EQ(GetGlobalProvider(), captured_provider);
}

TEST(GlobalProviderTest, SetProviderToNullReturnsError) {
  EXPECT_THAT(SetGlobalProvider(nullptr),
              AllOf(StatusIs(absl::StatusCode::kInternal, HasSubstr("nullptr")),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(GlobalProviderTest, SetProviderWhenAlreadySetReturnsError) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider1,
                       Provider::New(LibraryConfig()));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider2,
                       Provider::New(LibraryConfig()));

  ASSERT_OK(SetGlobalProvider(std::move(provider1)));
  absl::Cleanup c = [] { ASSERT_OK(ReleaseGlobalProvider()); };

  EXPECT_THAT(SetGlobalProvider(std::move(provider2)),
              AllOf(StatusIs(absl::StatusCode::kInternal,
                             HasSubstr("provider has already been set")),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(GlobalProviderTest, GetProviderAfterReleaseReturnsNullptr) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider,
                       Provider::New(LibraryConfig()));

  ASSERT_OK(SetGlobalProvider(std::move(provider)));
  ASSERT_OK(ReleaseGlobalProvider());

  EXPECT_THAT(GetGlobalProvider(), IsNull());
}

TEST(GlobalProviderTest, SetAndGetProviderAfterReleaseReturnsProvider) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider1,
                       Provider::New(LibraryConfig()));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Provider> provider2,
                       Provider::New(LibraryConfig()));
  Provider* captured_provider2 = provider2.get();

  ASSERT_OK(SetGlobalProvider(std::move(provider1)));
  ASSERT_OK(ReleaseGlobalProvider());
  ASSERT_OK(SetGlobalProvider(std::move(provider2)))
  absl::Cleanup c = [] { ASSERT_OK(ReleaseGlobalProvider()); };

  EXPECT_EQ(GetGlobalProvider(), captured_provider2);
}

}  // namespace
}  // namespace cloud_kms::kmsp11

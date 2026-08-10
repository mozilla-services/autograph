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

#include "kmsp11/util/handle_map.h"

#include "common/test/test_status_macros.h"
#include "gtest/gtest.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::Pointee;

TEST(HandleMapTest, ItemHandleValid) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);
  EXPECT_NE(handle, CK_INVALID_HANDLE);
}

TEST(HandleMapTest, ItemHandlesDifferent) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle1 = map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  EXPECT_NE(handle1, handle2);
}

TEST(HandleMapTest, AllItemsAdded) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle1 = map.Add(3);
  CK_ULONG handle2 = map.Add(4);
  CK_ULONG handle3 = map.Add(5);

  EXPECT_THAT(map.Get(handle1), IsOkAndHolds(Pointee(3)));
  EXPECT_THAT(map.Get(handle2), IsOkAndHolds(Pointee(4)));
  EXPECT_THAT(map.Get(handle3), IsOkAndHolds(Pointee(5)));
}

TEST(HandleMapTest, GetByHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);

  ASSERT_OK_AND_ASSIGN(std::shared_ptr<int> value, map.Get(handle));
  EXPECT_EQ(*value, 3);
}

TEST(HandleMapTest, GetInvalidHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_THAT(map.Get(1), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(HandleMapTest, RemoveRemoves) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  CK_ULONG handle = map.Add(3);
  EXPECT_OK(map.Remove(handle));

  EXPECT_THAT(map.Get(handle), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(HandleMapTest, RemoveInvalidHandle) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);

  EXPECT_THAT(map.Remove(5), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST(HandleMapTest, RemoveIfRemovesOnPredicate) {
  HandleMap<int> map(CKR_SESSION_HANDLE_INVALID);
  CK_ULONG h1 = map.Add(1);
  CK_ULONG h2 = map.Add(2);
  CK_ULONG h3 = map.Add(3);
  CK_ULONG h4 = map.Add(4);

  map.RemoveIf([](const int& i) -> bool { return i % 2 == 0; });

  EXPECT_OK(map.Get(h1));
  EXPECT_THAT(map.Get(h2), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
  EXPECT_OK(map.Get(h3));
  EXPECT_THAT(map.Get(h4), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

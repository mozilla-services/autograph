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

#include "kmscng/util/string_utils.h"

#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"

namespace cloud_kms::kmscng {
namespace {

TEST(Uint32ToBytesTest, Success) {
  uint32_t bytes = 0x44434241;
  EXPECT_EQ(Uint32ToBytes(bytes), "ABCD");
}

TEST(ProvHandleToBytesTest, Success) {
  NCRYPT_PROV_HANDLE handle = 1;
  // Use string constructor to handle \x00.
  EXPECT_EQ(ProvHandleToBytes(handle), std::string("\x1\0\0\0\0\0\0\0", 8));
}

TEST(WideStringTest, StringToWideSuccess) {
  EXPECT_EQ(StringToWide("1337"), L"1337");
}

TEST(WideStringTest, WideToStringSuccess) {
  EXPECT_EQ(WideToString(L"1337"), "1337");
}

TEST(WideStringTest, StringToWideExtendedCharacterSuccess) {
  EXPECT_EQ(StringToWide("鍵"), L"鍵");
}

TEST(WideStringTest, WideToStringExtendedCharacterSuccess) {
  EXPECT_EQ(WideToString(L"鍵"), "鍵");
}

TEST(WideStringTest, StringToWideWithZeroByteSuccess) {
  // '?' corresponds to '\x003F'
  EXPECT_EQ(StringToWide("?"), L"?");
}

TEST(WideStringTest, WideToStringWithZeroByteSuccess) {
  // '?' corresponds to '\x003F'
  EXPECT_EQ(WideToString(L"?"), "?");
}

TEST(WideStringTest, StringToWideEmptySuccess) {
  EXPECT_EQ(StringToWide(""), L"");
}

TEST(WideStringTest, WideToStringEmptySuccess) {
  EXPECT_EQ(WideToString(L""), "");
}

TEST(WideStringTest, StringToWideAndBackSuccess) {
  EXPECT_EQ(WideToString(StringToWide("1337")), "1337");
  EXPECT_EQ(WideToString(StringToWide("鍵")), "鍵");
  EXPECT_EQ(WideToString(StringToWide("?")), "?");
}

TEST(WideToBytesTest, WideToBytesSuccess) {
  char expected_output[] = {'E', '\0', 'C', '\0', 'D',  '\0', 'S', '\0',
                            'A', '\0', '_', '\0', 'P',  '\0', '2', '\0',
                            '5', '\0', '6', '\0', '\0', '\0'};
  EXPECT_EQ(WideToBytes(BCRYPT_ECDSA_P256_ALGORITHM),
            std::string(expected_output, 22));
}

}  // namespace
}  // namespace cloud_kms::kmscng

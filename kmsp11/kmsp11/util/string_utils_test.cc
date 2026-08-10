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

#include "kmsp11/util/string_utils.h"

#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Field;
using ::testing::HasSubstr;
using ::testing::Pointee;
using ::testing::SizeIs;

TEST(StrFromBytesTest, DecodeTextData) {
  uint8_t bytes[4] = {0x41, 0x42, 0x43, 0x44};
  EXPECT_EQ(StrFromBytes(bytes), "ABCD");
}

TEST(StrFromBytesTest, DecodeBinaryData) {
  uint8_t bytes[] = {0x00, 0x7f, 0x80, 0xff};
  // Note that we can't use a plain `char*` literal  because \x00 is the C
  // string terminator.
  EXPECT_EQ(StrFromBytes(bytes), std::string("\x00\x7f\x80\xff", 4));
}

TEST(CkStrCopyTest, EqualSizedSrcAndDest) {
  uint8_t bytes[3];
  EXPECT_OK(CryptokiStrCopy("ABC", bytes));
  EXPECT_THAT(bytes, ElementsAre(0x41, 0x42, 0x43));
}

TEST(CkStrCopyTest, WithPadCharacters) {
  uint8_t bytes[4];
  EXPECT_OK(CryptokiStrCopy("AB", bytes));
  EXPECT_THAT(bytes, ElementsAre(0x41, 0x42, 0x20, 0x20));
}

TEST(CkStrCopyTest, OversizedString) {
  uint8_t bytes[2];
  EXPECT_THAT(CryptokiStrCopy("abc", bytes),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(CkStrCopyTest, WithExistingContent) {
  uint8_t bytes[3] = {0x01, 0x02, 0x03};
  EXPECT_OK(CryptokiStrCopy("a", bytes));
  EXPECT_THAT(bytes, ElementsAre('a', ' ', ' '));
}

TEST(CkStrCopyTest, WithAlternatePadChar) {
  uint8_t bytes[4];
  EXPECT_OK(CryptokiStrCopy("ab", bytes, '0'));
  EXPECT_THAT(bytes, ElementsAre('a', 'b', '0', '0'));
}

TEST(MarshalTest, MarshalBigNum32768) {
  // Test vector from
  // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc441755756
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  BN_set_word(bn.get(), 32768);

  EXPECT_EQ(MarshalBigNum(bn.get()), std::string("\x80\x00", 2));
}

TEST(MarshalTest, MarshalBigNum0) {
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  BN_set_word(bn.get(), 0);

  EXPECT_EQ(MarshalBigNum(bn.get()), "");
}

TEST(MarshalTest, MarshalBoolFalse) {
  std::string s = MarshalBool(false);
  const CK_BBOOL* got = reinterpret_cast<const CK_BBOOL*>(s.data());
  EXPECT_THAT(got, Pointee(CK_FALSE));
}

TEST(MarshalTest, MarshalBoolTrue) {
  std::string s = MarshalBool(true);
  const CK_BBOOL* got = reinterpret_cast<const CK_BBOOL*>(s.data());
  EXPECT_THAT(got, Pointee(CK_TRUE));
}

TEST(MarshalTest, MarshalDateEpoch) {
  EXPECT_EQ(MarshalDate(absl::FromUnixSeconds(0)), "19700101");
}

TEST(MarshalTest, MarshalDate2020) {
  EXPECT_EQ(MarshalDate(absl::FromUnixSeconds(1591031247L)), "20200601");
}

TEST(MarshalTest, MarshalUnsignedLong) {
  std::string s = MarshalULong(2048);
  const CK_ULONG* got = reinterpret_cast<const CK_ULONG*>(s.data());
  EXPECT_THAT(got, Pointee(2048L));
}

TEST(MarshalTest, MarshalUnsignedLongList) {
  std::string s = MarshalULongList({2048, 3072, 4096});
  absl::Span<const CK_ULONG> got(reinterpret_cast<const CK_ULONG*>(s.data()),
                                 s.size() / sizeof(CK_ULONG));
  EXPECT_THAT(got, ElementsAre(2048, 3072, 4096));
}

TEST(MarshalTest, MarshalUnsignedLongListEmpty) {
  std::string s = MarshalULongList(std::vector<unsigned long int>());
  EXPECT_THAT(s, SizeIs(0));
}

TEST(ExtractorTest, ExtractKeyIdSuccess) {
  EXPECT_THAT(ExtractKeyId("projects/foo/locations/global/keyRings/bar/"
                           "cryptoKeys/baz/cryptoKeyVersions/1"),
              IsOkAndHolds("baz"));
}

TEST(ExtractorTest, ExtractKeyIdFailure) {
  EXPECT_THAT(ExtractKeyId("projects/foo/locations/global/keyRings/bar/"
                           "cryptoKeys/baz"),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("invalid CryptoKeyVersion name")));
}

TEST(ExtractorTest, ExtractLocationNameSuccess) {
  EXPECT_THAT(ExtractLocationName("projects/foo/locations/global/keyRings/bar"),
              IsOkAndHolds("projects/foo/locations/global"));
}

TEST(ExtractorTest, ExtractLocationNameFailure) {
  EXPECT_THAT(
      ExtractLocationName(
          "projects/foo/locations/global/keyRings/bar/cryptoKeys/baz"),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("invalid KeyRing name")));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

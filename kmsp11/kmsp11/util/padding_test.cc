// Copyright 2022 Google LLC
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

#include "kmsp11/util/padding.h"

#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/test/matchers.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;

std::vector<uint8_t> kPlaintext(12, 'a');
std::vector<uint8_t> kRightSizePlaintext(16, 'a');

TEST(PaddingTest, PaddingMatchesExpected) {
  std::vector<uint8_t> padded_plaintext = Pad(kPlaintext);
  EXPECT_EQ(padded_plaintext.back(), '\4');
}

TEST(PaddingTest, PaddingRightSizePlaintext) {
  std::vector<uint8_t> padded_plaintext = Pad(kRightSizePlaintext);
  EXPECT_EQ(padded_plaintext.back(), '\x10');
}

TEST(PaddingTest, InvalidPaddingValueGreaterThanBlockSize) {
  std::vector<uint8_t> invalid_padding_plaintext(17, '\x11');
  EXPECT_THAT(Unpad(invalid_padding_plaintext),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(PaddingTest, InvalidZeroPaddingValue) {
  std::vector<uint8_t> invalid_padding_plaintext(17, '\0');
  EXPECT_THAT(Unpad(invalid_padding_plaintext),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(PaddingTest, InvalidPaddingValueGreaterThanLength) {
  std::vector<uint8_t> invalid_padding_plaintext(3, '\4');
  EXPECT_THAT(Unpad(invalid_padding_plaintext),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(PaddingTest, InvalidInconsistentPadding) {
  std::vector<uint8_t> invalid_padding_plaintext(16, '\4');
  invalid_padding_plaintext.data()[14] = '\3';
  EXPECT_THAT(Unpad(invalid_padding_plaintext),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST(PaddingTest, PadUnpadSuccess) {
  std::vector<uint8_t> padded_plaintext = Pad(kPlaintext);
  ASSERT_OK_AND_ASSIGN(auto unpadded_plaintext, Unpad(padded_plaintext));
  EXPECT_EQ(unpadded_plaintext, kPlaintext);
}

TEST(PaddingTest, PadUnpadRightSizePlaintextSuccess) {
  auto padded_plaintext = Pad(kRightSizePlaintext);
  EXPECT_EQ(padded_plaintext.size(), kRightSizePlaintext.size() + 16);
  ASSERT_OK_AND_ASSIGN(auto unpadded_plaintext, Unpad(padded_plaintext));
  EXPECT_EQ(unpadded_plaintext, kRightSizePlaintext);
}

}  // namespace
}  // namespace cloud_kms::kmsp11

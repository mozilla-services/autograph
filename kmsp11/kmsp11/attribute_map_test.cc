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

#include "kmsp11/attribute_map.h"

#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/test/matchers.h"

namespace cloud_kms::kmsp11 {
namespace {

TEST(AttributeMapTest, PopulatedValue) {
  AttributeMap m;
  m.Put(CKA_LABEL, "my_important_key");

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_LABEL));
  EXPECT_EQ(got, "my_important_key");
}

TEST(AttributeMapTest, EmptyValue) {
  AttributeMap m;
  m.Put(CKA_ID, "");

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_ID));
  EXPECT_TRUE(got.empty());
}

TEST(AttributeMapTest, ValueNotSet) {
  AttributeMap m;
  EXPECT_THAT(m.Value(CKA_ID), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

TEST(AttributeMapTest, ValueSensitive) {
  AttributeMap m;
  m.PutSensitive(CKA_PRIVATE_EXPONENT);

  EXPECT_THAT(m.Value(CKA_PRIVATE_EXPONENT),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
}

TEST(AttributeMapTest, PutBool) {
  AttributeMap m;
  m.PutBool(CKA_ENCRYPT, false);

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_ENCRYPT));
  EXPECT_EQ(got, std::string("\x00", 1));
}

TEST(AttributeMapTest, PutBigNum) {
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  BN_set_word(bn.get(), 65537);

  AttributeMap m;
  m.PutBigNum(CKA_PUBLIC_EXPONENT, bn.get());

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_PUBLIC_EXPONENT));
  EXPECT_EQ(got, std::string("\x01\x00\x01", 3));
}

TEST(AttributeMapTest, PutDate) {
  AttributeMap m;
  m.PutDate(CKA_START_DATE, absl::FromUnixSeconds(0));

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_START_DATE));
  EXPECT_EQ(got, "19700101");
}

TEST(AttributeMapTest, PutULong) {
  CK_OBJECT_CLASS value = CKO_PUBLIC_KEY;

  AttributeMap m;
  m.PutULong(CKA_CLASS, value);

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_CLASS));
  EXPECT_EQ(got, MarshalULong(value));
}

TEST(AttributeMapTest, PutULongList) {
  CK_MECHANISM_TYPE value[] = {CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS};

  AttributeMap m;
  m.PutULongList(CKA_ALLOWED_MECHANISMS, value);

  ASSERT_OK_AND_ASSIGN(std::string_view got, m.Value(CKA_ALLOWED_MECHANISMS));
  EXPECT_EQ(got, MarshalULongList(value));
}

TEST(AttributeMapTest, PutAndGetMultipleValues) {
  std::string id_value = "Some more arbitrary text";
  std::string label_value = "Some arbitrary text";

  AttributeMap m;
  m.Put(CKA_ID, id_value);
  m.Put(CKA_LABEL, label_value);

  ASSERT_OK_AND_ASSIGN(std::string_view got_id, m.Value(CKA_ID));
  EXPECT_EQ(got_id, id_value);

  ASSERT_OK_AND_ASSIGN(std::string_view got_label, m.Value(CKA_LABEL));
  EXPECT_EQ(got_label, label_value);
}

TEST(AttributeMapTest, Contains) {
  std::string id = "projects/foo/keys/bar";

  AttributeMap m;
  m.Put(CKA_ID, id);

  CK_ATTRIBUTE attr;
  attr.type = CKA_ID;
  attr.pValue = id.data();
  attr.ulValueLen = id.size();

  EXPECT_TRUE(m.Contains(attr));
}

TEST(AttributeMapTest, DoesNotContain) {
  AttributeMap m;
  m.Put(CKA_ID, "projects/foo/keys/bar");

  std::string want_id = "projects/foo/keys/baz";
  CK_ATTRIBUTE attr;
  attr.type = CKA_ID;
  attr.pValue = want_id.data();
  attr.ulValueLen = want_id.size();

  EXPECT_FALSE(m.Contains(attr));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

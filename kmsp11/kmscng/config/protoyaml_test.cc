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

#include "kmscng/config/protoyaml.h"

#include "common/test/proto_parser.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/config/protoyaml_test.pb.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;

TEST(ProtoyamlTest, ParseEmpty) {
  YAML::Node node = YAML::Load("");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_THAT(result, EqualsProto(Scalars()));
}

TEST(ProtoyamlTest, ParseString) {
  YAML::Node node = YAML::Load("string_field: foo");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.string_field(), "foo");
}

TEST(ProtoyamlTest, ParseInt) {
  YAML::Node node = YAML::Load("int_field: 31337");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.int_field(), 31337);
}

TEST(ProtoyamlTest, ParseTrue) {
  YAML::Node node = YAML::Load("bool_field: true");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_TRUE(result.bool_field());
}

TEST(ProtoyamlTest, ParseFalse) {
  YAML::Node node = YAML::Load("bool_field: false");
  Scalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_FALSE(result.bool_field());
}

TEST(ProtoyamlTest, CombinedWithDefaults) {
  YAML::Node node = YAML::Load("bool_field: false");
  Scalars result = ParseTestProto("int_field: 123");
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_THAT(result, EqualsProto<Scalars>(ParseTestProto(R"pb(
                bool_field: false
                int_field: 123
              )pb")));
}

TEST(ProtoyamlTest, FailsOnUnknownField) {
  YAML::Node node = YAML::Load("foo_field: foo");
  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("unrecognized key: foo_field"));
}

TEST(ProtoyamlTest, ErrorMessageContainsLocation) {
  YAML::Node node = YAML::Load(R"(---
string_field: foo
nota_field: bar
)");

  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("line 2, column 0"));
}

TEST(ProtoyamlTest, MultipleDefinition) {
  YAML::Node node = YAML::Load(R"(---
string_field: foo
string_field: bar
)");

  Scalars result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(status.message(), HasSubstr("string_field is multiply defined"));
}

TEST(ProtoyamlTest, RepeatedStringInternalError) {
  YAML::Node node = YAML::Load(R"(---
strings:
  - foo
  - bar
)");

  RepeatedString result;
  absl::Status status = YamlToProto(node, &result);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(status.message(), HasSubstr("repeated string"));
}

TEST(ProtoyamlTest, SimpleFieldInComplexMessage) {
  YAML::Node node = YAML::Load("root_field: foo");
  NestedScalars result;
  EXPECT_OK(YamlToProto(node, &result));
  EXPECT_EQ(result.root_field(), "foo");
}

TEST(ProtoyamlTest, NestedMessage) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  bool_field: true
  string_field: bar
)");

  NestedScalars result;
  EXPECT_OK(YamlToProto(node, &result));

  NestedScalars want = ParseTestProto(R"pb(
    scalars { bool_field: true string_field: "bar" }
  )pb");

  EXPECT_THAT(result, EqualsProto(want));
}

TEST(ProtoyamlTest, RepeatedMessage) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  - int_field: 123
  - bool_field: true
    string_field: bar
)");

  RepeatedScalars result;
  EXPECT_OK(YamlToProto(node, &result));

  RepeatedScalars want = ParseTestProto(R"pb(
    scalars { int_field: 123 }
    scalars { bool_field: true string_field: "bar" }
  )pb");

  EXPECT_THAT(result, EqualsProto(want));
}

TEST(ProtoyamlTest, RepeatedMessageReplacesDefault) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  - int_field: 123
)");

  RepeatedScalars result = ParseTestProto(R"pb(
    scalars { bool_field: false })pb");

  EXPECT_OK(YamlToProto(node, &result));

  RepeatedScalars want = ParseTestProto(R"pb(
    scalars { int_field: 123 })pb");

  EXPECT_THAT(result, EqualsProto(want));
}

TEST(ProtoyamlTest, RepeatedMessageUnmodifiedOnParseError) {
  YAML::Node node = YAML::Load(R"(---
scalars:
  - int_field: 123
  - foo_field: 456
)");

  RepeatedScalars want = ParseTestProto(R"pb(
    scalars { bool_field: false })pb");

  RepeatedScalars got(want);

  EXPECT_THAT(YamlToProto(node, &got),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(got, EqualsProto(want));
}

}  // namespace
}  // namespace cloud_kms::kmscng

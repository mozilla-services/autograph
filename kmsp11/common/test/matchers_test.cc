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

#include "common/test/matchers.h"

#include <string_view>

#include "absl/status/statusor.h"
#include "common/test_message.pb.h"
#include "gmock/gmock.h"

namespace cloud_kms {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::Not;

TEST(MatchesStdRegexTest, MatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", MatchesStdRegex("^\\w+.*az$"));
}

TEST(MatchesStdRegexTest, NotMatchesSmokeTest) {
  EXPECT_THAT("foobar_1_2_3@@#baz", Not(MatchesStdRegex("^for.*$")));
}

TEST(MatchesStdRegexTest, StringView) {
  std::string value("abcde");
  EXPECT_THAT(std::string_view(value), MatchesStdRegex("a\\w+e"));
}

TEST(IsOkTest, OkStatus) { EXPECT_THAT(absl::OkStatus(), IsOk()); }

TEST(IsOkTest, OkStatusOr) { EXPECT_THAT(absl::StatusOr<int>(3), IsOk()); }

TEST(IsOkTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"), Not(IsOk()));
}

TEST(IsOkTest, NotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::AbortedError("aborted")), Not(IsOk()));
}

TEST(StatusIsTest, OkStatus) {
  EXPECT_THAT(absl::OkStatus(), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, OkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(3), StatusIs(absl::StatusCode::kOk));
}

TEST(StatusIsTest, NotOkStatus) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted));
}

TEST(StatusIsTest, NotOkStatusWithMessage) {
  EXPECT_THAT(absl::AbortedError("aborted"),
              StatusIs(absl::StatusCode::kAborted, HasSubstr("bort")));
}

TEST(StatusIsTest, NotOkStatusOr) {
  EXPECT_THAT(absl::StatusOr<int>(absl::CancelledError("cancelled")),
              StatusIs(absl::StatusCode::kCancelled));
}
TEST(StatusIsTest, NotOkStatusOrWithMessage) {
  EXPECT_THAT(absl::CancelledError("cancelled"),
              StatusIs(absl::StatusCode::kCancelled, Eq("cancelled")));
}

TEST(EqualsProtoTest, Equals) {
  TestMessage m1;
  m1.set_string_value("foo");

  TestMessage m2;
  m2.set_string_value("foo");

  EXPECT_THAT(m1, EqualsProto(m2));
}

TEST(EqualsProtoTest, NotEquals) {
  TestMessage m1;
  m1.set_string_value("foo");

  TestMessage m2;
  m2.set_string_value("bar");

  EXPECT_THAT(m1, Not(EqualsProto(m2)));
}

TEST(IsOkAndHoldsTest, MatchesValue) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, IsOkAndHolds(3));
}

TEST(IsOkAndHoldsTest, MatchesMatcher) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, IsOkAndHolds(AllOf(Gt(2), Lt(5))));
}

TEST(IsOkAndHoldsTest, DoesNotMatch) {
  absl::StatusOr<int> s(3);
  EXPECT_THAT(s, Not(IsOkAndHolds(4)));
}

TEST(IsOkAndHoldsTest, IsNotOk) {
  absl::StatusOr<int> s(absl::AbortedError("aborted"));
  EXPECT_THAT(s, Not(IsOkAndHolds(3)));
}

}  // namespace
}  // namespace cloud_kms

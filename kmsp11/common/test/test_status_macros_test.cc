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

#include "common/test/test_status_macros.h"

#include "gmock/gmock.h"
#include "gtest/gtest-spi.h"

namespace cloud_kms {
namespace {

TEST(ExpectOkTest, OkStatus) { EXPECT_OK(absl::OkStatus()); }

TEST(ExpectOkTest, OkStatusOr) { EXPECT_OK(absl::StatusOr<int>(3)); }

TEST(ExpectOkTest, NotOkStatus) {
  EXPECT_NONFATAL_FAILURE(EXPECT_OK(absl::UnknownError("foo")), "UNKNOWN: foo");
}

TEST(ExpectOkTest, NotOkStatusOr) {
  EXPECT_NONFATAL_FAILURE(
      EXPECT_OK(absl::StatusOr<int>(absl::UnknownError("foo"))),
      "UNKNOWN: foo");
}

TEST(AssertOkTest, OkStatus) { ASSERT_OK(absl::OkStatus()); }

TEST(AssertOkTest, OkStatusOr) { ASSERT_OK(absl::StatusOr<int>(3)); }

TEST(AssertOkTest, NotOkStatus) {
  EXPECT_FATAL_FAILURE(ASSERT_OK(absl::NotFoundError("foo")), "NOT_FOUND: foo");
}

TEST(AssertOkTest, NotOkStatusOr) {
  EXPECT_FATAL_FAILURE(
      ASSERT_OK(absl::StatusOr<int>(absl::NotFoundError("foo"))),
      "NOT_FOUND: foo");
}

TEST(AssertOkAndAssignTest, OkCopyableExistingVar) {
  int i = 0;
  auto f = []() -> absl::StatusOr<int> { return 3; };
  ASSERT_OK_AND_ASSIGN(i, f());
  EXPECT_EQ(i, 3);
}

TEST(AssertOkAndAssignTest, OkCopyableNewVar) {
  auto f = []() -> absl::StatusOr<int> { return 3; };
  ASSERT_OK_AND_ASSIGN(int i, f());
  EXPECT_EQ(i, 3);
}

TEST(AssertOkAndAssignTest, OkMovableExistingVar) {
  std::unique_ptr<int> i;
  auto f = []() -> absl::StatusOr<std::unique_ptr<int>> {
    return std::make_unique<int>(3);
  };
  ASSERT_OK_AND_ASSIGN(i, f());
  EXPECT_EQ(*i, 3);
}

TEST(AssertOkAndAssignTest, OkMovableNewVar) {
  auto f = []() -> absl::StatusOr<std::unique_ptr<int>> {
    return std::make_unique<int>(3);
  };
  ASSERT_OK_AND_ASSIGN(auto i, f());
  EXPECT_EQ(*i, 3);
}

TEST(AssertOkAndAssignTest, NotOkCopyableExistingVar) {
  EXPECT_FATAL_FAILURE(
      []() -> void {
        auto f = []() -> absl::StatusOr<int> {
          return absl::UnknownError("unknown");
        };
        int i;
        ASSERT_OK_AND_ASSIGN(i, f());
        i++;  // hush the compiler warning for an unused variable
      }(),
      "UNKNOWN: unknown");
}

TEST(AssertOkAndAssignTest, NotOkCopyableNewVar) {
  EXPECT_FATAL_FAILURE(
      []() -> void {
        auto f = []() -> absl::StatusOr<int> {
          return absl::ResourceExhaustedError("no quota");
        };
        ASSERT_OK_AND_ASSIGN(int i, f());
        i++;  // hush the compiler warning for an unused variable
      }(),
      "RESOURCE_EXHAUSTED: no quota");
}

TEST(AssertOkAndAssignTest, NotOkMovableExistingVar) {
  EXPECT_FATAL_FAILURE(
      []() -> void {
        auto f = []() -> absl::StatusOr<std::unique_ptr<int>> {
          return absl::FailedPreconditionError("foo");
        };
        std::unique_ptr<int> i;
        ASSERT_OK_AND_ASSIGN(i, f());
        (*i)++;  // hush the compiler warning for an unused variable
      }(),
      "FAILED_PRECONDITION: foo");
}

TEST(AssertOkAndAssignTest, NotOkMovableNewVar) {
  EXPECT_FATAL_FAILURE(
      []() -> void {
        auto f = []() -> absl::StatusOr<std::unique_ptr<int>> {
          return absl::UnauthenticatedError("bar");
        };
        ASSERT_OK_AND_ASSIGN(std::unique_ptr<int> i, f());
        (*i)++;  // hush the compiler warning for an unused variable
      }(),
      "UNAUTHENTICATED: bar");
}

}  // namespace
}  // namespace cloud_kms

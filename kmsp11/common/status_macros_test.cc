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

#include "common/status_macros.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"

namespace cloud_kms {
namespace {

TEST(ReturnIfErrorTest, NoEarlyReturnOnOkStatus) {
  int i = 0;

  absl::Status result = [&i]() -> absl::Status {
    auto okFunc = []() -> absl::Status { return absl::OkStatus(); };
    RETURN_IF_ERROR(okFunc());
    i = 3;
    return absl::OkStatus();
  }();

  EXPECT_OK(result);
  EXPECT_EQ(i, 3);
}

TEST(ReturnIfErrorTest, InvalidArgumentStatus) {
  int i = 0;
  absl::Status result = [&i]() -> absl::Status {
    RETURN_IF_ERROR(absl::NotFoundError("not found"));
    i = 3;
    return absl::OkStatus();
  }();

  EXPECT_THAT(result, StatusIs(absl::StatusCode::kNotFound));
  EXPECT_EQ(i, 0);
}

TEST(ReturnIfErrorTest, ReturnsFromStatusOr) {
  absl::Status s = absl::UnknownError("unknown");
  absl::StatusOr<int> result = [&s]() -> absl::StatusOr<int> {
    RETURN_IF_ERROR(s);
    return 3;
  }();
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnknown));
  // It's important that the returned status is equal, and doesn't just have
  // the same code. Message and payload should be equal too.
  EXPECT_EQ(result.status(), s);
}

TEST(AssignOrReturnTest, MutateStateOnOkStatus) {
  int i = 0;
  absl::Status s = [&i]() -> absl::Status {
    ASSIGN_OR_RETURN(i, absl::StatusOr<int>(3));
    return absl::OkStatus();
  }();
  EXPECT_OK(s);
  EXPECT_EQ(i, 3);
}

TEST(AssignOrReturnTest, InitializeStateOnOkStatus) {
  absl::StatusOr<int> s = []() -> absl::StatusOr<int> {
    ASSIGN_OR_RETURN(int j, absl::StatusOr<int>(3));
    return j + 1;
  }();
  EXPECT_OK(s);
  EXPECT_EQ(s.value(), 4);
}

TEST(AssignOrReturnTest, MoveConstructibleIsMoved) {
  auto f = []() -> absl::StatusOr<std::unique_ptr<int>> {
    return std::make_unique<int>(3);
  };
  absl::StatusOr<int> s = [&f]() -> absl::StatusOr<int> {
    ASSIGN_OR_RETURN(std::unique_ptr<int> i, f());
    return *i;
  }();
  EXPECT_OK(s);
  EXPECT_EQ(s.value(), 3);
}

TEST(AssignOrReturnTest, ReturnOnNonOkStatus) {
  absl::Status s = absl::AbortedError("aborted");
  absl::StatusOr<int> s_or = [&s]() -> absl::StatusOr<int> {
    ASSIGN_OR_RETURN(int i, absl::StatusOr<int>(s));
    return i;
  }();
  EXPECT_THAT(s_or, StatusIs(absl::StatusCode::kAborted));
  // It's important that the returned status is equal, and doesn't just have
  // the same code. Message and payload should be equal too.
  EXPECT_EQ(s_or.status(), s);
}

}  // namespace
}  // namespace cloud_kms

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

#include "common/backoff.h"

#include "gmock/gmock.h"

namespace cloud_kms {
namespace {

TEST(ComputeBackoffTest, Simple) {
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 0),
            absl::Seconds(1));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 1),
            absl::Seconds(1.3));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 2),
            absl::Seconds(1.69));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 3),
            absl::Seconds(2.197));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 4),
            absl::Seconds(2.8561));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 5),
            absl::Seconds(3.71293));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 6),
            absl::Seconds(4.826809));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 7),
            absl::Seconds(6.2748517));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 8),
            absl::Seconds(8.15730721));
  EXPECT_EQ(ComputeBackoff(absl::Seconds(1), absl::Seconds(10), 9),
            absl::Seconds(10));
}

TEST(ComputeBackoffTest, MinDelayLessThan1nsIsCoercedTo1ns) {
  EXPECT_EQ(ComputeBackoff(absl::ZeroDuration(), absl::Seconds(1), 0),
            absl::Nanoseconds(1));
}

TEST(ComputeBackoffTest, MaxDelayLessThanMinDelayIsCoercedToMinDelay) {
  EXPECT_EQ(ComputeBackoff(absl::Hours(2), absl::Hours(1), 0), absl::Hours(2));
}

TEST(ComputeBackoffTest, PreviousRetriesLessThanZeroIsCoercedToZero) {
  EXPECT_EQ(ComputeBackoff(absl::Hours(1), absl::Hours(2), -5), absl::Hours(1));
}

TEST(ComputeBackoffTest, SmallDurations) {
  // Make sure we do actually exponentially back off for low minimum delays.
  EXPECT_LT(absl::Nanoseconds(1),
            ComputeBackoff(absl::Nanoseconds(1), absl::Nanoseconds(1000), 10));
  EXPECT_LT(ComputeBackoff(absl::Nanoseconds(1), absl::Nanoseconds(1000), 10),
            ComputeBackoff(absl::Nanoseconds(1), absl::Nanoseconds(1000), 20));
}

TEST(ComputeBackoffTest, ManyRetries) {
  // Make sure we don't suffer any weird overflow issues.
  const absl::Duration backoff =
      ComputeBackoff(absl::Nanoseconds(1), absl::InfiniteDuration(), 1 << 30);

  EXPECT_LT(absl::Nanoseconds(1), backoff);
  EXPECT_LE(backoff, absl::InfiniteDuration());
}

}  // namespace
}  // namespace cloud_kms

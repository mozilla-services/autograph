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

#include "absl/log/absl_log.h"

namespace cloud_kms {

absl::Duration ComputeBackoff(absl::Duration min_delay,
                              absl::Duration max_delay, int previous_retries) {
  if (min_delay < absl::Nanoseconds(1)) {
    ABSL_LOG_FIRST_N(WARNING, 100)
        << "ComputeBackoff increasing min_delay from " << min_delay
        << " to 1ns.";
    min_delay = absl::Nanoseconds(1);
  }
  if (max_delay < min_delay) {
    ABSL_LOG_FIRST_N(WARNING, 100)
        << "ComputeBackoff increasing max_delay of " << max_delay
        << " to match min_delay of " << min_delay << ".";
    max_delay = min_delay;
  }
  if (previous_retries < 0) {
    ABSL_LOG_FIRST_N(WARNING, 100)
        << "ComputeBackoff increasing previous_retries from "
        << previous_retries << " to 0.";
    previous_retries = 0;
  }

  constexpr double kBackoffMultiplier = 1.3;
  absl::Duration uncapped_delay =
      min_delay * std::pow(kBackoffMultiplier, previous_retries);
  absl::Duration delay = std::min(uncapped_delay, max_delay);

  // Ensure that floating point errors don't cause us to violate our contract.
  delay = std::max(delay, min_delay);
  return delay;
}

}  // namespace cloud_kms

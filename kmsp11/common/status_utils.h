/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_STATUS_UTILS_H_
#define COMMON_STATUS_UTILS_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "grpcpp/support/status.h"

namespace cloud_kms {

// These functions permit us to call ToStatus(x) on varying types of statuses.

inline const absl::Status& ToStatus(const absl::Status& status) {
  return status;
}

template <typename T>
inline const absl::Status& ToStatus(const absl::StatusOr<T>& status_or) {
  return status_or.status();
}

inline absl::Status ToStatus(const grpc::Status& status) {
  return absl::Status(absl::StatusCode(status.error_code()),
                      status.error_message());
}

}  // namespace cloud_kms

#endif  // COMMON_STATUS_UTILS_H_

/*
 * Copyright 2023 Google LLC
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

#ifndef KMSCNG_UTIL_ERRORS_H_
#define KMSCNG_UTIL_ERRORS_H_

#include "absl/status/status.h"
#include "common/source_location.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

// Creates a new error status with the provided parameters.
// `code` and `ss` must not be OK; these requirements are CHECKed.
absl::Status NewError(absl::StatusCode code, std::string_view msg,
                      SECURITY_STATUS ss,
                      const SourceLocation& source_location);

// Creates a new Internal error with a SECURITY_STATUS of NTE_INTERNAL_ERROR.
inline absl::Status NewInternalError(std::string_view msg,
                                     const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInternal, msg, NTE_INTERNAL_ERROR,
                  source_location);
}

// Creates a new error with status code unimplemented and SECURITY_STATUS of
// NTE_NOT_SUPPORTED.
inline absl::Status NewUnsupportedError(const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "the function is not supported", NTE_NOT_SUPPORTED,
                  source_location);
}

// Creates a new InvalidArgument error with the provided SECURITY_STATUS.
inline absl::Status NewInvalidArgumentError(
    std::string_view msg, SECURITY_STATUS ss,
    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInvalidArgument, msg, ss, source_location);
}

// Creates a new OutOfRange error with a SECURITY_STATUS of
// NTE_BUFFER_TOO_SMALL.
inline absl::Status NewOutOfRangeError(std::string_view msg,
                                       const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kOutOfRange, msg, NTE_BUFFER_TOO_SMALL,
                  source_location);
}

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_UTIL_ERRORS_H_

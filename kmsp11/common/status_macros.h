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

#ifndef COMMON_STATUS_MACROS_H_
#define COMMON_STATUS_MACROS_H_

#include "common/status_utils.h"

// Run a command that returns an absl::Status. If the called code returns a
// non-OK status, return that value up out of this method too.
//
// Example:
//   RETURN_IF_ERROR(DoThings(4));
#define RETURN_IF_ERROR(expr)                                                \
  do {                                                                       \
    /* Using _status below to avoid capture problems if expr is "status". */ \
    const ::absl::Status _status = ::cloud_kms::ToStatus(expr);              \
    if (!_status.ok()) return _status;                                       \
  } while (0)

// Internal helper for concatenating macro values.
#define STATUS_CONCAT_NAME_INNER(x, y) x##y
#define STATUS_CONCAT_NAME(x, y) STATUS_CONCAT_NAME_INNER(x, y)

#define ASSIGN_OR_RETURN_IMPL(var, lhs, rexpr)  \
  auto var = (rexpr);                           \
  if (ABSL_PREDICT_FALSE(!var.ok()))            \
    return ::cloud_kms::ToStatus(var.status()); \
  lhs = std::move(var).value();

// Executes an expression that returns a absl::StatusOr, extracting its value
// into the variable defined by lhs (or returning on error).
//
// Example: Assigning to an existing value
//   ValueType value;
//   ASSIGN_OR_RETURN(value, MaybeGetValue(arg));
//
// WARNING: ASSIGN_OR_RETURN expands into multiple statements; it cannot be used
//  in a single statement (e.g. as the body of an if statement without {})!
#define ASSIGN_OR_RETURN(lhs, rexpr)                                      \
  ASSIGN_OR_RETURN_IMPL(STATUS_CONCAT_NAME(_status_or, __COUNTER__), lhs, \
                        rexpr);

#endif  // COMMON_STATUS_MACROS_H_

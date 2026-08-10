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

#ifndef KMSP11_UTIL_ERRORS_H_
#define KMSP11_UTIL_ERRORS_H_

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "common/source_location.h"
#include "common/status_utils.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/status_utils.h"

namespace cloud_kms::kmsp11 {

// Creates a new error status with the provided parameters.
// `code` and `ck_rv` must not be OK; these requirements are CHECKed.
absl::Status NewError(absl::StatusCode code, std::string_view msg, CK_RV ck_rv,
                      const SourceLocation& source_location);

// Creates a new FailedPrecondition error with the provided CK_RV.
inline absl::Status FailedPreconditionError(
    std::string_view msg, CK_RV ck_rv, const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition, msg, ck_rv,
                  source_location);
}

// Creates a new NotFound error for a missing handle with the provided CK_RV.
inline absl::Status HandleNotFoundError(CK_ULONG handle, CK_RV rv,
                                        const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kNotFound,
                  absl::StrFormat("handle not found: %#x", handle), rv,
                  SOURCE_LOCATION);
}

// Creates a new InvalidArgument error with ck_rv = CKR_MECHANISM_INVALID.
inline absl::Status InvalidMechanismError(
    CK_MECHANISM_TYPE mechanism_type, std::string_view operation,
    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat("mechanism %#x is not valid for operation %s",
                                  mechanism_type, operation),
                  CKR_MECHANISM_INVALID, source_location);
}

// Creates a new InvalidArgument error with ck_rv = CKR_MECHANISM_PARAM_INVALID.
inline absl::Status InvalidMechanismParamError(
    std::string_view message, const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInvalidArgument, message,
                  CKR_MECHANISM_PARAM_INVALID, source_location);
}

// Creates a new Internal error with a return value of
// CKR_GENERAL_ERROR.
inline absl::Status NewInternalError(std::string_view msg,
                                     const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInternal, msg, CKR_GENERAL_ERROR,
                  source_location);
}

// Creates a new InvalidArgument error with the provided CK_RV.
inline absl::Status NewInvalidArgumentError(
    std::string_view msg, CK_RV ck_rv, const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kInvalidArgument, msg, ck_rv,
                  source_location);
}

// Creates a new InvalidArgument error with rv = CKR_ARGUMENTS_BAD.
inline absl::Status NullArgumentError(std::string_view arg_name,
                                      const SourceLocation& source_location) {
  return NewInvalidArgumentError(
      absl::StrFormat("argument %s was unexpectedly null", arg_name),
      CKR_ARGUMENTS_BAD, source_location);
}

// Creates a new FailedPrecondition error with a return value of
// CKR_CRYPTOKI_NOT_INITIALIZED.
inline absl::Status NotInitializedError(const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition,
                  "the library is not initialized",
                  CKR_CRYPTOKI_NOT_INITIALIZED, source_location);
}

// Creates a new FailedPrecondition error with a return value of
// CKR_OPERATION_ACTIVE.
inline absl::Status OperationActiveError(
    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition,
                  "another operation is already active", CKR_OPERATION_ACTIVE,
                  source_location);
}

// Creates a new FailedPrecondition error with a return value of
// CKR_OPERATION_NOT_INITIALIZED.
inline absl::Status OperationNotInitializedError(
    std::string_view operation_name, const SourceLocation& source_location) {
  return NewError(
      absl::StatusCode::kFailedPrecondition,
      absl::StrFormat("operation '%s' is not active", operation_name),
      CKR_OPERATION_NOT_INITIALIZED, source_location);
}

// Creates a new error with status code OutOfRange and return value of
// CKR_BUFFER_TOO_SMALL.
inline absl::Status OutOfRangeError(std::string_view msg,
                                    const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kOutOfRange, msg, CKR_BUFFER_TOO_SMALL,
                  source_location);
}

// Creates a new error with status code unimplemented and return value of
// CKR_FUNCTION_NOT_SUPPORTED.
inline absl::Status UnsupportedError(const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kUnimplemented,
                  "the function is not supported", CKR_FUNCTION_NOT_SUPPORTED,
                  source_location);
}

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_ERRORS_H_

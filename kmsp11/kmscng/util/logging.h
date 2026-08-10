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

#ifndef KMSCNG_UTIL_LOGGING_H_
#define KMSCNG_UTIL_LOGGING_H_

#include <string_view>

#include "absl/base/log_severity.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

const char* const kVerboseLoggingEnvVariable = "KMS_CNG_VERBOSE";

SECURITY_STATUS LogAndResolve(std::string_view function_name,
                              const absl::Status& status);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_UTIL_LOGGING_H_

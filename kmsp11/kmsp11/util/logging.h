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

#ifndef KMSP11_UTIL_LOGGING_H_
#define KMSP11_UTIL_LOGGING_H_

#include <string_view>

#include "absl/status/status.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

absl::Status InitializeLogging(std::string_view output_directory,
                               std::string_view output_filename_suffix);
void ShutdownLogging();

CK_RV LogAndResolve(std::string_view function_name, const absl::Status& status);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_LOGGING_H_

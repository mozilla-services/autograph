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

#ifndef FAKEKMS_CPP_FAULT_HELPERS_H_
#define FAKEKMS_CPP_FAULT_HELPERS_H_

#include <string_view>

#include "absl/status/status.h"
#include "absl/time/time.h"
#include "fakekms/cpp/fakekms.h"
#include "fakekms/fault/fault.grpc.pb.h"

namespace fakekms {

void AddDelayOrDie(const Server& server, absl::Duration delay,
                   std::string_view method_name = "");

void AddErrorOrDie(const Server& server, absl::Status error,
                   std::string_view method_name = "");

}  // namespace fakekms

#endif  // FAKEKMS_CPP_FAULT_HELPERS_H_

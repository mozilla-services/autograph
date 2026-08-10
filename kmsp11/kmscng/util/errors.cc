// Copyright 2023 Google LLC
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

#include "kmscng/util/errors.h"

#include "absl/strings/str_cat.h"
#include "common/status_utils.h"
#include "glog/logging.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {

absl::Status NewError(absl::StatusCode code, std::string_view msg,
                      SECURITY_STATUS ss,
                      const SourceLocation& source_location) {
  CHECK(code != absl::StatusCode::kOk)
      << "errors::New cannot be called with code=OK; original location="
      << source_location.ToString();
  CHECK(ss != ERROR_SUCCESS) << "errors::New cannot be called with "
                                "ss=ERROR_SUCCESS; original location="
                             << source_location.ToString();
  absl::Status status(
      code, absl::StrCat("at ", source_location.ToString(), ": ", msg));
  SetErrorSs(status, ss);
  return status;
}

}  // namespace cloud_kms::kmscng

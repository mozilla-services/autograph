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

#include "kmsp11/util/errors.h"

#include "absl/strings/str_cat.h"
#include "glog/logging.h"

namespace cloud_kms::kmsp11 {

absl::Status NewError(absl::StatusCode code, std::string_view msg, CK_RV ck_rv,
                      const SourceLocation& source_location) {
  CHECK(code != absl::StatusCode::kOk)
      << "errors::New cannot be called with code=OK; original location="
      << source_location.ToString();
  CHECK(ck_rv != CKR_OK)
      << "errors::New cannot be called with ck_rv=CKR_OK; original location="
      << source_location.ToString();
  absl::Status status(
      code, absl::StrCat("at ", source_location.ToString(), ": ", msg));
  SetErrorRv(status, ck_rv);
  return status;
}

}  // namespace cloud_kms::kmsp11
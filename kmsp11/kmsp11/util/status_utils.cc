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

#include "kmsp11/util/status_utils.h"

#include <cstring>
#include <optional>
#include <string>

#include "absl/status/status_payload_printer.h"
#include "absl/strings/cord.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "common/status_details.pb.h"
#include "common/status_utils.h"
#include "glog/logging.h"

namespace cloud_kms::kmsp11 {
namespace {

// The URL we'll use for storing a custom payload in the status.
// Notes on the naming convention are at
// https://github.com/abseil/abseil-cpp/blob/bf6166a635ab57fe0559b00dcd3ff09a8c42de2e/absl/status/status.h#L149
constexpr std::string_view kTypeUrl =
    "type.googleapis.com/kmsp11.StatusDetails";

CK_RV ExtractRvFromCord(const absl::Cord& cord) {
  std::string payload(cord);
  StatusDetails details;
  if (!details.ParseFromString(payload)) {
    // It doesn't really make sense to return an error status from a function
    // that is itself processing an error status. Log a warning instead.
    LOG(WARNING) << "status payload of type " << kTypeUrl << " with payload '"
                 << absl::BytesToHexString(payload)
                 << "' could not be parsed as a StatusDetails";
  }
  return details.rv();
}

std::optional<std::string> PrintPayload(std::string_view type_url,
                                        const absl::Cord& content) {
  if (type_url != kTypeUrl) {
    return std::nullopt;
  }
  return absl::StrFormat("CK_RV=%#x", ExtractRvFromCord(content));
}

}  // namespace

void SetErrorRv(absl::Status& status, CK_RV rv) {
  static const bool kPayloadPrinterRegistered = [] {
    absl::status_internal::SetStatusPayloadPrinter(&PrintPayload);
    return true;
  }();
  CHECK(kPayloadPrinterRegistered);
  CHECK(!status.ok()) << "attempting to set rv=" << rv << " for status OK";
  CHECK(rv != CKR_OK) << "attempting to set rv=0 for status " << status;
  StatusDetails details;
  details.set_rv(rv);
  status.SetPayload(kTypeUrl, absl::Cord(details.SerializeAsString()));
}

CK_RV GetCkRv(const absl::Status& status) {
  if (status.ok()) {
    return CKR_OK;
  }

  std::optional<absl::Cord> payload = status.GetPayload(kTypeUrl);
  if (!payload.has_value()) {
    return kDefaultErrorCkRv;
  }

  CK_RV rv = ExtractRvFromCord(*payload);
  if (rv == CKR_OK) {
    LOG(WARNING) << "recovered status details has rv=CKR_OK; falling back to "
                    "default error code";
    return kDefaultErrorCkRv;
  }
  return rv;
}

}  // namespace cloud_kms::kmsp11

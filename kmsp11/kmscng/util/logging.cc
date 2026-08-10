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

#include "kmscng/util/logging.h"

#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "absl/strings/str_format.h"
#include "absl/synchronization/mutex.h"
#include "common/platform.h"
#include "common/status_utils.h"
#include "grpc/support/log.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {
namespace {

void GrpcLog(gpr_log_func_args* args) {
  // Map gRPC severities to log severities.
  // gRPC severities: ERROR, INFO, DEBUG
  // log severities: FATAL, ERROR, WARNING, INFO
  std::string log_message =
      absl::StrFormat("[%s:%d]: %s", args->file, args->line, args->message);
  switch (args->severity) {
    // gRPC ERROR -> WARNING. gRPC errors aren't necessarily errors for
    // us; see e.g. https://github.com/grpc/grpc/issues/22613. We should emit
    // our own message at level ERROR for events that we consider errors.
    case GPR_LOG_SEVERITY_ERROR:
      LOG(WARNING) << log_message;
      break;
    // gRPC INFO and gRPC DEBUG -> INFO. Note that, by default, gRPC will
    // not pass us messages at these levels. The GRPC_VERBOSITY environment
    // variable would need to be set.
    // https://github.com/grpc/grpc/blob/master/TROUBLESHOOTING.md#grpc_verbosity
    default:
      LOG(INFO) << log_message;
      break;
  }
}

static const bool logging_initialized = []() {
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  absl::InitializeLog();
  gpr_set_log_function(&GrpcLog);
  return true;
}();

}  // namespace

SECURITY_STATUS LogAndResolve(std::string_view function_name,
                              const absl::Status& status) {
  if (status.ok()) {
    return ERROR_SUCCESS;
  }

  SECURITY_STATUS ss = GetErrorSs(status);
  std::string message =
      absl::StrFormat("returning %#x from %s due to status %s", ss,
                      function_name, status.ToString());

  if (absl::IsInternal(status)) {
    // Internal statuses mean some library assumption was violated, so treat
    // this more severely than a business error.
    LOG(ERROR) << message;
    return ss;
  }

  // Treat all other non-OK statuses as business errors.
  LOG(INFO) << message;
  return ss;
}

}  // namespace cloud_kms::kmscng

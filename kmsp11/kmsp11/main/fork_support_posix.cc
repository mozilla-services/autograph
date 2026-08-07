// Copyright 2022 Google LLC
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

#include <pthread.h>
#include <string.h>

#include "grpc/fork.h"
#include "kmsp11/main/fork_support.h"
#include "kmsp11/util/global_provider.h"
#include "kmsp11/util/logging.h"

namespace cloud_kms::kmsp11 {

absl::Status RegisterForkHandlers() {
  // pthread_atfork handlers are run in order according to specified rules.
  // https://man7.org/linux/man-pages/man3/pthread_atfork.3.html#RETURN_VALUE
  //
  //
  // Our post-fork child routine hangs unless it comes after gRPC's.

  // This is the gRPC team's prescribed way of registering fork handlers.
  //
  // Internally, gRPC registers its fork handlers during `grpc_init()`. The
  // right way to call grpc_init from C++ is to instantiate
  // `grpc::internal::GrpcLibrary` or one of its subclasses.
  grpc::internal::GrpcLibrary init;

  // Now we can register our own fork handler.
  int result =
      pthread_atfork(/*prepare=*/nullptr, /*parent=*/nullptr, /*child=*/[] {
        ReleaseGlobalProvider().IgnoreError();
        ShutdownLogging();
      });
  if (result != 0) {
    return absl::InternalError(
        absl::StrCat("pthread_atfork failed with error ", strerror(result)));
  }
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11
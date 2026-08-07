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

#include "fakekms/cpp/fakekms.h"

#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "gmock/gmock.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"

namespace fakekms {
namespace {

namespace kms_v1 = ::google::cloud::kms::v1;

// Declare an IsOk matcher locally so that we don't have to depend on kmsp11.
MATCHER(IsOk, absl::StrFormat("status is %sOK", negation ? "not " : "")) {
  return arg.ok();
}

TEST(ServerTest, SmokeTest) {
  absl::StatusOr<std::unique_ptr<Server>> server = Server::New();
  ASSERT_THAT(server.status(), IsOk());

  std::unique_ptr<kms_v1::KeyManagementService::Stub> stub =
      (*server)->NewClient();

  grpc::ClientContext ctx;

  kms_v1::CreateKeyRingRequest req;
  req.set_parent("projects/my-project/locations/us-central1");
  req.set_key_ring_id("kr1");

  kms_v1::KeyRing kr;

  EXPECT_THAT(stub->CreateKeyRing(&ctx, req, &kr), IsOk());
  EXPECT_EQ(kr.name(),
            "projects/my-project/locations/us-central1/keyRings/kr1");
}

}  // namespace
}  // namespace fakekms

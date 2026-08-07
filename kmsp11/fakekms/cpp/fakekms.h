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

#ifndef FAKEKMS_CPP_FAKEKMS_H_
#define FAKEKMS_CPP_FAKEKMS_H_

#include "absl/status/statusor.h"
#include "absl/strings/str_split.h"
#include "absl/strings/strip.h"
#include "fakekms/fault/fault.grpc.pb.h"
#include "glog/logging.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace fakekms {

// Class Server provides a C++ language binding for launching a Fake KMS
// server.
//
// The binding is implemented by launching the fake server in a child process.
// Unfortunately, cgo is not an option for our use, because cgo requires clang
// or gcc, and we compile using MSVC on Windows.
//
// On both Windows and Posix platforms, the fake server is launched in a child
// process and the parent captures the child-determined listen address. During
// the FakeKms object lifetime, the server at listen_addr() is available for
// use. The FakeKms destructor shuts down the child process and releases all
// resources associated with the fake.
class Server {
 public:
  static absl::StatusOr<std::unique_ptr<Server>> New();

  virtual ~Server() {}

  const std::string& listen_addr() const { return listen_addr_; }

  inline std::unique_ptr<google::cloud::kms::v1::KeyManagementService::Stub>
  NewClient() const {
    return google::cloud::kms::v1::KeyManagementService::NewStub(
        client_channel_);
  }

  inline std::unique_ptr<FaultService::Stub> NewFaultClient() const {
    return FaultService::NewStub(client_channel_);
  }

 protected:
  Server(std::string listen_addr) {
    std::vector<std::string> split = absl::StrSplit(listen_addr, '\n');
    listen_addr_ = std::string(absl::StripAsciiWhitespace(split[0]));
    client_channel_ =
        grpc::CreateChannel(listen_addr_, grpc::InsecureChannelCredentials());
  }

  inline static std::string BinaryLocation(
      std::string_view binary_suffix = "") {
    using ::bazel::tools::cpp::runfiles::Runfiles;
    std::string error;
    std::unique_ptr<Runfiles> runfiles =
        absl::WrapUnique(Runfiles::CreateForTest(&error));
    CHECK(runfiles) << "error creating runfiles: " << error;
    return runfiles->Rlocation(absl::StrCat(
        "com_google_kmstools/fakekms/main/fakekms_/fakekms", binary_suffix));
  }

 private:
  std::string listen_addr_;
  std::shared_ptr<grpc::Channel> client_channel_;
};

}  // namespace fakekms

#endif  // FAKEKMS_CPP_FAKEKMS_H_

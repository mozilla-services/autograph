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

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(FipsTest, InitializeFailsFipsSelfTestFipsModeRequired) {
  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file) << "require_fips_mode: true" << std::endl;
  absl::Cleanup c = [&] { std::remove(config_file.c_str()); };

  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = const_cast<char*>(config_file.c_str());

  EXPECT_DEATH(
      Initialize(&init_args).IgnoreError(),
      AllOf(HasSubstr("FIPS tests failed"), HasSubstr("FIPS_mode()=0")));
}

}  // namespace
}  // namespace cloud_kms::kmsp11

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

#include <iostream>
#include <string>

#include "absl/status/status.h"
#include "kmscng/util/registration.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "Invalid number of arguments: want 2; got " << argc << "\n";
  }

  // Valid arguments: 'i' for install, 'u' for uninstall.
  if (strcmp(argv[1], "i") == 0) {
    absl::Status result = cloud_kms::kmscng::RegisterProvider();
    if (!result.ok()) {
      std::cerr << result.message() << "\n";
    }
    return static_cast<int>(result.code());
  } else if (strcmp(argv[1], "u") == 0) {
    absl::Status result = cloud_kms::kmscng::UnregisterProvider();
    if (!result.ok()) {
      std::cerr << result.message() << "\n";
    }
    return static_cast<int>(result.code());
  }

  return 1;
}

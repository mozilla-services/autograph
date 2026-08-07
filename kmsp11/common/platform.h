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

#ifndef COMMON_PLATFORM_H_
#define COMMON_PLATFORM_H_

#include <cstdlib>
#include <string>

#include "absl/status/status.h"

namespace cloud_kms {

// Ensure that the file at the provided path is not group- or world- writeable.
// Note that always returns OK on Windows. (See b/148377771).
absl::Status EnsureWriteProtected(const char* filename);

// Returns "x86" or "amd64" indicating the target platform for this binary.
std::string_view GetTargetPlatform();

// Return a string that provides host platform information suitable for
// inclusion an a user-agent header. Note that the host platform may vary from
// the target platform (e.g. running an x86 binary on amd64).
//
// Examples:
// "Linux/4.15.0-1096-gcp-amd64-x86_64; glibc/2.23"
// "FreeBSD/11.4-RELEASE-p2-amd64"
// "Darwin/19.6.0-x86_64"
// "Windows Server Datacenter/10.0.2004.19041-amd64"
std::string GetHostPlatformInfo();

// Writes the provided message to the system log. This is a no-op on Windows.
void WriteToSystemLog(const char* message);

}  // namespace cloud_kms

#endif  // COMMON_PLATFORM_H_

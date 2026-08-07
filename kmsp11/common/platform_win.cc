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

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "absl/cleanup/cleanup.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "common/platform.h"
#include "common/source_location.h"
#include "common/status_macros.h"

namespace cloud_kms {
namespace {

struct SystemVersionInfo {
  std::string product_name;
  DWORD major_version;
  DWORD minor_version;
  std::string release_id;
  std::string current_build;
};

// Retrieves system version information from the Windows registry.
//
// Using the Win32 API to look up version information would be nicer, but the
// Win32 APIs purposely serve up the wrong information, in an attempt to keep
// poorly coded applcations compatible.
// https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexa
absl::StatusOr<SystemVersionInfo> GetSystemVersionInfo() {
  constexpr LPCSTR kKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
  HKEY key_handle;
  LSTATUS open_status =
      RegOpenKeyEx(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ, &key_handle);
  if (open_status != ERROR_SUCCESS) {
    return absl::InternalError(
        absl::StrFormat("at %s: error %d opening key '%s'.",
                        SOURCE_LOCATION.ToString(), open_status, kKey));
  }
  absl::Cleanup c = [&] {
    ABSL_DCHECK_EQ(RegCloseKey(key_handle), ERROR_SUCCESS);
  };

  auto read_string =
      [&](const LPCSTR value_name) -> absl::StatusOr<std::string> {
    DWORD length;
    LSTATUS query_status = RegQueryValueEx(key_handle, value_name, nullptr,
                                           nullptr, nullptr, &length);
    if (query_status != ERROR_SUCCESS) {
      return absl::InternalError(absl::StrFormat(
          "at %s: error %d retrieving length for '%s'.",
          SOURCE_LOCATION.ToString(), query_status, value_name));
    }

    DWORD type = REG_SZ;
    std::string result(length, 0);
    query_status =
        RegQueryValueEx(key_handle, value_name, nullptr, &type,
                        reinterpret_cast<LPBYTE>(result.data()), &length);
    if (query_status != ERROR_SUCCESS) {
      return absl::InternalError(absl::StrFormat(
          "at %s: error %d retrieving value for '%s'.",
          SOURCE_LOCATION.ToString(), query_status, value_name));
    }
    return result;
  };
  auto read_dword = [&](const LPCSTR value_name) -> absl::StatusOr<DWORD> {
    DWORD type = REG_DWORD;
    DWORD value;
    DWORD value_size = sizeof(value);
    LSTATUS query_status =
        RegQueryValueEx(key_handle, value_name, nullptr, &type,
                        reinterpret_cast<LPBYTE>(&value), &value_size);
    if (query_status != ERROR_SUCCESS) {
      return absl::InternalError(absl::StrFormat(
          "at %s: error %d retrieving value for '%s'.",
          SOURCE_LOCATION.ToString(), query_status, value_name));
    }
    return value;
  };

  SystemVersionInfo result;
  ASSIGN_OR_RETURN(result.product_name, read_string("ProductName"));
  ASSIGN_OR_RETURN(result.major_version,
                   read_dword("CurrentMajorVersionNumber"));
  ASSIGN_OR_RETURN(result.minor_version,
                   read_dword("CurrentMinorVersionNumber"));
  ASSIGN_OR_RETURN(result.release_id, read_string("ReleaseId"));
  ASSIGN_OR_RETURN(result.current_build, read_string("CurrentBuild"));
  return result;
}

}  // namespace

absl::Status EnsureWriteProtected(const char* filename) {
  return absl::OkStatus();
}

std::string_view GetTargetPlatform() {
#if _WIN64
  return "amd64";
#elif _WIN32
  return "x86";
#else
  static_assert(false, "unhandled processor type");
#endif
}

std::string GetHostPlatformInfo() {
  SYSTEM_INFO arch_info;
  GetNativeSystemInfo(&arch_info);
  std::string arch;
  switch (arch_info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
      arch = "amd64";
      break;
    case PROCESSOR_ARCHITECTURE_ARM:
      arch = "arm";
      break;
    case PROCESSOR_ARCHITECTURE_ARM64:
      arch = "aarch64";
      break;
    case PROCESSOR_ARCHITECTURE_INTEL:
      arch = "x86";
      break;
    default:
      arch = "unknown";
      break;
  }

  absl::StatusOr<SystemVersionInfo> info = GetSystemVersionInfo();
  if (!info.ok()) {
    return absl::StrCat("Windows/unknown-", arch);
  }
  return absl::StrFormat("%s/%d.%d.%s.%s-%s", info->product_name,
                         info->major_version, info->minor_version,
                         info->release_id, info->current_build, arch);
}

void WriteToSystemLog(const char* message) {
  // Maybe this could be implemented but it's pretty gross.
  // Windows event logs are highly structured and require a registered source.
  // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventa
  // https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources
}

}  // namespace cloud_kms

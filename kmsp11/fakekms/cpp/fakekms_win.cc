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
#include <windows.h>

#include "absl/cleanup/cleanup.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "fakekms/cpp/fakekms.h"

namespace fakekms {
namespace {

class WindowsServer : public Server {
 public:
  static absl::StatusOr<std::unique_ptr<WindowsServer>> New(
      std::string_view flags);

  WindowsServer(std::string listen_addr, HANDLE process_handle)
      : Server(listen_addr), process_handle_(process_handle) {}

  ~WindowsServer() {
    CHECK(TerminateProcess(process_handle_, 0));
    CHECK(CloseHandle(process_handle_));
  }

 private:
  HANDLE process_handle_;
};

absl::Status Win32ErrorToStatus(std::string_view message) {
  char* error_text = nullptr;
  DWORD error_code = GetLastError();

  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS,
                 nullptr, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 error_text, 0, nullptr);

  return absl::InternalError(
      absl::StrFormat("%s: code %d: %s", message, error_code, error_text));
}

}  // namespace

absl::StatusOr<std::unique_ptr<Server>> Server::New() {
  // https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output
  SECURITY_ATTRIBUTES security_attrs{
      sizeof(SECURITY_ATTRIBUTES),  // nLength
      nullptr,                      // lpSecurityDescriptor
      true,                         // bInheritHandle
  };

  HANDLE out_read, out_write;
  if (!CreatePipe(&out_read, &out_write, &security_attrs, 0)) {
    return Win32ErrorToStatus("error creating output pipe");
  }
  absl::Cleanup c = [&] {
    CHECK(CloseHandle(out_read));
    CHECK(CloseHandle(out_write));
  };

  STARTUPINFOA startup_info;
  ZeroMemory(&startup_info, sizeof(STARTUPINFOA));
  startup_info.cb = sizeof(STARTUPINFOA);
  startup_info.hStdOutput = out_write;
  startup_info.dwFlags = STARTF_USESTDHANDLES;

  PROCESS_INFORMATION process_info;

  std::string bin_path = BinaryLocation(".exe");
  if (!CreateProcessA(bin_path.c_str(), const_cast<char*>(bin_path.c_str()),
                      nullptr, nullptr, true, CREATE_NO_WINDOW, nullptr,
                      nullptr, &startup_info, &process_info)) {
    return Win32ErrorToStatus("error creating fakekms process");
  }
  CHECK(CloseHandle(process_info.hThread));  // we don't use this handle

  const size_t kBufferSize = 4096;  // should be enough to hold the listen addr
  char buf[kBufferSize];
  DWORD len;
  if (!ReadFile(out_read, buf, kBufferSize, &len, nullptr)) {
    return Win32ErrorToStatus("error reading listen address");
  }

  std::string address(buf, len);
  return std::make_unique<WindowsServer>(address, process_info.hProcess);
}

}  // namespace fakekms
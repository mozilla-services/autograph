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

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <unistd.h>

#ifdef __linux__
#include <gnu/libc-version.h>
#endif

#include "absl/strings/str_format.h"
#include "common/platform.h"
#include "common/source_location.h"

namespace cloud_kms {

absl::Status EnsureWriteProtected(const char* filename) {
  struct stat buf;
  if (stat(filename, &buf) != 0) {
    return absl::NotFoundError(
        absl::StrFormat("at %s: unable to stat file %s: error %d",
                        SOURCE_LOCATION.ToString(), filename, errno));
  }

  if ((buf.st_mode & S_IWGRP) == S_IWGRP ||
      (buf.st_mode & S_IWOTH) == S_IWOTH) {
    return absl::FailedPreconditionError(
        absl::StrFormat("at %s: file %s has excessive write permissions",
                        SOURCE_LOCATION.ToString(), filename));
  }

  return absl::OkStatus();
}

std::string_view GetTargetPlatform() {
#if defined(__amd64__)
  return "amd64";
#elif defined(__i386__)
  return "x86";
#elif defined(__aarch64__)
  return "aarch64";
#else
  static_assert(false, "unhandled processor type");
#endif
}

std::string GetHostPlatformInfo() {
  std::string info = "posix/unknown";
  utsname n;
  if (uname(&n) == 0) {
    info = absl::StrFormat("%s/%s-%s", n.sysname, n.release, n.machine);
  }

#ifdef __linux__
  // For Linux we target a specific minimum glibc version, so grab that
  // information as well.
  info = absl::StrCat(info, "; glibc/", gnu_get_libc_version());
#endif
  return info;
}

void WriteToSystemLog(const char* message) {
  // References
  // https://www.man7.org/linux/man-pages/man3/syslog.3.html
  // https://pubs.opengroup.org/onlinepubs/009695399/basedefs/syslog.h.html
  openlog("kmsp11", LOG_PID, LOG_USER);
  syslog(LOG_ERR, "%s", message);
  closelog();
}

}  // namespace cloud_kms

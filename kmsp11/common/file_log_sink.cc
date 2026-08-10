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

#include "common/file_log_sink.h"

#include <fstream>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

namespace cloud_kms {

std::string GetLogSeverityPrefix(absl::LogSeverity severity) {
  switch (severity) {
    case absl::LogSeverity::kInfo:
      return "[I]";
    case absl::LogSeverity::kError:
      return "[E]";
    case absl::LogSeverity::kWarning:
      return "[W]";
    case absl::LogSeverity::kFatal:
      return "[F]";
  }
}

absl::StatusOr<std::unique_ptr<FileLogSink>> FileLogSink::New(
    absl::string_view file_name) {
  // Try to open the file for appending to it and return an error if the file
  // could not be opened.
  std::ofstream s(std::string(file_name).c_str(), std::ofstream::app);
  if (!s) {
    return absl::InvalidArgumentError(
        absl::StrCat("Could not open file ", file_name));
  }
  return absl::WrapUnique(new FileLogSink(std::move(s)));
}

void FileLogSink::Send(const absl::LogEntry& e) {
  stream_ << GetLogSeverityPrefix(e.log_severity()) << "\t"
          << e.text_message_with_newline();
  // If we are logging a fatal error, flush the sink now because the process
  // will terminate right after this function returns.
  if (e.log_severity() == absl::LogSeverity::kFatal) {
    Flush();
  }
};

void FileLogSink::Flush() { stream_.flush(); };

FileLogSink::FileLogSink(std::ofstream stream) { stream_ = std::move(stream); }

}  // namespace cloud_kms

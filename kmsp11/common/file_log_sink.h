/*
 * Copyright 2023 Google LLC
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

#ifndef COMMON_FILE_LOG_SINK_H_
#define COMMON_FILE_LOG_SINK_H_

#include <fstream>

#include "absl/log/log.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace cloud_kms {
// A simple log sink that is writing all INFO log entries to a file.
class FileLogSink : public absl::LogSink {
 public:
  // Create a new FileLogSink that writes in the specified file_name.
  // Any logs are appended to the contents of the file if the file already
  // exists. Returns an error if the file cannot be opened.
  static absl::StatusOr<std::unique_ptr<FileLogSink>> New(
      absl::string_view file_name);

  // Logs messages to the specified file.
  // Writing to the file may fail silently.
  void Send(const absl::LogEntry& e) override;

  // Flush the buffer to file.
  void Flush() override;

 private:
  std::ofstream stream_;

  FileLogSink(std::ofstream stream);
};

}  // namespace cloud_kms
#endif  // COMMON_FILE_LOG_SINK_H_

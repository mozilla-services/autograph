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
#include <streambuf>
#include <string>

#include "absl/log/log.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace cloud_kms {
namespace {

using ::testing::_;
using ::testing::HasSubstr;

std::string ReadFile(const char* file_name) {
  std::ifstream stream(file_name);
  return std::string((std::istreambuf_iterator<char>(stream)),
                     std::istreambuf_iterator<char>());
}

TEST(FileLogSinkTest, SetLogFileSuccess) {
  EXPECT_OK(FileLogSink::New("test_creation.log"));
}

TEST(FileLogSinkTest, CannotSetToInvalidLogFile) {
  EXPECT_THAT(FileLogSink::New("folder/"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not open file")));
}

TEST(FileLogSinkTest, InfoLogsAreWrittenToFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string entry = "entry";
  LOG(INFO).ToSinkOnly(sink.get()) << entry;
  // Delete the sink to flush all buffered entries.
  sink.reset();

  EXPECT_NE(ReadFile(dest_path.c_str()).find("[I]"), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(entry), std::string::npos);
}

TEST(FileLogSinkTest, ErrorLogsAreWrittenToFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string entry = "entry";
  LOG(ERROR).ToSinkOnly(sink.get()) << entry;
  // Delete the sink to flush all buffered entries.
  sink.reset();

  EXPECT_NE(ReadFile(dest_path.c_str()).find("[E]"), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(entry), std::string::npos);
}

TEST(FileLogSinkTest, WarningLogsAreWrittenToFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string entry = "entry";
  LOG(WARNING).ToSinkOnly(sink.get()) << entry;
  // Delete the sink to flush all buffered entries.
  sink.reset();

  EXPECT_NE(ReadFile(dest_path.c_str()).find("[W]"), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(entry), std::string::npos);
}

TEST(FileLogSinkTest, FatalLogsAreWrittenToFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string entry = "entry";
  EXPECT_DEATH(LOG(FATAL).ToSinkOnly(sink.get()) << entry, _);

  EXPECT_NE(ReadFile(dest_path.c_str()).find("[F]"), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(entry), std::string::npos);
}

TEST(FileLogSinkTest, MultipleEntriesAreWrittenToFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string first_entry = "first entry";
  LOG(INFO).ToSinkOnly(sink.get()) << first_entry;
  std::string second_entry = "second entry";
  LOG(INFO).ToSinkOnly(sink.get()) << second_entry;
  // Delete the sink to flush all buffered entries.
  sink.reset();

  EXPECT_NE(ReadFile(dest_path.c_str()).find(first_entry), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(second_entry), std::string::npos);
}

TEST(FileLogSinkTest, NewLogSinkAppendsToExistingFile) {
  std::string dest_path = "test_simple.log";
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<FileLogSink> sink,
                       FileLogSink::New(dest_path));

  std::string init_entry = "init entry";
  LOG(INFO).ToSinkOnly(sink.get()) << init_entry;

  // Delete the sink to flush all buffered entries.
  sink.reset();
  EXPECT_NE(ReadFile(dest_path.c_str()).find(init_entry), std::string::npos);

  // Create a new sink with the same file destination, write something,
  // and ensure that both the old and the new entry are present.
  ASSERT_OK_AND_ASSIGN(sink, FileLogSink::New(dest_path));

  std::string second_entry = "second entry";
  LOG(INFO).ToSinkOnly(sink.get()) << second_entry;

  // Delete the sink to flush all buffered entries.
  sink.reset();
  EXPECT_NE(ReadFile(dest_path.c_str()).find(second_entry), std::string::npos);
  EXPECT_NE(ReadFile(dest_path.c_str()).find(init_entry), std::string::npos);
}

}  // namespace
}  // namespace cloud_kms

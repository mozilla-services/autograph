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

#ifndef COMMON_TEST_PROTO_PARSER_H_
#define COMMON_TEST_PROTO_PARSER_H_

#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"

namespace cloud_kms {

// A helper for parsing a text format protobuf message, and converting it on
// demand to a desired type. Conversion EXPECT fails if the provided string
// cannot be parsed as the requested type.
class ParseProtoHelper {
 public:
  ParseProtoHelper(std::string text) : text_(text) {}

  template <class T>
  inline operator T() {
    T message;
    EXPECT_TRUE(google::protobuf::TextFormat::ParseFromString(text_, &message))
        << "failure parsing textproto";
    return message;
  }

 private:
  const std::string text_;
};

inline ParseProtoHelper ParseTestProto(std::string text) {
  return ParseProtoHelper(text);
}

}  // namespace cloud_kms

#endif  // COMMON_TEST_PROTO_PARSER_H_

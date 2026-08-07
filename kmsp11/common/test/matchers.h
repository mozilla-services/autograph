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

#ifndef COMMON_TEST_MATCHERS_H_
#define COMMON_TEST_MATCHERS_H_

#include <regex>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "common/status_utils.h"
#include "gmock/gmock.h"
#include "google/protobuf/util/message_differencer.h"

namespace cloud_kms {

// A regex matcher with the same signature as ::testing::MatchesRegex, but whose
// implementation is backed by std::regex.
//
// Unfortunately ::testing::MatchesRegex does not operate consistently across
// platforms:
// https://github.com/google/googletest/blob/master/googletest/docs/advanced.md#regular-expression-syntax
MATCHER_P(MatchesStdRegex, pattern,
          absl::StrFormat("%s regex '%s'",
                          (negation ? "doesn't match" : "matches"),
                          testing::PrintToString(pattern))) {
  return std::regex_match(std::string(arg), std::regex(pattern));
}

// Tests that the supplied status has the expected status code.
MATCHER_P(StatusIs, status_code,
          absl::StrFormat("status is %s%s", (negation ? "not " : ""),
                          testing::PrintToString(status_code))) {
  return ToStatus(arg).code() == status_code;
}

// Tests that the supplied status has the expected status code and has a message
// that matches the supplied message matcher.
MATCHER_P2(
    StatusIs, status_code, message_matcher,
    negation
        ? absl::StrFormat(
              "is a status whose code is not %d or has a message that %s",
              status_code,
              testing::DescribeMatcher<std::string_view>(message_matcher, true))
        : absl::StrFormat(
              "is a status whose code is %d and has a message that %s",
              status_code,
              testing::DescribeMatcher<std::string_view>(message_matcher,
                                                         false))) {
  absl::Status status = ToStatus(arg);
  return status.code() == status_code &&
         testing::ExplainMatchResult(message_matcher, status.message(),
                                     result_listener);
}

// Tests that the supplied status is OK.
MATCHER(IsOk, absl::StrFormat("status is %sOK", negation ? "not " : "")) {
  return ToStatus(arg).ok();
}

// Tests that the supplied protocol buffer message is equal.
MATCHER_P(EqualsProto, proto,
          absl::StrFormat("proto %s", negation ? "does not equal" : "equals")) {
  return google::protobuf::util::MessageDifferencer::Equals(arg, proto);
}

// Tests that the supplied absl::StatusOr is OK and has a value that matches the
// provided matcher.
MATCHER_P(IsOkAndHolds, matcher, "") {
  if (!arg.ok()) {
    return false;
  }
  return testing::ExplainMatchResult(matcher, arg.value(), result_listener);
}

}  // namespace cloud_kms

#endif  // COMMON_TEST_MATCHERS_H_

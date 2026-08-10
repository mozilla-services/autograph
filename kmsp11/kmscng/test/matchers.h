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

#ifndef KMSCNG_TEST_MATCHERS_H_
#define KMSCNG_TEST_MATCHERS_H_

#include <regex>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "common/test/matchers.h"
#include "gmock/gmock.h"
#include "google/protobuf/util/message_differencer.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {

// Tests that the supplied status has the expected SECURITY_STATUS.
MATCHER_P(StatusSsIs, ss_matcher,
          absl::StrCat("status ss matches ",
                       testing::DescribeMatcher<SECURITY_STATUS>(ss_matcher,
                                                                 negation))) {
  return testing::ExplainMatchResult(ss_matcher, GetErrorSs(ToStatus(arg)),
                                     result_listener);
}

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_TEST_MATCHERS_H_

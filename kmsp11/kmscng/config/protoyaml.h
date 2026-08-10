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

#ifndef KMSCNG_CONFIG_PROTOYAML_H_
#define KMSCNG_CONFIG_PROTOYAML_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/message.h"
#include "yaml-cpp/yaml.h"

namespace cloud_kms::kmscng {

// Parse the supplied YAML node into the provided protobuf message. The message
// descriptor of the supplied protobuf message supplies the parsing rules.
//
// The protobuf scalar types string, uint32, and bool are supported. Message
// fields and repeated message fields are also supported.
//
// For example, given these protobuf message descriptors:
//
// message SampleMessage {
//   string string_value = 1;
//   bool bool_value = 2;
//   repeated KeyValue nested_values = 3;
// }
//
// message KeyValue {
//   uint32 key = 1;
//   string value = 2;
// }
//
// We would translate the following YAML file:
//
// bool_value: false
// nested_values:
//   - key: 123
//     value: foo
//   - value: bar
//   - key: 456
//
// Into an equivalent protobuf representation:
//
// bool_value: false
// nested_values {
//   key: 123
//   value: "foo"
// }
// nested_values {
//   value: "bar"
// }
// nested_values {
//   key: 456
// }
//
// Note that all values are always optional.
//
// YAML that is inconsistent with the protobuf descriptor results in an
// InvalidArgument error. Unsupported field types in the protobuf message
// descriptor result in an Internal error.
absl::Status YamlToProto(const YAML::Node& node,
                         google::protobuf::Message* message);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_CONFIG_PROTOYAML_H_

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

#include "kmsp11/config/protoyaml.h"

#include "absl/container/flat_hash_set.h"
#include "common/status_macros.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

using google::protobuf::FieldDescriptor;
using google::protobuf::Message;
using google::protobuf::MessageFactory;
using google::protobuf::Reflection;

absl::Status YamlError(std::string_view message, YAML::Mark mark,
                       SourceLocation source_location) {
  return NewInvalidArgumentError(
      absl::StrFormat("error in YAML document at line %d, column %d: %s",
                      mark.line, mark.column, message),
      CKR_GENERAL_ERROR, source_location);
}

absl::Status SetScalarField(Message* dest, const FieldDescriptor* field,
                            const YAML::Node& value) {
  if (!value.IsScalar()) {
    return YamlError("expected scalar node", value.Mark(), SOURCE_LOCATION);
  }
  std::string string_value = value.Scalar();
  const Reflection* reflect = dest->GetReflection();

  switch (field->type()) {
    case FieldDescriptor::Type::TYPE_STRING:
      reflect->SetString(dest, field, string_value);
      return absl::OkStatus();

    case FieldDescriptor::Type::TYPE_UINT32:
      uint32_t int_value;
      if (!absl::SimpleAtoi(string_value, &int_value)) {
        return YamlError(absl::StrCat("unexpected int value: ", string_value),
                         value.Mark(), SOURCE_LOCATION);
      }
      reflect->SetUInt32(dest, field, int_value);
      return absl::OkStatus();

    case FieldDescriptor::Type::TYPE_BOOL:
      bool bool_value;
      if (!absl::SimpleAtob(string_value, &bool_value)) {
        return YamlError(absl::StrCat("unexpected bool value: ", string_value),
                         value.Mark(), SOURCE_LOCATION);
      }
      reflect->SetBool(dest, field, bool_value);
      return absl::OkStatus();

    default:
      return NewInternalError(
          absl::StrCat("unsupported proto type: ", field->type_name()),
          SOURCE_LOCATION);
  }
}

absl::Status SetRepeatedField(Message* dest, const FieldDescriptor* field,
                              const YAML::Node& value) {
  if (!value.IsSequence()) {
    return YamlError("expected a sequence", value.Mark(), SOURCE_LOCATION);
  }

  switch (field->type()) {
    case FieldDescriptor::TYPE_MESSAGE: {
      // Process all the child messages (and handle any errors) before we make
      // any changes to dest.
      std::vector<std::unique_ptr<Message>> child_messages;
      child_messages.reserve(value.size());
      for (const YAML::Node& child_node : value) {
        child_messages.emplace_back(MessageFactory::generated_factory()
                                        ->GetPrototype(field->message_type())
                                        ->New());
        RETURN_IF_ERROR(YamlToProto(child_node, child_messages.back().get()));
      }

      const Reflection* reflect = dest->GetReflection();
      // Clear the repeated field. This allows overwriting pre-configured
      // default values with values that are actually specified in YAML. (If we
      // didn't clear repeated fields that are specified in YAML, we'd end up
      // with the sum of the template and what's specified in YAML.)
      reflect->ClearField(dest, field);
      for (std::unique_ptr<Message>& m : child_messages) {
        reflect->AddAllocatedMessage(dest, field, m.release());
      }
      return absl::OkStatus();
    }
    case FieldDescriptor::TYPE_STRING: {
      // Process all child nodes (and handle any errors) before we make any
      // changes to dest.
      std::vector<std::string> child_strings;
      child_strings.reserve(value.size());
      for (const YAML::Node& child_node : value) {
        if (!child_node.IsScalar()) {
          return YamlError("expected scalar node", child_node.Mark(),
                           SOURCE_LOCATION);
        }
        child_strings.emplace_back(child_node.Scalar());
      }

      const Reflection* reflect = dest->GetReflection();
      reflect->ClearField(dest, field);
      for (const std::string& s : child_strings) {
        reflect->AddString(dest, field, s);
      }
      return absl::OkStatus();
    }

    default:
      return NewInternalError(
          absl::StrFormat("unsupported proto type: repeated %s",
                          field->type_name()),
          SOURCE_LOCATION);
  }
}

absl::Status SetMessageField(Message* dest, const FieldDescriptor* field,
                             const YAML::Node& value) {
  std::unique_ptr<Message> child_message(
      MessageFactory::generated_factory()
          ->GetPrototype(field->message_type())
          ->New());

  RETURN_IF_ERROR(YamlToProto(value, child_message.get()));
  dest->GetReflection()->SetAllocatedMessage(dest, child_message.release(),
                                             field);
  return absl::OkStatus();
}

absl::Status SetField(Message* dest, const FieldDescriptor* field,
                      const YAML::Node& value) {
  if (field->is_repeated()) {
    return SetRepeatedField(dest, field, value);
  }
  if (field->type() == FieldDescriptor::TYPE_MESSAGE) {
    return SetMessageField(dest, field, value);
  }
  return SetScalarField(dest, field, value);
}

}  // namespace

absl::Status YamlToProto(const YAML::Node& node,
                         google::protobuf::Message* message) {
  if (node.IsNull()) {
    return absl::OkStatus();
  }
  if (!node.IsMap()) {
    return YamlError("expected a YAML map", node.Mark(), SOURCE_LOCATION);
  }

  absl::flat_hash_set<std::string> keys_seen;
  for (auto it = node.begin(); it != node.end(); it++) {
    if (!it->first.IsScalar()) {
      return YamlError("unexpected map key", it->first.Mark(), SOURCE_LOCATION);
    }
    const std::string& key = it->first.Scalar();

    if (keys_seen.contains(key)) {
      return YamlError(
          absl::StrFormat("YAML map key %s is multiply defined", key),
          it->first.Mark(), SOURCE_LOCATION);
    }
    keys_seen.emplace(key);

    const FieldDescriptor* field =
        message->GetDescriptor()->FindFieldByName(key);
    if (!field) {
      return YamlError(
          absl::StrCat("YAML map contains an unrecognized key: ", key),
          it->first.Mark(), SOURCE_LOCATION);
    }

    RETURN_IF_ERROR(SetField(message, field, it->second));
  }
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11

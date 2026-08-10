# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

_BUILD_FILE_CONTENT = """
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "cloudkms_grpc_service_config",
    hdrs = ["cloudkms_grpc_service_config.h"],
    visibility = ["//visibility:public"],
)
"""

_SERVICE_CONFIG_H_TPL_CONTENT = """
#ifndef CLOUDKMS_GRPC_SERVICE_CONFIG_H_
#define CLOUDKMS_GRPC_SERVICE_CONFIG_H_

#include <string_view>

namespace cloud_kms {

constexpr std::string_view kDefaultCloudKmsGrpcServiceConfig = R"({config})";

}  // namespace cloud_kms

#endif  // CLOUDKMS_GRPC_SERVICE_CONFIG_H_
"""

def _cloudkms_grpc_service_config_impl(repo_ctx):
    repo_ctx.file("cloudkms_grpc_service_config.h.tpl", _SERVICE_CONFIG_H_TPL_CONTENT)
    config = repo_ctx.read(repo_ctx.path(Label(
        "@com_google_googleapis//google/cloud/kms/v1:cloudkms_grpc_service_config.json",
    )))
    repo_ctx.template(
        "cloudkms_grpc_service_config.h",
        "cloudkms_grpc_service_config.h.tpl",
        {"{config}": config},
    )
    repo_ctx.file("BUILD.bazel", content = _BUILD_FILE_CONTENT)

cloudkms_grpc_service_config = repository_rule(
    implementation = _cloudkms_grpc_service_config_impl,
)

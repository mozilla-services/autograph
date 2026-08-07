workspace(name = "com_google_kmstools")

# Direct Dependencies
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_archive(
    name = "bazel_gazelle",  # v0.36.0 / 2024-04-03
    sha256 = "75df288c4b31c81eb50f51e2e14f4763cb7548daae126817247064637fd9ea62",
    urls = [
        "https://github.com/bazel-contrib/bazel-gazelle/releases/download/v0.36.0/bazel-gazelle-v0.36.0.tar.gz",
    ],
)

http_archive(
    name = "io_bazel_rules_go",  #v0.46.0 // 2024-02-09
    sha256 = "80a98277ad1311dacd837f9b16db62887702e9f1d1c4c9f796d0121a46c8e184",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
    ],
)

load("boringssl.bzl", "select_crypto_library")

select_crypto_library()

load("//kmscng:cpdk.bzl", "cpdk")

cpdk(name = "cpdk")

http_archive(
    name = "wix",
    build_file_content = """
package(default_visibility = ["//visibility:public"])

filegroup(name = "all", srcs = glob(["**/*"]))
alias(name = "candle", actual = "candle.exe")
alias(name = "light", actual = "light.exe")
    """,
    sha256 = "2c1888d5d1dba377fc7fa14444cf556963747ff9a0a289a3599cf09da03b9e2e",
    url = "https://github.com/wixtoolset/wix3/releases/download/wix3112rtm/wix311-binaries.zip",
)

load("//:build/cloudkms_grpc_service_config.bzl", "cloudkms_grpc_service_config")

cloudkms_grpc_service_config(name = "cloudkms_grpc_service_config")

http_archive(
    name = "com_github_gflags_gflags",  # 2020-03-18
    sha256 = "68e26a487038a842da3ef2ddd1f886dad656e9efaf1a3d49e87d1d3a9fa3a8eb",
    strip_prefix = "gflags-addd749114fab4f24b7ea1e0f2f837584389e52c",
    url = "https://github.com/gflags/gflags/archive/addd749114fab4f24b7ea1e0f2f837584389e52c.tar.gz",
)

http_archive(
    name = "com_github_google_glog",  # v0.7.1 / 2024-06-08
    sha256 = "00e4a87e87b7e7612f519a41e491f16623b12423620006f59f5688bfd8d13b08",
    strip_prefix = "glog-0.7.1",
    url = "https://github.com/google/glog/archive/refs/tags/v0.7.1.tar.gz",
)

http_archive(
    name = "com_github_grpc_grpc",  # v1.59.1 / 2023-10-06
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = [
        "//:third_party/grpc_windows_system_roots.patch",
        "//:third_party/grpc_mac_event_engine.patch",
    ],
    sha256 = "916f88a34f06b56432611aaa8c55befee96d0a7b7d7457733b9deeacbc016f99",
    strip_prefix = "grpc-1.59.1",
    url = "https://github.com/grpc/grpc/archive/v1.59.1.tar.gz",
)

http_archive(
    name = "com_github_jbeder_yaml_cpp",  # v0.7.0 // 2021-07-10
    sha256 = "43e6a9fcb146ad871515f0d0873947e5d497a1c9c60c58cb102a97b47208b7c3",
    strip_prefix = "yaml-cpp-yaml-cpp-0.7.0",
    url = "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.7.0.tar.gz",
)

http_archive(
    name = "com_google_absl",  # 2023-04-03
    sha256 = "ca1428b2593432f56c9a8db6d8e98ae926618d78a64b8bc2f6ebcc8fac49cada",
    strip_prefix = "abseil-cpp-c4127a721f498ad417b4db603e643822305cb11e",
    url = "https://github.com/abseil/abseil-cpp/archive/c4127a721f498ad417b4db603e643822305cb11e.tar.gz",
)

http_archive(
    name = "com_google_googletest",  # 2023-08-02
    sha256 = "8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7",
    strip_prefix = "googletest-1.14.0",
    url = "https://github.com/google/googletest/archive/v1.14.0.tar.gz",
)

http_archive(
    name = "com_google_protobuf",  # v24.4 / 2023-10-03
    sha256 = "616bb3536ac1fff3fb1a141450fa28b875e985712170ea7f1bfe5e5fc41e2cd8",
    strip_prefix = "protobuf-24.4",
    url = "https://github.com/protocolbuffers/protobuf/archive/v24.4.tar.gz",
)

http_archive(
    name = "upb",  # 2023-07-12
    sha256 = "9c91d50bc22e2d78dcf268f3894fef17c2b8e80255ead9752a93ded456891b50",
    strip_prefix = "upb-79af13abde31f5ab8d29931429df70d282a3e867",
    url = "https://github.com/protocolbuffers/upb/archive/79af13abde31f5ab8d29931429df70d282a3e867.tar.gz",
)

http_archive(
    name = "com_google_googleapis",  # 2023-08-08
    # Patch unreleased HSM_SINGLE_TENANT protection level into googleapis.
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/googleapis.patch"],
    sha256 = "bebd8086ab6690bede0d3fa1116b6d549b55e84e4fd25fe3402c19ca87c09263",
    strip_prefix = "googleapis-4a274fa45dec28e84198082dcdb3a9fb7f818b0c",
    url = "https://github.com/googleapis/googleapis/archive/4a274fa45dec28e84198082dcdb3a9fb7f818b0c.zip",
)

http_file(
    name = "pkcs11_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11.h",
    sha256 = "8bb7aa1aeaa328b6a39913070d6f3d2bdeb9f2c92baf27f714fbb4cbefdf4054",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h"],
)

http_file(
    name = "pkcs11f_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11f.h",
    sha256 = "a85adad038bfc9dad9c71377f3ed3b049ba2ac9b3f37198a372f211d210c6057",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h"],
)

http_file(
    name = "pkcs11t_h_v240",  # 2016-05-13
    downloaded_file_path = "pkcs11t.h",
    sha256 = "5b58736b6d23f12b4d9492cd24b06b9d11056c3153afc4e89b1fe564749e71a2",
    urls = ["http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h"],
)

http_archive(
    name = "rules_foreign_cc",  # 2021-03-18
    patch_args = [
        "-E",
        "-p1",
    ],
    patches = ["//:third_party/rules_foreign_cc.patch"],
    sha256 = "776d661daddf614b678abfb36f9624335fbad2d618afbf773759d421bcef49c5",
    strip_prefix = "rules_foreign_cc-d02390f1363cdd2ba5a7f7907a481503d483d569",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/d02390f1363cdd2ba5a7f7907a481503d483d569.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies(register_built_tools = False)

# Transitive Dependencies

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,  # C++ support is only "Partially implemented", roll our own.
    grpc = True,
)

# gRPC

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

load("@build_bazel_rules_apple//apple:repositories.bzl", "apple_rules_dependencies")

apple_rules_dependencies()

load("@build_bazel_apple_support//lib:repositories.bzl", "apple_support_dependencies")

apple_support_dependencies()

# rules_gapic also depends on rules_go, so it must come after our own dependency on rules_go.
_rules_gapic_version = "0.13.0"

_rules_gapic_sha256 = "1ebbd74b064697f4ff01d8f59764ba8431d52673f48f636be6b135b6da640b8e"

http_archive(
    name = "rules_gapic",
    sha256 = _rules_gapic_sha256,
    strip_prefix = "rules_gapic-%s" % _rules_gapic_version,
    urls = ["https://github.com/googleapis/rules_gapic/archive/v%s.tar.gz" % _rules_gapic_version],
)

load("@rules_gapic//:repositories.bzl", "rules_gapic_repositories")

rules_gapic_repositories()

## Java
# Begin: Googleapis Java dependencies
# This section is based off of the WORKSPACE file of googleapis:
# https://github.com/googleapis/googleapis/blob/master/WORKSPACE
load("@com_google_protobuf//:protobuf_deps.bzl", "PROTOBUF_MAVEN_ARTIFACTS")

# Starting in protobuf 3.19, protobuf project started to provide
# PROTOBUF_MAVEN_ARTIFACTS variable so that Bazel users can resolve their
# dependencies through maven_install.
# https://github.com/protocolbuffers/protobuf/issues/9132
RULES_JVM_EXTERNAL_TAG = "4.2"

RULES_JVM_EXTERNAL_SHA = "cd1a77b7b02e8e008439ca76fd34f5b07aecb8c752961f9640dea15e9e5ba1ca"

http_archive(
    name = "rules_jvm_external",
    sha256 = RULES_JVM_EXTERNAL_SHA,
    strip_prefix = "rules_jvm_external-%s" % RULES_JVM_EXTERNAL_TAG,
    url = "https://github.com/bazelbuild/rules_jvm_external/archive/%s.zip" % RULES_JVM_EXTERNAL_TAG,
)

load("@rules_jvm_external//:defs.bzl", "maven_install")

maven_install(
    artifacts = PROTOBUF_MAVEN_ARTIFACTS + ["com.google.cloud:google-cloud-kms:2.27.0"],
    generate_compat_repositories = True,
    repositories = [
        "https://repo.maven.apache.org/maven2/",
    ],
)

# End: Googleapis Java dependencies

## Golang

# Ensure our own repositories are loaded before standard toolchain stuff. Otherwise we can inherit
# versions we do not intend.
load("//:go.bzl", "go_repositories")

# gazelle:repository_macro go.bzl%go_repositories
go_repositories()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

go_register_toolchains("1.22.0")

gazelle_dependencies()

go_rules_dependencies()

## Protobuf
load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

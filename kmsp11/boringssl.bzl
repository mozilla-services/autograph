# Copyright 2021 Google LLC
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

load("@bazel_gazelle//internal:go_repository_cache.bzl", _read_go_env = "read_cache_env")

_BSSL_FIPS_BUILD_FILE_TEMPLATE = """
load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "bssl_sources",
    srcs = glob(["src/**"]),
)

cmake(
    name = "bssl_fips",
    targets = ["crypto", "ssl"],
    lib_source = ":bssl_sources",
    out_include_dir = "",
    out_lib_dir = "",
    out_static_libs = [
        "crypto/libcrypto.a",
        "ssl/libssl.a",
    ],
    install_prefix = ".",
    generate_args = ["-GNinja"],
    cache_entries = {
        "CMAKE_BUILD_TYPE": "Release",
        "FIPS": "1",
        "GO_EXECUTABLE": "$GOROOT/bin/go",
    },
    env = %CMAKE_ENV%,
)

filegroup(
    name = "bssl_fips_gen",
    srcs = [":bssl_fips"],
    output_group = "gen_dir",
)

genrule(
    name = "bssl_fips_static_libs",
    srcs = [":bssl_fips_gen"],
    cmd = "cp $(location bssl_fips_gen)/crypto/libcrypto.a $(@D); " +
          "cp $(location bssl_fips_gen)/ssl/libssl.a $(@D)",
    outs = ["libcrypto.a", "libssl.a"],
)

# This list from https://github.com/google/boringssl/blob/ae223d6138807a13006342edfeef32e813246b39/util/generate_build_files.py#L424
_ssl_headers = [
    "src/include/openssl/ssl.h",
    "src/include/openssl/tls1.h",
    "src/include/openssl/ssl3.h",
    "src/include/openssl/dtls1.h",
    "src/include/openssl/srtp.h",
]

_crypto_headers = glob(
    include = ["src/include/openssl/*.h"],
    exclude = _ssl_headers,
)

cc_library(
    name = "crypto",
    srcs = ["libcrypto.a"],
    hdrs = _crypto_headers,
    strip_include_prefix = "src/include",
    linkstatic = True,
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    srcs = ["libssl.a"],
    hdrs = _ssl_headers,
    deps = [":crypto"],
    strip_include_prefix = "src/include",
    linkstatic = True,
    visibility = ["//visibility:public"],
)
"""

_OPENSSL_BUILD_FILE_CONTENT = """
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "crypto",
    hdrs = glob(["openssl/*.h"]),
    linkopts = ["-lcrypto"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    hdrs = glob(["openssl/*.h"]),
    deps = [":crypto"],
    linkopts = ["-lssl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "openssl_compat",
    hdrs = ["compat/openssl/libcrypto-compat.h"],
    srcs = ["compat/openssl/libcrypto-compat.c"],
    strip_include_prefix = "compat",
    deps = [":crypto"],
    visibility = ["//visibility:public"],
)
"""

def _must_succeed(operation, result):
    if (result.return_code != 0):
        error_msg = (
            "{operation} failed, " +
            "return code {code}, stderr: {err}, stdout: {out}"
        ).format(
            operation = operation,
            code = result.return_code,
            err = result.stderr,
            out = result.stdout,
        )
        fail(error_msg)

def _crypto_library_impl(repo_ctx):
    library = repo_ctx.os.environ.get("KMSP11_CRYPTO_LIBRARY", default = "boringssl")
    if library not in ["boringssl", "boringssl_fips", "openssl"]:
        fail("KMSP11_CRYPTO_LIBRARY='%s' is not supported" % (library))

    if library == "boringssl":
        repo_ctx.download_and_extract(
            # 2023-09-12
            url = "https://github.com/google/boringssl/archive/48a16fed0bf57f3d04f856a17490b5935458eb99.tar.gz",
            sha256 = "5e475b54e1f7a7536c66fb777aeac97943d032b46bbff4c646dfcd337828ff87",
            stripPrefix = "boringssl-48a16fed0bf57f3d04f856a17490b5935458eb99",
        )
        return

    if library == "openssl":
        include_dir = repo_ctx.os.environ.get(
            "OPENSSL_INCLUDE_DIR",
            default = "/usr/include/openssl",
        )
        repo_ctx.symlink(include_dir, "openssl")

        # See https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Backward_compatibility
        repo_ctx.download_and_extract(
            url = "https://wiki.openssl.org/images/e/ed/Openssl-compat.tar.gz",
            sha256 = "2d75ffb10b2e3138a9c4e3c130fede955c5b8e326e6a860b718a99e41df58abb",
            output = "compat/openssl",
        )
        repo_ctx.patch(Label("//:third_party/openssl_compat.patch"))

        repo_ctx.file(
            "BUILD",
            content = _OPENSSL_BUILD_FILE_CONTENT,
        )
        return

    # Proceeding to set up BoringSSL + FIPS config

    # 853ca1ea1168dff08011e5d42d94609cc0ca2e27 is the latest FIPS-validated version.
    # https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4407
    repo_ctx.download_and_extract(
        url = "https://github.com/google/boringssl/archive/853ca1ea1168dff08011e5d42d94609cc0ca2e27.tar.gz",
        stripPrefix = "boringssl-853ca1ea1168dff08011e5d42d94609cc0ca2e27",
        sha256 = "61e85d6eaecf1706be0420a9104b66ff01bd04301b5fad323970685f942108ed",
        output = "src",
    )

    fips_patches = [
        # Specific to our builds. Needed to ensure that symbols are exposed
        # transitively within the Bazel ecosystem.
        Label("//:third_party/bssl_visibility.patch"),
    ]

    for patch in fips_patches:
        _must_succeed(
            "patch for bssl fips",
            repo_ctx.execute([
                "patch",
                "-d",
                "src",
                "-i",
                repo_ctx.path(patch),
                "-E",
                "-p1",
            ]),
        )

    repo_ctx.file(
        "BUILD.tmpl",
        content = _BSSL_FIPS_BUILD_FILE_TEMPLATE,
        executable = False,
    )

    go_env = _read_go_env(repo_ctx, str(repo_ctx.path(repo_ctx.attr._go_cache)))

    build_env = {
        "GOROOT": go_env["GOROOT"],
        "GOPATH": go_env["GOPATH"],
        "GOCACHE": "$BUILD_TMPDIR/cache",
        "SYSTEM_NAME": repo_ctx.os.name,
    }

    # Download dependencies from go.mod
    _must_succeed("go get", repo_ctx.execute(
        [go_env["GOROOT"] + "/bin/go", "get", "-u", "..."],
        working_directory = "src",
        environment = build_env,
    ))

    repo_ctx.template(
        "BUILD",
        "BUILD.tmpl",
        substitutions = {
            "%CMAKE_ENV%": str(build_env),
        },
        executable = False,
    )

crypto_library = repository_rule(
    implementation = _crypto_library_impl,
    attrs = {
        "_go_cache": attr.label(
            default = Label("@bazel_gazelle_go_repository_cache//:go.env"),
            allow_single_file = True,
        ),
    },
    environ = [
        "KMSP11_CRYPTO_LIBRARY",
        "OPENSSL_INCLUDE_DIR",
    ],
)

def select_crypto_library():
    if native.existing_rule("boringssl"):
        return

    # Our crypto repository will always be named 'boringssl' so that our
    # gRPC stack uses it as well.
    crypto_library(name = "boringssl")

_CPDK_BUILD_FILE_CONTENT = """
load("@rules_cc//cc:defs.bzl", "cc_library")

cc_import(
    name = "bcrypt_provider",
    hdrs = ["bcrypt_provider.h"],
    static_library = "lib/bcrypt_provider.lib",
    visibility = ["//visibility:public"],
)

cc_import(
    name = "ncrypt_provider",
    hdrs = ["ncrypt_provider.h"],
    static_library = "lib/ncrypt_provider.lib",
    visibility = ["//visibility:public"],
)
"""

def _cpdk_impl(repo_ctx):
    location = repo_ctx.os.environ.get(
        "CPDK_LOCATION",
        default = "C:\\Program Files (x86)\\Windows Kits\\10\\Cryptographic Provider Development Kit",
    )
    if not repo_ctx.path(location).exists:
        fail("Could not find Cryptographic Provider Development Kit at %s", location)
    repo_ctx.symlink(location + "\\Include\\bcrypt_provider.h", "bcrypt_provider.h")
    repo_ctx.symlink(location + "\\Include\\ncrypt_provider.h", "ncrypt_provider.h")
    repo_ctx.symlink(location + "\\Lib\\x64", "lib")
    repo_ctx.file(
        "BUILD.bazel",
        content = _CPDK_BUILD_FILE_CONTENT,
    )

cpdk = repository_rule(
    implementation = _cpdk_impl,
    environ = ["CPDK_LOCATION"],
)

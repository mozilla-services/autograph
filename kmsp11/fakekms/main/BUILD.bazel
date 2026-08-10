load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "fakekms",
    srcs = ["main.go"],
    importpath = "oss-tools/fakekms/main",
    visibility = ["//visibility:public"],
    deps = ["//fakekms"],
)

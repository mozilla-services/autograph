# Building

The project is built using the [Bazel](https://bazel.build) build tool, version
6.4.0. Bazelisk is the recommended way to install Bazel on
Ubuntu, Windows, and macOS. It automatically downloads and installs the
appropriate version of Bazel, based on the .bazelversion file in this project.
See https://bazel.build/install/bazelisk for additional information.

All targets can be built and tested by invoking `bazelisk test ...` at the
command line (or `bazel test ...` if you are not using `bazelisk`).

The project's dependencies will be downloaded and built automatically during the
build process.

## Tested Platforms

The project is built and tested by Google on the following platforms.

### Linux

* Operating System: Linux 2.6+
* Architecture: amd64
* Compiler: clang 9.0+
* C Standard Library: glibc 2.17+
* C++ Standard Library: libc++

### FreeBSD

* Operating System: FreeBSD 13
* Architecture: amd64, i386
* Compiler: clang 15.0+
* C++ Standard Library: libc++
* Bazel: 6.2.0 (replacing the contents of .bazelversion in the root of the
  repository prior to building)

### macOS

* Operating System: macOS 11+
* Architecture: amd64
* Compiler: Apple Clang (Xcode 12)

### Windows

* Operating System: Windows 8.1+ or Windows Server 2012 R2+
* Architecture: amd64
* Compiler: MSVC 2022

## Configuration Options

The following options are available if required in your environment.

### BoringSSL FIPS mode support

The PKCS #11 library may be built with the FIPS-validated version of BoringSSL.
This build mode is not recommended, but may be necessary in certain regulated
environments. Building in this mode is only supported on Linux and FreeBSD, with
the amd64 architecture.

You may specify building in this mode using the `--config fips` option at the
Bazel command line. For example:

```sh
bazel build --config fips //kmsp11/main:libkmsp11.so
```

### OpenSSL support

The PKCS #11 library may be built using OpenSSL instead of BoringSSL. This mode
is not recommended, but may be necessary in certain regulated environments.
Building in this mode is only supported on Linux and FreeBSD.

You may specify building in this mode using the `--config openssl` option at the
Bazel command line. For example:

```sh
bazel build --config openssl //kmsp11/main:libkmsp11.so
```

### Building 32-bit binaries on 64-bit build systems

32-bit binaries can be built on 64-bit Linux and FreeBSD systems. Not all tests
can run in this configuration.

You may specify building in this mode using the `--config m32` option at the
Bazel command line. For example:

```sh
bazel test --config m32 ...
```

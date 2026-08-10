#!/bin/bash
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


# Fail on any error.
set -e

# Code under repo is checked out to ${KOKORO_ARTIFACTS_DIR}/git.
# The final directory name in this path is determined by the scm name specified
# in the job configuration.
export PROJECT_ROOT="${KOKORO_ARTIFACTS_DIR}/git/oss-tools"
cd "${PROJECT_ROOT}"

export RESULTS_DIR="${KOKORO_ARTIFACTS_DIR}/results"
mkdir "${RESULTS_DIR}"

sudo apt-get update
sudo apt-get install -y libc++abi-dev

# Pull in a more recent LLVM toolchain
export LLVM_VERSION=10.0.1
export LLVM_DIST="clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-16.04"
export LLVM_ROOT=/opt/${LLVM_DIST}
sudo tar xf "${KOKORO_GFILE_DIR}/${LLVM_DIST}.tar.xz" -C /opt

# Get Go and Bazelisk
sudo tar xf "${KOKORO_GFILE_DIR}/go1.22.0.linux-amd64.tar.gz" -C /opt
export GOROOT=/opt/go
export GOPATH=${KOKORO_ARTIFACTS_DIR}/gopath
${GOROOT}/bin/go install github.com/bazelbuild/bazelisk@v1.25.0
shopt -s expand_aliases
alias bazelisk=${GOPATH}/bin/bazelisk

# Unwrap our wrapped service account key
export GOOGLE_APPLICATION_CREDENTIALS=${KOKORO_ARTIFACTS_DIR}/oss-tools-ci-key.json
${GOROOT}/bin/go run ./.kokoro/unwrap_key.go \
  -wrapping_key_file=${KOKORO_KEYSTORE_DIR}/75220_token-wrapping-key \
  -wrapped_key_file=${KOKORO_GFILE_DIR}/oss-tools-ci-key.json.enc \
  > ${GOOGLE_APPLICATION_CREDENTIALS}

# Configure user.bazelrc with remote build caching options and Google creds
cp .kokoro/remote_cache.bazelrc user.bazelrc
echo "build --remote_default_exec_properties=cache-silo-key=${KOKORO_JOB_NAME}" \
  >> user.bazelrc
echo "test --test_env=GOOGLE_APPLICATION_CREDENTIALS" >> user.bazelrc

# Ensure that coverage outputs and test logs are uploaded even on failure
_upload_artifacts() {
  if [ -e "${PROJECT_ROOT}/bazel-out/_coverage/_coverage_report.dat" ]; then
    cp "${PROJECT_ROOT}/bazel-out/_coverage/_coverage_report.dat" ${RESULTS_DIR}
  fi

  python3 "${PROJECT_ROOT}/.kokoro/copy_test_outputs.py" \
    "${PROJECT_ROOT}/bazel-testlogs" "${RESULTS_DIR}/testlogs"
}
trap _upload_artifacts EXIT

# See b/161127142#comment5
export CC=${LLVM_ROOT}/bin/clang
export BAZEL_CXXOPTS=-stdlib=libc++
export BAZEL_LINKLIBS=-nostdlib++:-L${LLVM_ROOT}/lib:-lc++:-lc++abi:-Wl,-rpath=${LLVM_ROOT}/lib
export BAZEL_USE_LLVM_NATIVE_COVERAGE=1
export BAZEL_LLVM_COV=${LLVM_ROOT}/bin/llvm-cov
export GCOV=${LLVM_ROOT}/bin/llvm-profdata

# Ensure Bazel version information is included in the build log
bazelisk version

bazelisk coverage \
  --combined_report=lcov \
  --coverage_report_generator=@bazel_tools//tools/test/CoverageOutputGenerator/java/com/google/devtools/coverageoutputgenerator:Main \
  --experimental_generate_llvm_lcov \
  --instrument_test_targets \
  --nocache_test_results \
  ...

mkdir ${RESULTS_DIR}/coverage
genhtml -o ${RESULTS_DIR}/coverage bazel-out/_coverage/_coverage_report.dat
cd ${RESULTS_DIR}
tar czf coverage.tar.gz coverage/

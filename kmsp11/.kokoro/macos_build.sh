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

# Display commands being run.
# WARNING: please only enable 'set -x' if necessary for debugging, and be very
#  careful if you handle credentials (e.g. from Keystore) with 'set -x':
#  statements like "export VAR=$(cat /tmp/keystore/credentials)" will result in
#  the credentials being printed in build logs.
#  Additionally, recursive invocation with credentials as command-line
#  parameters, will print the full command, with credentials, in the build logs.
# set -x

# Code under repo is checked out to ${KOKORO_ARTIFACTS_DIR}/git.
# The final directory name in this path is determined by the scm name specified
# in the job configuration.
export PROJECT_ROOT="${KOKORO_ARTIFACTS_DIR}/git/oss-tools"
cd "${PROJECT_ROOT}"

export RESULTS_DIR="${KOKORO_ARTIFACTS_DIR}/results"
mkdir "${RESULTS_DIR}"

# Unwrap our wrapped service account key
export GOOGLE_APPLICATION_CREDENTIALS=${KOKORO_ARTIFACTS_DIR}/oss-tools-ci-key.json
go run ./.kokoro/unwrap_key.go \
  -wrapping_key_file=${KOKORO_KEYSTORE_DIR}/75220_token-wrapping-key \
  -wrapped_key_file=${KOKORO_GFILE_DIR}/oss-tools-ci-key.json.enc \
  > ${GOOGLE_APPLICATION_CREDENTIALS}

# Configure user.bazelrc with remote build caching options
cp .kokoro/remote_cache.bazelrc user.bazelrc
echo "build --remote_default_exec_properties=cache-silo-key=${KOKORO_JOB_NAME}" \
  >> user.bazelrc
echo "test --test_env=GOOGLE_APPLICATION_CREDENTIALS" >> user.bazelrc

# Ensure that bazel is shut down, and build outputs and test logs
# are uploaded even on failure.
_finish() {
  set +e

  # Explicit shutdown seems to be needed on Catalina and later or the
  # build hangs; see b/196832502.
  bazelisk shutdown

  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" \
      "${RESULTS_DIR}/libkmsp11.dylib"
  fi
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" \
      "${RESULTS_DIR}/libkmsp11_e2e_test"
  fi

  cp "${PROJECT_ROOT}/LICENSE" "${RESULTS_DIR}"

  python3 "${PROJECT_ROOT}/.kokoro/copy_test_outputs.py" \
    "${PROJECT_ROOT}/bazel-testlogs" "${RESULTS_DIR}/testlogs"
}
trap _finish EXIT

# Use Developer Tools for macOS 13.0, from Kokoro configuration.
sudo xcode-select -s /Applications/Xcode_15.1.app

# Ensure Bazel version information is included in the build log
bazelisk version

export BAZEL_ARGS="-c opt --keep_going ${BAZEL_EXTRA_ARGS}"

bazelisk test ${BAZEL_ARGS} ... :ci_only_tests

bazelisk run ${BAZEL_ARGS} //kmsp11/tools/buildsigner -- \
  -signing_key=${BUILD_SIGNING_KEY} \
  < bazel-bin/kmsp11/main/libkmsp11.so \
  > ${RESULTS_DIR}/libkmsp11.dylib.sig

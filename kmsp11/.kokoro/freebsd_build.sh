#!/usr/local/bin/bash
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

# Install package dependencies. Stored in GCS since FreeBSD aggressively
# turns down package repositories when a distribution hits end of life.
tar zxvf ${KOKORO_GFILE_DIR}/freebsd13-amd64-packages.tar.gz -C ${KOKORO_ARTIFACTS_DIR}
pushd ${KOKORO_ARTIFACTS_DIR}/freebsd13-amd64-packages
sudo pkg add bazel-6.2.0.pkg
#  Required for BoringSSL FIPS builds.
sudo pkg add cmake-core-3.26.1_3.pkg
sudo pkg add ninja-1.11.1,2.pkg
popd

# Configure user.bazelrc with remote build caching options
cp .kokoro/remote_cache.bazelrc user.bazelrc
echo "build --remote_default_exec_properties=cache-silo-key=${KOKORO_JOB_NAME}" \
  >> user.bazelrc

# Ensure that build outputs and test logs are uploaded even on failure
_upload_artifacts() {
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/main/libkmsp11.so" \
      "${RESULTS_DIR}/libkmsp11.so"
  fi
  if [ -e "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" ]; then
    cp "${PROJECT_ROOT}/bazel-bin/kmsp11/test/e2e/e2e_test" \
      "${RESULTS_DIR}/libkmsp11_e2e_test"
  fi

  cp "${PROJECT_ROOT}/LICENSE" "${RESULTS_DIR}"

  python3 "${PROJECT_ROOT}/.kokoro/copy_test_outputs.py" \
    "${PROJECT_ROOT}/bazel-testlogs" "${RESULTS_DIR}/testlogs"
}
trap _upload_artifacts EXIT

# This is a temporary hack to work around the fact that we don't
# have the latest Bazel on FreeBSD.
echo '6.2.0' > .bazelversion

# Ensure Bazel version information is included in the build log
bazel version

export BAZEL_ARGS="-c opt --keep_going ${BAZEL_EXTRA_ARGS}"

bazel test ${BAZEL_ARGS} ... :ci_only_tests

bazel run ${BAZEL_ARGS} //kmsp11/tools/buildsigner -- \
  -signing_key=${BUILD_SIGNING_KEY} \
  < bazel-bin/kmsp11/main/libkmsp11.so \
  > ${RESULTS_DIR}/libkmsp11.so.sig

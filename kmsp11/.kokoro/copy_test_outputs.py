#!/usr/bin/env python3
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


import os
import shutil
import sys


def copy_test_outputs(src_root: str, dest_root: str):
    """Prepares bazel test outputs from src_root into files at dest_root.

    The file patterns are converted into a format that is acceptable to Cloud
    Build ResultStore.

    See go/kokoro/userdocs/general/custom_test_logs.md#converting-bazel-test-logs-to-spongeresultstore-test-logs
    """
    for src_dir, _, files in os.walk(src_root, followlinks=True):
        dest_dir = os.path.join(
            dest_root, os.path.relpath(src_dir, src_root))
        for file_name in files:
            if file_name == 'test.log':
                os.makedirs(dest_dir, exist_ok=True)
                shutil.copyfile(os.path.join(src_dir, 'test.log'),
                                os.path.join(dest_dir, 'sponge_log.log'))
            if file_name == 'test.xml':
                os.makedirs(dest_dir, exist_ok=True)
                shutil.copyfile(os.path.join(src_dir, 'test.xml'),
                                os.path.join(dest_dir, 'sponge_log.xml'))


if __name__ == "__main__":
    copy_test_outputs(sys.argv[1], sys.argv[2])

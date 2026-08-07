// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <jni.h>

#include "common/test/test_platform.h"

extern "C" {

JNIEXPORT void JNICALL Java_kmsp11_test_jca_Environment_setenv(JNIEnv* env,
                                                               jclass cl,
                                                               jstring name,
                                                               jstring value) {
  const char* name_chars = env->GetStringUTFChars(name, nullptr);
  const char* value_chars = env->GetStringUTFChars(value, nullptr);
  cloud_kms::SetEnvVariable(name_chars, value_chars);
  env->ReleaseStringUTFChars(name, name_chars);
  env->ReleaseStringUTFChars(value, value_chars);
}

JNIEXPORT void JNICALL Java_kmsp11_test_jca_Environment_unsetenv(JNIEnv* env,
                                                                 jclass cl,
                                                                 jstring name) {
  const char* name_chars = env->GetStringUTFChars(name, nullptr);
  cloud_kms::ClearEnvVariable(name_chars);
  env->ReleaseStringUTFChars(name, name_chars);
}
}

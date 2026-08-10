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

package com.google.cloud.kms.pkcs11.fakekms;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRing;
import org.junit.Assert;
import org.junit.Test;

public class FakeKmsTest {

  @Test
  public void smokeTest() throws Exception {
    try (FakeKms fake = new FakeKms()) {
      try (KeyManagementServiceClient client = fake.newClient()) {
        KeyRing kr =
            client.createKeyRing(
                "projects/foo/locations/global", "my-key-ring", KeyRing.getDefaultInstance());
        Assert.assertEquals(kr.getName(), "projects/foo/locations/global/keyRings/my-key-ring");
      }
    }
  }
}

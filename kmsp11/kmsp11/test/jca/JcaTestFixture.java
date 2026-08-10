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

package kmsp11.test.jca;

import com.google.cloud.kms.pkcs11.fakekms.FakeKms;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyRing;
import com.google.devtools.build.runfiles.Runfiles;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Provider;
import java.security.Security;
import java.util.UUID;

/**
 * JcaTestFixture contains helpers to create a Fake KMS, key ring, and PKCS 11 provider for use in
 * JCA integration tests.
 */
public class JcaTestFixture implements AutoCloseable {
  private static final String CONFIG_ENV_VARIABLE = "KMS_PKCS11_CONFIG";
  private static final String SHARED_LIB_PATH = "com_google_kmstools/kmsp11/main/libkmsp11.so";
  private static final String TEST_LOCATION = "projects/kmsp11-test/locations/us-central1";

  private static Runfiles runfiles;

  static {
    try {
      runfiles = Runfiles.create();
    } catch (IOException e) {
      throw new IllegalStateException("error loading runfiles", e);
    }
  }

  private final FakeKms fakeKms;
  private final KeyManagementServiceClient client;
  private final KeyRing keyRing;

  /** Create a new fixture with a listening fake KMS server. */
  public JcaTestFixture() throws IOException {
    fakeKms = new FakeKms();
    client = fakeKms.newClient();

    String keyRingId = "test-keyring-" + UUID.randomUUID().toString();
    keyRing = client.createKeyRing(TEST_LOCATION, keyRingId, KeyRing.getDefaultInstance());

    File configFile = File.createTempFile("config", ".yaml");
    configFile.deleteOnExit();
    try (FileWriter w = new FileWriter(configFile)) {
      w.write(newLibraryConfig(fakeKms.getServerAddress(), keyRing.getName()));
    }

    Environment.set(CONFIG_ENV_VARIABLE, configFile.getAbsolutePath());
  }

  /** Get a client for the fake KMS server. */
  public KeyManagementServiceClient getClient() {
    return client;
  }

  /** Get the KeyRing associated with this fixture. */
  public KeyRing getKeyRing() {
    return keyRing;
  }

  /** Create a new SunPKCS11 provider that points to our PKCS11 library. */
  public Provider newProvider() throws IOException {
    Provider p = Security.getProvider("SunPKCS11");
    return p.configure(newProviderConfig());
  }

  /** Release the resources associated with this test fixture. */
  @Override
  public void close() {
    Environment.unset(CONFIG_ENV_VARIABLE);
    client.close();
    fakeKms.close();
  }

  private static String newLibraryConfig(String kmsEndpoint, String keyRingName) {
    StringBuilder s = new StringBuilder();
    s.append("---");
    s.append(System.lineSeparator());

    s.append("tokens:");
    s.append(System.lineSeparator());

    s.append("  - key_ring: ");
    s.append('"');
    s.append(keyRingName);
    s.append('"');
    s.append(System.lineSeparator());

    s.append("kms_endpoint: ");
    s.append('"');
    s.append(kmsEndpoint);
    s.append('"');
    s.append(System.lineSeparator());

    s.append("use_insecure_grpc_channel_credentials: true");
    s.append(System.lineSeparator());

    s.append("generate_certs: true");
    s.append(System.lineSeparator());

    return s.toString();
  }

  private static String newProviderConfig() throws IOException {
    StringBuilder s = new StringBuilder();
    s.append("--");
    s.append(System.lineSeparator());

    s.append("name = libkmsp11-");
    s.append(UUID.randomUUID().toString());
    s.append(System.lineSeparator());

    // The SunPKCS11 provider caches loads of the same .so file. In order to change
    // the library config within a single Java process, we need to make a copy.
    File libraryCopy = File.createTempFile("libkmsp11", ".so");
    libraryCopy.deleteOnExit();
    Files.copy(
        Paths.get(runfiles.rlocation(SHARED_LIB_PATH)),
        libraryCopy.toPath(),
        StandardCopyOption.REPLACE_EXISTING);

    s.append("library = ");
    s.append(libraryCopy.getAbsolutePath());
    s.append(System.lineSeparator());

    return s.toString();
  }
}

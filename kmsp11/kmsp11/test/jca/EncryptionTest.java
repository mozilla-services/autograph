// Copyright 2022 Google LLC
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

import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class EncryptionTest {
  private JcaTestFixture f;

  @Before
  public void setup() throws IOException {
    f = new JcaTestFixture();
  }

  @After
  public void tearDown() {
    f.close();
  }

  @Test
  public void testAes128CbcEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-128-cbc-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_128_CBC */ 42);

    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/NoPadding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/NoPadding");
    encryptDecrypt(cryptoKeyId, "AES/CBC/NoPadding");
    // Java treats PKCS#5 as PKCS#7 internally, it's a misnaming that ignores the fact that PKCS#5
    // should be limited to 8-byte blocks, so we use */PKCS5Padding here.
    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/PKCS5Padding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/PKCS5Padding");
    encryptDecrypt(cryptoKeyId, "AES/CBC/PKCS5Padding");
  }

  @Test
  public void testAes256CbcEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-256-cbc-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_256_CBC */ 43);

    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/NoPadding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/NoPadding");
    encryptDecrypt(cryptoKeyId, "AES/CBC/NoPadding");
    // Java treats PKCS#5 as PKCS#7 internally, it's a misnaming that ignores the fact that PKCS#5
    // should be limited to 8-byte blocks, so we use */PKCS5Padding here.
    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/PKCS5Padding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CBC/PKCS5Padding");
    encryptDecrypt(cryptoKeyId, "AES/CBC/PKCS5Padding");
  }

  @Test
  public void testAes128CtrEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-128-ctr-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_128_CTR */ 44);

    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    encryptDecrypt(cryptoKeyId, "AES/CTR/NoPadding");
  }

  @Test
  public void testAes256CtrEncryptDecrypt() throws Exception {
    String cryptoKeyId = "aes-256-ctr-key";
    // TODO(b/234842124): use real enum values once the KMS proto changes are public.
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, /* RAW_ENCRYPT_DECRYPT */ 7,
        /* AES_256_CTR */ 45);

    encryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    decryptMatchesExpected(cryptoKeyId, ckv.getName(), "AES/CTR/NoPadding");
    encryptDecrypt(cryptoKeyId, "AES/CTR/NoPadding");
  }

  private void encryptDecrypt(String keyLabel, String jcaAlgorithm) throws Exception {
    byte[] data;
    if (jcaAlgorithm.contains("NoPadding")) {
      data = "Here is my data to be encrypted.".getBytes(StandardCharsets.UTF_8);
    } else {
      data = "Here is some data that needs padding.".getBytes(StandardCharsets.UTF_8);
    }
    byte[] iv = "my_custom_iv_123".getBytes(StandardCharsets.UTF_8);
    IvParameterSpec spec = new IvParameterSpec(iv);

    Provider provider = f.newProvider();
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);

    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;
    Assert.assertTrue(sk.getSecretKey() != null);
    Assert.assertTrue(sk.getSecretKey().getFormat() == null);
    Assert.assertTrue(sk.getSecretKey().getEncoded() == null);
    Assert.assertTrue(sk.getSecretKey().getAlgorithm() == "AES");

    Cipher cipher = Cipher.getInstance(jcaAlgorithm, provider);
    cipher.init(Cipher.ENCRYPT_MODE, sk.getSecretKey(), spec);
    byte[] ciphertext = cipher.doFinal(data);

    cipher.init(Cipher.DECRYPT_MODE, sk.getSecretKey(), spec);
    byte[] recoveredPlaintext = cipher.doFinal(ciphertext);

    Assert.assertTrue(Arrays.equals(recoveredPlaintext, data));
  }

  private void encryptMatchesExpected(String keyLabel, String versionName, String jcaAlgorithm)
      throws Exception {
    byte[] data, paddedData;
    if (jcaAlgorithm.contains("NoPadding")) {
      data = "Here is my data to be encrypted.".getBytes(StandardCharsets.UTF_8);
      paddedData = data;
    } else {
      data = "Here is my data with padding".getBytes(StandardCharsets.UTF_8);
      paddedData =
          "Here is my data with padding\u0004\u0004\u0004\u0004".getBytes(StandardCharsets.UTF_8);
    }
    byte[] iv = "my_custom_iv_123".getBytes(StandardCharsets.UTF_8);

    // Encrypt using KMS directly (RawEncrypt).
    RawEncryptRequest encryptReq = RawEncryptRequest.newBuilder()
                                       .setName(versionName)
                                       .setPlaintext(ByteString.copyFrom(paddedData))
                                       .setInitializationVector(ByteString.copyFrom(iv))
                                       .build();

    RawEncryptResponse encryptResp = f.getClient().rawEncrypt(encryptReq);
    byte[] responseIv = encryptResp.getInitializationVector().toByteArray();
    Assert.assertTrue(Arrays.equals(responseIv, iv));
    byte[] expected_ciphertext = encryptResp.getCiphertext().toByteArray();

    Provider provider = f.newProvider();
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);

    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;
    Assert.assertTrue(sk.getSecretKey() != null);
    Assert.assertTrue(sk.getSecretKey().getFormat() == null);
    Assert.assertTrue(sk.getSecretKey().getEncoded() == null);
    Assert.assertTrue(sk.getSecretKey().getAlgorithm() == "AES");

    Cipher cipher = Cipher.getInstance(jcaAlgorithm, provider);
    IvParameterSpec spec = new IvParameterSpec(responseIv);
    cipher.init(Cipher.ENCRYPT_MODE, sk.getSecretKey(), spec);
    byte[] ciphertext = cipher.doFinal(data);

    Assert.assertTrue(Arrays.equals(ciphertext, expected_ciphertext));
  }

  private void decryptMatchesExpected(String keyLabel, String versionName, String jcaAlgorithm)
      throws Exception {
    byte[] data, paddedData;
    if (jcaAlgorithm.contains("NoPadding")) {
      paddedData = "Here is my data to be encrypted.".getBytes(StandardCharsets.UTF_8);
      data = paddedData;
    } else {
      paddedData =
          "Here is my data with padding\u0004\u0004\u0004\u0004".getBytes(StandardCharsets.UTF_8);
      data = "Here is my data with padding".getBytes(StandardCharsets.UTF_8);
    }
    byte[] iv = "my_custom_iv_123".getBytes(StandardCharsets.UTF_8);

    // Encrypt using KMS directly (RawEncrypt).
    RawEncryptRequest encryptReq = RawEncryptRequest.newBuilder()
                                       .setName(versionName)
                                       .setPlaintext(ByteString.copyFrom(paddedData))
                                       .setInitializationVector(ByteString.copyFrom(iv))
                                       .build();

    RawEncryptResponse encryptResp = f.getClient().rawEncrypt(encryptReq);
    byte[] responseIv = encryptResp.getInitializationVector().toByteArray();
    Assert.assertTrue(Arrays.equals(responseIv, iv));
    byte[] ciphertext = encryptResp.getCiphertext().toByteArray();

    Provider provider = f.newProvider();
    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);

    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;
    Assert.assertTrue(sk.getSecretKey() != null);
    Assert.assertTrue(sk.getSecretKey().getFormat() == null);
    Assert.assertTrue(sk.getSecretKey().getEncoded() == null);
    Assert.assertTrue(sk.getSecretKey().getAlgorithm() == "AES");

    Cipher cipher = Cipher.getInstance(jcaAlgorithm, provider);
    IvParameterSpec spec = new IvParameterSpec(responseIv);
    cipher.init(Cipher.DECRYPT_MODE, sk.getSecretKey(), spec);
    byte[] plaintext = cipher.doFinal(ciphertext);

    Assert.assertTrue(Arrays.equals(plaintext, data));
  }

  private CryptoKeyVersion createCkv(String cryptoKeyId, CryptoKey.CryptoKeyPurpose purpose,
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) throws Exception {
    return createCkv(cryptoKeyId, purpose.getNumber(), algorithm.getNumber());
  }

  // TODO(b/234842124): drop overload once the KMS proto changes are public.
  private CryptoKeyVersion createCkv(String cryptoKeyId, int purposeID, int algorithmID)
      throws Exception {
    CreateCryptoKeyRequest ckReq =
        CreateCryptoKeyRequest.newBuilder()
            .setParent(f.getKeyRing().getName())
            .setCryptoKeyId(cryptoKeyId)
            .setCryptoKey(CryptoKey.newBuilder().setPurposeValue(purposeID).setVersionTemplate(
                CryptoKeyVersionTemplate.newBuilder()
                    .setAlgorithmValue(algorithmID)
                    .setProtectionLevel(ProtectionLevel.HSM)))
            .setSkipInitialVersionCreation(true)
            .build();

    CryptoKey ck = f.getClient().createCryptoKey(ckReq);
    CryptoKeyVersion ckv =
        f.getClient().createCryptoKeyVersion(ck.getName(), CryptoKeyVersion.getDefaultInstance());

    while (ckv.getState() != CryptoKeyVersion.CryptoKeyVersionState.ENABLED) {
      Thread.sleep(1 /* millisecond */);
      ckv = f.getClient().getCryptoKeyVersion(ckv.getName());
    }

    return ckv;
  }
}

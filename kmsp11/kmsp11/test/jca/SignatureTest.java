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

import com.google.cloud.kms.v1.*;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Signature;
import javax.crypto.Mac;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SignatureTest {

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
  public void testEcP256SignVerify() throws Exception {
    String cryptoKeyId = "ec-p256-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256);

    signAndVerify(cryptoKeyId, "SHA256withECDSA");
  }

  @Test
  public void testEcP384SignVerify() throws Exception {
    String cryptoKeyId = "ec-p384-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384);

    signAndVerify(cryptoKeyId, "SHA384withECDSA");
  }

  @Test
  public void testRsa2048Pkcs1Sha256SignVerify() throws Exception {
    String cryptoKeyId = "rsa-pkcs1-2048-sha256-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256);

    signAndVerify(cryptoKeyId, "SHA256withRSA");
  }

  @Test
  public void testRsa3072Pkcs1Sha256SignVerify() throws Exception {
    String cryptoKeyId = "rsa-pkcs1-3072-sha256-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256);

    signAndVerify(cryptoKeyId, "SHA256withRSA");
  }

  @Test
  public void testRsa4096Pkcs1Sha256SignVerify() throws Exception {
    String cryptoKeyId = "rsa-pkcs1-4096-sha256-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256);

    signAndVerify(cryptoKeyId, "SHA256withRSA");
  }

  @Test
  public void testRsa4096Pkcs1Sha512SignVerify() throws Exception {
    String cryptoKeyId = "rsa-pkcs1-4096-sha512-key";
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512);

    signAndVerify(cryptoKeyId, "SHA512withRSA");
  }

  @Test
  public void testRsa2048RawPkcs1SignVerify() throws Exception {
    String cryptoKeyId = "rsa-raw-pkcs1-2048-key";
    // We use the publicly released Java client from maven.org, so we don't have the raw PKCS#1 enum
    // values available in Java.
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_RAW_PKCS1_2048);

    // The JCA provider does the hashing; we should be able to use any hash algorithm.
    signAndVerify(cryptoKeyId, "SHA1withRSA");
    signAndVerify(cryptoKeyId, "SHA256withRSA");
    signAndVerify(cryptoKeyId, "SHA384withRSA");
    signAndVerify(cryptoKeyId, "SHA512withRSA");
  }

  @Test
  public void testRsa3072RawPkcs1SignVerify() throws Exception {
    String cryptoKeyId = "rsa-raw-pkcs1-3072-key";
    // We use the publicly released Java client from maven.org, so we don't have the raw PKCS#1 enum
    // values available in Java.
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_RAW_PKCS1_3072);

    // The JCA provider does the hashing; we should be able to use any hash algorithm.
    signAndVerify(cryptoKeyId, "SHA1withRSA");
    signAndVerify(cryptoKeyId, "SHA256withRSA");
    signAndVerify(cryptoKeyId, "SHA384withRSA");
    signAndVerify(cryptoKeyId, "SHA512withRSA");
  }

  @Test
  public void testRsa4096RawPkcs1SignVerify() throws Exception {
    String cryptoKeyId = "rsa-raw-pkcs1-4096-key";
    // We use the publicly released Java client from maven.org, so we don't have the raw PKCS#1 enum
    // values available in Java.
    createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_RAW_PKCS1_4096);

    // The JCA provider does the hashing; we should be able to use any hash algorithm.
    signAndVerify(cryptoKeyId, "SHA1withRSA");
    signAndVerify(cryptoKeyId, "SHA256withRSA");
    signAndVerify(cryptoKeyId, "SHA384withRSA");
    signAndVerify(cryptoKeyId, "SHA512withRSA");
  }

  @Test
  public void testHmacSha1SignVerify() throws Exception {
    String cryptoKeyId = "hmac-sha1-key";
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.MAC.getNumber(),
        /* HMAC_SHA1 */ 33);

    macSignAndVerify(cryptoKeyId, ckv.getName(), "HmacSHA1");
  }

  @Test
  public void testHmacSha224SignVerify() throws Exception {
    String cryptoKeyId = "hmac-sha224-key";
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.MAC.getNumber(),
        /* HMAC_SHA224 */ 36);

    macSignAndVerify(cryptoKeyId, ckv.getName(), "HmacSHA224");
  }

  @Test
  public void testHmacSha256SignVerify() throws Exception {
    String cryptoKeyId = "hmac-sha256-key";
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.MAC,
        CryptoKeyVersion.CryptoKeyVersionAlgorithm.HMAC_SHA256);

    macSignAndVerify(cryptoKeyId, ckv.getName(), "HmacSHA256");
  }

  @Test
  public void testHmacSha384SignVerify() throws Exception {
    String cryptoKeyId = "hmac-sha384-key";
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.MAC.getNumber(),
        /* HMAC_SHA384 */ 34);

    macSignAndVerify(cryptoKeyId, ckv.getName(), "HmacSHA384");
  }

  @Test
  public void testHmacSha512SignVerify() throws Exception {
    String cryptoKeyId = "hmac-sha512-key";
    CryptoKeyVersion ckv = createCkv(cryptoKeyId, CryptoKey.CryptoKeyPurpose.MAC.getNumber(),
        /* HMAC_SHA512 */ 35);

    macSignAndVerify(cryptoKeyId, ckv.getName(), "HmacSHA512");
  }

  private void signAndVerify(String keyLabel, String jcaAlgorithm) throws Exception {
    Provider provider = f.newProvider();

    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.PrivateKeyEntry);
    KeyStore.PrivateKeyEntry pk = (KeyStore.PrivateKeyEntry) e;

    byte[] data = "Here is some different data to authenticate".getBytes(StandardCharsets.UTF_8);

    Signature signer = Signature.getInstance(jcaAlgorithm, provider);
    signer.initSign(pk.getPrivateKey());
    signer.update(data);
    byte[] signature = signer.sign();

    // Verify using the retrieved certificate's public key + the Java standard
    // library.
    Signature verifier = Signature.getInstance(jcaAlgorithm);
    verifier.initVerify(pk.getCertificate().getPublicKey());
    verifier.update(data);
    Assert.assertTrue(verifier.verify(signature));
  }

  private void macSignAndVerify(String keyLabel, String versionName, String jcaAlgorithm) throws Exception {
    Provider provider = f.newProvider();

    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);
    KeyStore.Entry e = keyStore.getEntry(keyLabel, null);
    Assert.assertTrue(e instanceof KeyStore.SecretKeyEntry);
    KeyStore.SecretKeyEntry sk = (KeyStore.SecretKeyEntry) e;

    byte[] data = "Here is some different data to authenticate".getBytes(StandardCharsets.UTF_8);

    Mac signer = Mac.getInstance(jcaAlgorithm, provider);
    signer.init(sk.getSecretKey());
    signer.update(data);
    byte[] macTag = signer.doFinal();

    // Verify using KMS directly (MacVerify).
    MacVerifyRequest verifyReq = MacVerifyRequest.newBuilder()
                                     .setName(versionName)
                                     .setData(ByteString.copyFrom(data))
                                     .setMac(ByteString.copyFrom(macTag))
                                     .build();

    MacVerifyResponse verifyResp = f.getClient().macVerify(verifyReq);
    Assert.assertTrue(verifyResp.getSuccess());
  }

  private CryptoKeyVersion createCkv(String cryptoKeyId, CryptoKey.CryptoKeyPurpose purpose,
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm) throws Exception {
    return createCkv(cryptoKeyId, purpose.getNumber(), algorithm.getNumber());
  }

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

# APK Signing

APK is Android\'s application packaging format. It\'s basically a ZIP
file that follows the [JAR
Signing](http://download.java.net/jdk7/archive/b125/docs/technotes/tools/solaris/jarsigner.html)
specification, and stores a manifest of all file checksums that gets
signed by a private RSA key.

Android also supports [v2
Signing](https://source.android.com/security/apksigning/v2) and [v3
Signing](https://source.android.com/security/apksigning/v3) (set
`mode: v3enabled`) that put signatures in the metadata of the zip
file.

## Configuration

To generate a key and certificate using the standard
`keytool` approach, use the following command:

``` bash
keytool -keystore testkeystore.jks -genkey -alias testapp -keysize 2048 -keyalg RSA -validity 10000 -keypass password1 -storepass password1
```

This will create a file called `testkeystore.jks` that
contains both the private RSA key and the public certificate. To export
these in PEM format and load them into the Autograph configuration, we
first need to export the keystore into PKCS12, then extract the private
key from the PKCS12 file, as follows:

``` bash
# export the keystore into pkcs12
keytool -importkeystore -srckeystore testkeystore.jks -destkeystore testkeystore.p12 -deststoretype PKCS12 -srcalias testapp -deststorepass password1 -destkeypass password1

# export the private key from the pkcs12 file into PEM
openssl pkcs12 -in testkeystore.p12  -nodes -nocerts -out key.pem

# export the public certificate from the keystore into PEM
keytool -exportcert -keystore testkeystore.jks -alias testapp|openssl x509 -inform der -text
```

You can then place the certificate and private key in
\`autograph.yaml\`:

``` yaml
signers:
- id: some-android-app
  type: apk2
  mode: v3enabled
  certificate: |
      -----BEGIN CERTIFICATE-----
      MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
      ...
      -----END CERTIFICATE-----
  privatekey: |
      -----BEGIN PRIVATE KEY-----
      MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDHV+bKFLr1p5FR
      ...
      -----END PRIVATE KEY-----
```

Set the optional `mode` field to `v3enabled` to
enable APK v3 signatures (in addition to v1 and v2).

## Signature request

This signer only supports the `/sign/file` endpoint.

The `/sign/file` endpoint takes a whole APK encoded in
base64 and no options. It shells out to `apksigner` to issue
v1 JAR signatures and v2 zip file metadata signatures and returns a
zip-aligned APK:

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "some-android-app",
    }
]
```

Per the [zipalign
docs](https://developer.android.com/studio/command-line/zipalign)
callers should align their APK before signing and verify alignment after
signing:

``` bash
zipalign -v <alignment> infile outfile

# ... call /sign/file

zipalign -v <alignment> signedfile
```

## Signature response

### Data Signing

The response to a file signing request contains the base64 of the signed
and aligned APK in the `signed_file` field of the json
response. You should base64 decode that field and write the output as a
file.

``` json
[
  {
    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
    "type": "apk",
    "signer_id": "testapp-android",
    "signed_file": "MIIGPQYJKoZIhvcN..."
  }
]
```

## Verifying signatures

The android SDK has a tool called `apksigner` that can
verify both signature versions, as well as the zip alignment. Note that
you need to pass the min-sdk-version to verify the v1 signature.

``` bash
$ /opt/android-sdk/build-tools/27.0.3/apksigner verify -v --min-sdk-version 23 test.apk
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Number of signers: 1
```

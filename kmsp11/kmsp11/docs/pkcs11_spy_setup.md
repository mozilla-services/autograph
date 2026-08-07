# Setting Up PKCS #11 Tool and PKCS #11 Spy

## Requirements

This guide provides instructions for setting up PKCS #11 Tool and PKCS #11 Spy
for debugging purposes on Debian 11 (Bullseye). You may follow these
instructions if you are using another OS or environment, but be aware that there
may be slight differences.

This guide assumes that you have downloaded the latest linux amd64 [release
build](https://github.com/GoogleCloudPlatform/kms-integrations/releases)
and have a yaml configuration file ready to go.

Remember to point `KMS_PKCS11_CONFIG` at your config file with:

```
export KMS_PKCS11_CONFIG="/path/to/pkcs11-config.yaml"
```

We need the `opensc` package, which contains `pkcs11-tool` and `pkcs11-spy`:

```
sudo apt-get update
sudo apt-get install opensc
```

## Using PKCS #11 Tool

You can test out your yaml configuration by running

```
pkcs11-tool --module /path/to/libkmsp11.so -I
```

which should provide you with some basic information about the PKCS #11 Cloud
KMS Library. Make sure that the library version is the one you expect.

`pkcs11-tool` can be used to test out the KMS library and perform basic crypto
operations through its cli. For instance, you can sign a digest like this:

```
echo -n "hello world" | openssl dgst -binary -sha256 > data.txt

pkcs11-tool --module /path/to/libkmsp11.so --sign --mechanism ECDSA --slot 0 --label test-key-ec \
   --type privkey -i data.txt -o signature.sig
```

NOTE: the path to `libkmsp11.so` should be a full path, not a relative path.

The OpenSC configuration has a debug level variable, which can be overwritten
using the `OPENSC_DEBUG` environment variable. For example you can use:

```
OPENSC_DEBUG=9 pkcs11-tool --list-slots
```

TIP: you may want to try the `-M` flag, to list all the mechanisms supported by
the KMS library, and `-O` to list the objects (CryptoKeys) available for use
based on your yaml configuration.

## Setting up PKCS #11 Spy

PKCS#11 Spy is a special PKCS#11 Module that sits between your application and
your real PKCS#11 Module, and creates a log file with all functions calls by the
application and return values by the real PKCS#11 Module. It does not change the
communication in any way.

IMPORTANT: Be aware such log files are security sensitive. Since all information
is logged, you should only use it for debugging and preferably with test keys.

To use PKCS#11 Spy on Linux and MacOS, set the following environment variables:

```
export PKCS11SPY="/path/to/libkmsp11.so"
# Optional, stderr will be used for logging if not set
export PKCS11SPY_OUTPUT="/path/to/pkcs11-spy.log"
```

To capture the logs, you should now run your application using the
`pkcs11-spy.so` module, instead of the KMS library. For instance, if using
`pkcs11-tool` on a Debian linux distribution:

```
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so -I
```

Your `pkcs11-spy.log` file should now contain a full step-by-step breakdown of
the PKCS #11 functions executed.

<section class="zippy">

Sample pkcs11-spy log for GetInfo:

```
*************** OpenSC PKCS#11 spy *****************
Loaded: "/path/to/libkmsp11.so"

0: C_GetFunctionList
2021-04-12 21:43:35.549
Returned:  0 CKR_OK

1: C_Initialize
2021-04-12 21:43:35.549
[in] pInitArgs = (nil)
Returned:  0 CKR_OK

2: C_GetInfo
2021-04-12 21:43:35.762
[out] pInfo:
      cryptokiVersion:         2.40
      manufacturerID:         'Google                          '
      flags:                   0
      libraryDescription:     'Cryptoki Library for Cloud KMS  '
      libraryVersion:          0.21
Returned:  0 CKR_OK

3: C_GetSlotList
2021-04-12 21:43:35.762
[in] tokenPresent = 0x0
[out] pSlotList:
Count is 1
[out] *pulCount = 0x1
Returned:  0 CKR_OK

4: C_GetSlotList
2021-04-12 21:43:35.762
[in] tokenPresent = 0x0
[out] pSlotList:
Slot 0
[out] *pulCount = 0x1
Returned:  0 CKR_OK

5: C_GetSlotInfo
2021-04-12 21:43:35.762
[in] slotID = 0x0
[out] pInfo:
      slotDescription:        'A virtual slot mapped to a key r'
                              'ing in Google Cloud KMS         '
      manufacturerID:         'Google                          '
      hardwareVersion:         0.0
      firmwareVersion:         0.0
      flags:                   1
        CKF_TOKEN_PRESENT
Returned:  0 CKR_OK

6: C_Finalize
2021-04-12 21:43:35.762
Returned:  0 CKR_OK
```

</section>

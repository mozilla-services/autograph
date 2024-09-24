genpki
======

Simple utility to create a PKI for a contentsignaturepki signer.

It supports both SoftHSM and local key generation, but softhsm being the
default. Use `-no-hsm` to create key in regular files instead.

Example
-------

SoftHSM
~~~~~~~

First initialize a softhsm environment with

```bash
mkdir -p /var/lib/softhsm/tokens
softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000
```      

The configuration for how to talk to softhsm is kept in genpki.go
```go
p11Ctx, err := crypto11.Configure(&crypto11.PKCS11Config{
    Path:       "/usr/lib/softhsm/libsofthsm2.so",
    TokenLabel: "test",
    Pin:        "0000",
}, crypto11.NewDefaultPKCS11Context)
```

Then run the `genpki` tool. Genpki outputs the label of the root and intermediate keys in the HSM, and writes their public certificates to temp files.

```bash
$ go run genpki.go
2019/02/22 12:09:07 Using HSM on slot 1623786617
root key name: csroot1550855347
root cert path: /tmp/csrootcert097998013
inter key name: csinter1550855347
inter cert path: /tmp/csintercert802092792
```

The corresponding autograph configuration would be
```yaml
  - id: foo
    type: contentsignaturepki
    validity: 708h
    clockskewtolerance: 720h
    chainuploadlocation: s3://net-mozaws-dev-content-signature/chains/
    x5u: https://s3.amazonaws.com/net-mozaws-dev-content-signature/chains/
    privatekey: csinter1550855347
    publickey: CONTENT_OF_/tmp/csintercert802092792
    cacert: CONTENT_OF_/tmp/csrootcert097998013
```

Local (No HSM)
~~~~~~~~~~~~~~

With the `-no-hsm` flag set, genpki would write the private keys of the root CA and intermediate issuer to temp files instead. The private key of the intermediate issuer can then be added to the autograph `privatekey` signer configuration (instead of referencing the label of the key in the HSM).

```bash
$ go run genpki.go -no-hsm
[...]
root privkey path: /tmp/csrootkey339824548
inter privkey path: /tmp/csinterkey276780723
```

The corresponding autograph configuration would be
```yaml
  - id: foo
    type: contentsignaturepki
    validity: 708h
    clockskewtolerance: 720h
    chainuploadlocation: s3://net-mozaws-dev-content-signature/chains/
    x5u: https://s3.amazonaws.com/net-mozaws-dev-content-signature/chains/
    privatekey: CONTENT_OF_/tmp/csinterkey276780723
    publickey: CONTENT_OF_/tmp/csintercert802092792
    cacert: CONTENT_OF_/tmp/csrootcert097998013
```

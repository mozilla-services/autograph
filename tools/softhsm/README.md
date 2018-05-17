PKCS11 HSM Support
==================

Disclaimer: This code is under heavy development and not yet ready for
production.

# Setting up CloudHSM

## HSM init
* First activate the cluster with https://docs.aws.amazon.com/cloudhsm/latest/userguide/activate-cluster.html
* CO key len is shorter than 32, probably no more than 16 chars
* create a CU to use to create keys
* exit
* Now generate a 2048 RSA key using the crypto user:

```bash
$ /opt/cloudhsm/bin/key_mgmt_util

* Command:  loginHSM -u CU -s ulfr -p e2deea623796eecd

Cfm3LoginHSM returned: 0x00 : HSM Return: SUCCESS

Cluster Error Status
Node id 0 and err state 0x00000000 : HSM Return: SUCCESS

* Command:  genRSAKeyPair -m 2048 -e 65537 -l rsa2048

        Cfm3GenerateKeyPair returned: 0x00 : HSM Return: SUCCESS

        Cfm3GenerateKeyPair:    public key handle: 6    private key handle: 7

        Cluster Error Status
        Node id 0 and err state 0x00000000 : HSM Return: SUCCESS

* Command:  quit
```

# Setting up SoftHSM
* On Ubuntu Xenial, install `softhsm`
    - `mkdir /var/lib/softhsm/tokens`
* On ArchLinux, install `softhsm2` from AUR
* Then create a token with `$ softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000`

# PKCS11
We use Thales' Crypto11 package, which wraps Miekg' PKCS11 package. PKCS11
depends on `ltdl`. On Ubuntu, that's installed from `libltdl-dev`. On
Archlinux, use `libtool-ltdl-devel`.

## PKCS11 CloudHSM client
install the so library:
* https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html
* it is located under /opt/cloudhsm/lib/libcloudhsm_pkcs11.so

## PKCS11 SoftHSM client
* Ubuntu: `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`
* ArchLinux: `/usr/lib/libsofthsm2.so`

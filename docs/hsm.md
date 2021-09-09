# PKCS11 HSM Support

Autograph uses [Thales\'
Crypto11](https://github.com/ThalesIgnite/crypto11) package to support
PKCS11 operations. Crypto11 wraps [Miekg\'s
PKCS11](https://github.com/miekg/pkcs11/) package, which itself wraps
the C library that talks to the HSM.

PKCS11 depends on [ltdl]{.title-ref}. On Ubuntu, that\'s installed from
[libltdl-dev]{.title-ref}. On Archlinux, use
[libtool-ltdl-devel]{.title-ref}.

# Setting up CloudHSM

## HSM init

-   First activate the cluster with
    <https://docs.aws.amazon.com/cloudhsm/latest/userguide/activate-cluster.html>
-   CO key len is shorter than 32, probably no more than 16 chars
-   create a CU to use to create keys
-   exit
-   Now generate a 2048 RSA key using the crypto user (note: [MAR
    signers for SignatureAlgorithmID 2 / RSA-PKCS1-SHA384
    require >=4096](https://github.com/mozilla/build-mar/blob/607cb8cff99a3b2f8294b4175f81ed0cb28ef381/src/mardor/signing.py#L143)):

``` bash
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

## PKCS11 CloudHSM client

Install the so library from
<https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>,
it will be located under /opt/cloudhsm/lib/libcloudhsm_pkcs11.so

# Setting up SoftHSM

-   On Ubuntu Xenial, install [softhsm2]{.title-ref} and create [mkdir
    /var/lib/softhsm/tokens]{.title-ref}
-   On ArchLinux, install [softhsm]{.title-ref} from AUR
-   Then create a token with [\$ softhsm2-util \--init-token \--slot 0
    \--label test \--pin 0000 \--so-pin 0000]{.title-ref}

## PKCS11 SoftHSM client

The SO library is installed with the softhsm package and located: \*
Ubuntu: [/usr/lib/softhsm/libsofthsm2.so]{.title-ref} \* ArchLinux:
[/usr/lib/libsofthsm2.so]{.title-ref}

# Configuring Autograph

When using an HSM, tell autograph where to find the C library, then
indicate the label of each key in the HSM in their respective signer
blocks, as follows:

``` yaml
# SoftHSM test configuration
hsm:
    # this is the location of the softhsm lib on ubuntu xenial,
    # it will likely be different on each distribution
    path:       /usr/lib/softhsm/libsofthsm2.so
    tokenlabel: test
    pin:        0000

# The keys below are testing keys that do not grant any power
signers:
    - id: testmar
      type: mar
      # label of the key in the hsm
      privatekey: testrsa2048
    - id: testmarecdsa
      type: mar
      # label of the key in the hsm
      privatekey: testecdsap384
```

Note that autograph does not generate slots or keys, this must be
handled separately. For a full working example, take a look at
[autograph.softhsm.yaml]{.title-ref} and how it is used by CircleCI in
[.circleci/config.yaml]{.title-ref}.

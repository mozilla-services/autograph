# Configuration

The configuration lives in `autograph.yaml` at the default path
`/etc/autograph/autograph.yaml` (use the flag `-c` to provide an
alternate path).

## Server

Define an address and port for the API to listen on and an optional HAWK
nonce cache size to prevent replay attacks:

``` yaml
server:
    listen: "192.168.1.28:8000"
    noncecachesize: 524288
    idletimeout: 60s
    readtimeout: 60s
    writetimeout: 60s
```

Use flag `-p` to provide an alternate port and override any
port specified in the config.

## Database

Optionally, configure postgres using the sample below. Use the schema in
database/schema.sql to initialize the db. Make sure to set a user with
limited grants in the configuration.

``` yaml
database:
    name: autograph
    user: myautographdbuser
    password: myautographdbpassword
    host: 127.0.0.1:5432
    sslmode: full-verify
    sslrootcert: /etc/ssl/certs/db-root.crt
    maxopenconns: 100
    maxidleconns: 10
    monitorpollinterval: 10s
heartbeat:
    dbchecktimeout: 15ms
```

`heartbeat.dbchecktimeout` is how long the heartbeat handler
should wait for the DB to return a response before erroring.

## Hardware Security Module (HSM)

Several signers support key operations using an HSM. To configure it
globally, set the following config where:

-   *path* is the file system path to a pkcs11 library
-   *tokenlabel* is set by the type of hsm (cavium for cloudhsm)
-   *pin* is the credentials to use the hsm (`$user:$pass` for cloudhsm)

``` yaml
hsm:
    # sample config for cloudhsm
    path:       /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
    tokenlabel: cavium
    pin:        ulfr:e2deea623796eecd
heartbeat:
    hsmchecktimeout: 10ms
```

Refer to each signer\'s configuration doc to know how they each make use
of the HSM.

`heartbeat.hsmchecktimeout` is how long the heartbeat
handler should wait for the HSM to return a response before erroring.

## Signers

The detailed configuration for each signer is described in their
respective README under the
[autograph/signer/](https://github.com/mozilla-services/autograph/tree/main/signer)
directory.

All signers share the common field `id`, which is a name
unique to the installation to identify each signer. The `id`
is used in the authorization configurations for both
autograph and autograph edge.

``` yaml
signer:
    # installation unigue name for this signer/key/attributes combination
    - id: apk_signer_for_focus
    # rest of object depends on the signer type
```

## Authorizations

Authorizations map an arbitrary username and key to a list of signers.
The key does not need to be generated in any special way. You can use
`openssl` or the tool in `tools/maketoken/main.go` to obtain a random
256-bit string:

``` bash
$ openssl rand -hex 32
ecf1dbcf7d8b161f51d7f590ea4a4eec8332918276ddcfc657fb0b863b2e37e7
```

Then add it to the configuration as follows:

``` yaml
authorizations:
    # username 'alice' is allowed to use signers 'appkey1' and 'appkey2'
    - id: alice
      key: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu
      signers:
          - appkey1
          - appkey2

    # username 'bob' is only allowed to use signer 'appkey2'
    - id: bob
      key: 9vh6bhlc10y63ow2k4zke7k0c3l9hpr8mo96p92jmbfqngs9e7d
      hawktimestampvalidity: 10m
      signers:
          - appkey2
```

The configuration above allows `alice` to request signatures from both
`appkey1` and `appkey2`, while `bob` is only allowed to request
signatures from `appkey2`.

Note that, when a user is allowed to sign with more than one signer,
and no specific signer key id is provided in the signing request,
autograph will use the first signer in the list. For example, if alice
requests a signature without providing a key id, the private key from
`appkey1` will be used to sign her request.

The optional key `hawktimestampvalidity` maps to a string
[parsed as a time.Duration](https://golang.org/pkg/time/#ParseDuration)
and allows for different HAWK timestamp skews than the default of 1
minute.

The following diagram shows how the authentication and signer ids are
linked in the configurations.

![image of relationships between authorization objects](statics/a-h-s.dot.svg?sanitize=true)

## Building and running

Build the autograph binary using make:

``` bash
$ make install
```

The binary is located in `$GOPATH/bin/autograph` and can be
started with the configuration file:

``` bash
$ $GOPATH/bin/autograph -c autograph.yaml
{"Timestamp":1453721399358695130,"Type":"app.log","Logger":"Autograph","Hostname":"gator1","EnvVersion":"2.0","Pid":17287,"Fields":{"msg":"main.go:74: Starting Autograph API on localhost:8000"}}
```

You can test that the API is alive by querying its heartbeat URL:

``` bash
$ curl localhost:8000/__heartbeat__
ohai
```

## Test Key/Cert

For dev and testing purposes, the private key `appkey1` can
be used with the following self-signed certificate:

>     -----BEGIN CERTIFICATE-----
>     MIICjjCCAhUCCQC92fl+HNcL+zAKBggqhkjOPQQDAjCBsDELMAkGA1UEBhMCVVMx
>     EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxHDAa
>     BgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZp
>     Y2VzMRYwFAYDVQQDEw1BdXRvZ3JhcGggRGV2MSUwIwYJKoZIhvcNAQkBFhZob3N0
>     bWFzdGVyQG1vemlsbGEuY29tMB4XDTE2MDIwNjAwMDYwMloXDTI2MDIwMzAwMDYw
>     MlowgbAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
>     Ew1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcw
>     FQYDVQQLEw5DbG91ZCBTZXJ2aWNlczEWMBQGA1UEAxMNQXV0b2dyYXBoIERldjEl
>     MCMGCSqGSIb3DQEJARYWaG9zdG1hc3RlckBtb3ppbGxhLmNvbTB2MBAGByqGSM49
>     AgEGBSuBBAAiA2IABOJNxZhu3RaDrd07s5e+mm00bSvLG/6/4mwknlSmvekW6zl9
>     nIrHM/00/MH6gWEv/HDeMzHtfn+8EZpDawlKI2UdWSpmDNgXolDjJTKKpNju/rsL
>     J9Q8DUEmD+fE5L2bejAKBggqhkjOPQQDAgNnADBkAjARjtum9oq77JL9fhZ46Q1S
>     vxT5RAdzQRp9/l3OqnUP+kK42tRk05c9UGDFXLLVH/4CMH/ZmcpvtM0sCjeAWzGs
>     gnw91z0443965WZmaeBKpbinxB1PpnNMCnPhd9J/Hz40+Q==
>     -----END CERTIFICATE-----

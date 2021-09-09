# Autograph
Autograph is a cryptographic signature service that implements
[Content-Signature](signer/contentsignaturepki/README.rst),
[XPI Signing](signer/xpi/README.rst) for Firefox web extensions,
[MAR Signing](signer/mar/README.rst) for Firefox updates,
[APK Signing](signer/apk2/README.rst) for Android,
[GPG2](signer/gpg2/README.rst)
and [RSA](signer/genericrsa/README.rst).

[![CircleCI](https://circleci.com/gh/mozilla-services/autograph/tree/main.svg?style=svg)](https://circleci.com/gh/mozilla-services/autograph/tree/main)
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/autograph/badge.svg?branch=main)](https://coveralls.io/github/mozilla-services/autograph?branch=main)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=mozilla-services/autograph)](https://dependabot.com)

Why is it called "autograph"? Because it's a service to sign stuff.

## Installation

### Using Docker

`docker pull mozilla/autograph && docker run mozilla/autograph`

This will download the latest build of autograph from DockerHub and run it with its dev configuration.

### Using go get

If you don't yet have a GOPATH, export one:
```bash
$ export GOPATH=$HOME/go
$ mkdir $GOPATH
```

Install ltdl:
* on Ubuntu: ltdl-dev
* on RHEL/Fedora/Arch: libtool-ltdl-devel
* on MacOS: libtool (NB: this might require `brew unlink libtool && brew link libtool`)

Then download and build autograph:
```bash
$ go get github.com/mozilla-services/autograph
```

The resulting binary will be placed in `$GOPATH/bin/autograph`. To run autograph with the example conf, do:
```bash
$ cd $GOPATH/src/github.com/mozilla-services/autograph
$ $GOPATH/bin/autograph -c autograph.yaml
```

Example clients are in the `tools` directory. You can install the Go one like this:
```bash
$ go get github.com/mozilla-services/autograph/tools/autograph-client
$ $GOPATH/bin/autograph-client -u alice -p fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu -t http://localhost:8000/sign/data -r '[{"input": "Y2FyaWJvdW1hdXJpY2UK"}]'
2016/08/23 17:25:55 signature 0 pass
```

## Documentation

* [Architecture](docs/architecture.rst)
* [Configuration](docs/configuration.rst)
* [Endpoints](docs/endpoints.rst)
* [HSM Support](docs/hsm.rst)

### Signers

* [APK](signer/apk2/README.rst)
* [Content-Signature PKI](signer/contentsignaturepki/README.rst)
* [Content-Signature protocol](signer/contentsignature/README.rst)
* [GPG](signer/gpg2/README.rst)
* [MAR](signer/mar/README.rst)
* [RSA](signer/genericrsa/README.rst)
* [XPI Signing protocol](signer/xpi/README.rst)

## Signing

Autograph exposes a REST API that services can query to request signature of
their data. Autograph knows which key should be used to sign the data of a
service based on the service's authentication token. Access control and rate
limiting are performed at that layer as well.

![signing.png](docs/statics/Autograph%20signing.png)

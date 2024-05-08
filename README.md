# Autograph
Autograph is a cryptographic signature service that implements
[Content-Signature](signer/contentsignaturepki/README.md),
[XPI Signing](signer/xpi/README.md) for Firefox web extensions,
[MAR Signing](signer/mar/README.md) for Firefox updates,
[APK Signing](signer/apk2/README.md) for Android,
[GPG2](signer/gpg2/README.md)
and [RSA](signer/genericrsa/README.md).

[![CircleCI](https://circleci.com/gh/mozilla-services/autograph/tree/main.svg?style=svg)](https://circleci.com/gh/mozilla-services/autograph/tree/main)
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/autograph/badge.svg?branch=main)](https://coveralls.io/github/mozilla-services/autograph?branch=main)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=mozilla-services/autograph)](https://dependabot.com)

Why is it called "autograph"? Because it's a service to sign stuff.

## Installation

Use Docker whenever possible. The golang version on your machine is likely _not_ the corect version for autograph.

### Using Docker

`docker pull mozilla/autograph && docker run mozilla/autograph`

This will download the latest build of autograph from DockerHub and run it with its dev configuration.

#### Local Development with Docker

(This process will start a number of `gpg-agent` processes on your host machine,
then does a `killall gpg-agent` to clean up.)

After making any changes, please test locally by:
```bash
make build             # updates local docker images
make integration-test  # must pass
docker compose up      # runs unit tests in container, must pass
```
_Note: you must monitor the output of docker to detect when the unit tests have
completed. Otherwise, it will run forever with heartbeat messages. The following
pipeline is useful (and available in the Makefile as target `test-in-docker`):_
```bash
docker compose up 2>&1 | tee compose.log \
    | (grep --silent "autograph-unit-test exited with code" && docker compose down; \
       grep "autograph-unit-test" compose.log)
```

As of 2023-06-26, only the integration tests will pass on Circle CI. See [Issue 853](https://github.com/mozilla-services/autograph/issues/853) for details.

### Using go get

_**Do Not Use** unless you are an experienced golang developer._

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

* [Architecture](docs/architecture.md)
* [Configuration](docs/configuration.md)
* [Endpoints](docs/endpoints.md)
* [HSM Support](docs/hsm.md)

### Signers

* [APK](signer/apk2/README.md)
* [Content-Signature PKI](signer/contentsignaturepki/README.md)
* [Content-Signature protocol](signer/contentsignature/README.md)
* [GPG](signer/gpg2/README.md)
* [MAR](signer/mar/README.md)
* [RSA](signer/genericrsa/README.md)
* [XPI Signing protocol](signer/xpi/README.md)

## Signing

Autograph exposes a REST API that services can query to request signature of
their data. Autograph knows which key should be used to sign the data of a
service based on the service's authentication token. Access control and rate
limiting are performed at that layer as well.

![signing.png](docs/statics/Autograph%20signing.png)

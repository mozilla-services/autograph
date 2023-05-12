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

### Using Docker

`docker pull mozilla/autograph && docker run mozilla/autograph`

This will download the latest build of autograph from DockerHub and run it with its dev configuration.

### Using Docker Compose

Autograph writes to /tmp and relies on the apksigner and gpg2 binaries
being in specific locations, so it's cleanest to develop it in a
container.

1. copy over the local dev config to run the server in debug mode with
   the host repo mounted to `/host`:

```sh
cp docker-compose.override.yml.example docker-compose.override.yml
```

1. run `make build` to build the docker images

1. run `docker-compose up -d db app` to start the app and db (`app-hsm`
   runs the app using softhsm)

1. run `make unit-test` or `make integration-test` to test changes
   1. alternatively run `docker-compose exec -w /host -u 0 -- app
      /bin/bash` then `make test` to run unit tests without having to
      rebuild the `unit-test` image

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

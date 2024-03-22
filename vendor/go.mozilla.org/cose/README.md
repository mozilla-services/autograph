# go-cose

[![CircleCI](https://circleci.com/gh/mozilla-services/go-cose.svg?style=svg)](https://circleci.com/gh/mozilla-services/go-cose) 
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/go-cose/badge.svg)](https://coveralls.io/github/mozilla-services/go-cose)

A [COSE](https://tools.ietf.org/html/rfc8152) library for go.

It currently supports signing and verifying the SignMessage type with the ES{256,384,512} and PS256 algorithms.

[API docs](https://godoc.org/go.mozilla.org/cose)

## Usage

### Install

```console
go get -u go.mozilla.org/cose
```

### Signing a message

See [example/sign.go](example/sign.go) and run it with:

```console
$ go run example/sign.go
Bit lengths of integers r and s (256 and 256) do not match the key length 255
Message signature (ES256): 043685f99421f9e80c7c3c50d0fc8266161d3d614aaa3b63d2cdf581713fca62bb5d2e34d2352dbe41424b31d0b4a11d6b2d4764c18e2af04f4520fbe494d51c
```

### Verifying a message

See [example/verify.go](example/verify.go) and run it with:

```console
$ go run example/verify.go
Bit lengths of integers r and s (256 and 254) do not match the key length 254
Message signature (ES256): 9411dc5200c1cb67ccd76424ade09ce89c4a8d8d2b66f2bbf70edf63beb2dc3cbde83250773e659b635d3715442a1efaa6b0c030ee8a2523c3e37a22ddb055fa
Message signature verified
```

## Development

Running tests:

1. Install [rust and cargo](https://www.rustup.rs/)

1. On OSX: `brew install nss` [nss](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) then in `sign_verify_cose_rust_cli_test.go` add `NSS_LIB_DIR` to `cmd` or `-L /usr/local/opt/nss/lib` to RUSTFLAGS e.g. `cmd.Env = append(os.Environ(), "NSS_LIB_DIR=/usr/local/opt/nss/lib", "RUSTFLAGS=-A dead_code -A unused_imports")`

1. If you already have `dep` and `golint` commands installed, run `make install-godep install-golint`

1. Run `go test`

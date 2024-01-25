# MARGO: Mozilla ARchive library written in Go

[![Build Status](https://travis-ci.org/mozilla-services/margo.svg?branch=master)](https://travis-ci.org/mozilla-services/margo)
[![GoDoc](https://godoc.org/go.mozilla.org/mar?status.svg)](https://godoc.org/go.mozilla.org/mar) 
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/margo/badge.svg?branch=master)](https://coveralls.io/github/mozilla-services/margo?branch=master)

`import "go.mozilla.org/mar"`

**Requires Go 1.10**

Margo is a fairly secure MAR parser written to allow
[autograph](https://github.com/mozilla-services/autograph) to sign Firefox
MAR files. Its primary focus is signature, but it can also be used to parse,
create and verify signatures on existing MAR files.

Take a look at `example_test.go` for a taste of the API, or run the command line
tools under `examples/`.

## FAQ
### Why is it called "margo"?
it's subtle: it's a "mar" library, written in "go". get it? "margo"!

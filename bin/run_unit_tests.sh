#!/bin/bash

set -e
set -o pipefail

# run unit tests inside an app container
# and report coverage from CI
#
# refs: https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables

REPORT_COVERAGE=${CI:-""}
if [ "$REPORT_COVERAGE" = "true" ]; then
    make install-goveralls
fi

EMPTY_TESTCACHE=${EMPTY_TESTCACHE:-""}
if [ "$EMPTY_TESTCACHE" = "1" ]; then
    go clean -testcache
fi

make test

if [ "$REPORT_COVERAGE" = "true" ]; then
    # report coverage
    # ignore failures while coveralls is down for maintenance
    $(go env GOPATH)/bin/goveralls -coverprofile=coverage.out -service circle-ci || true
fi

#!/bin/bash

set -e
set -o pipefail


# run unit tests inside an app container
# and report coverage from CI
#
# refs: https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables

REPORT_COVERAGE=${CI:-""}
if [ "$REPORT_COVERAGE" = "true" ]; then
    make install-goveralls install-cover
fi
# run app unit tests
make generate test
# run monitor unit tests
make -C tools/autograph-monitor test

if [ "$REPORT_COVERAGE" = "true" ]; then
    # report coverage
    $GOPATH/bin/goveralls -coverprofile=coverage.out -service circle-ci
fi

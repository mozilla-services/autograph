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

if [ "$RACE_TEST" = "1" ]; then
    make race
    make -C tools/autograph-monitor race
    make -C verifier/contentsignature race
fi

if [ "$REPORT_COVERAGE" = "true" ]; then
    cp coverage.out combined-coverage.out
    # skip 'mode: count' on the first line
    tail -n +2 tools/autograph-monitor/monitor-coverage.out >> combined-coverage.out

    # report coverage
    # ignore failures while coveralls is down for maintenance
    $GOPATH/bin/goveralls -coverprofile=combined-coverage.out -service circle-ci || true
fi

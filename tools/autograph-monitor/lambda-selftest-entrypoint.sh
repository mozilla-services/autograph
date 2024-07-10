#!/bin/bash

set -e
set -o pipefail

# Fork to start the AWS runtime emulator
/usr/local/bin/aws-lambda-rie "$@" &
AWS_RUNTIME_PID=$!
cleanup() {
    kill -TERM $AWS_RUNTIME_PID
    wait $AWS_RUNTIME_PID
}
trap cleanup EXIT SIGINT SIGTERM

# invoke a test monitor run in a lambda monitor
MONITOR_ERROR=$(curl -s -w '\n' -X POST 'http://localhost:8080/2015-03-31/functions/function/invocations' -d '{}')

# If the result was null - then we succeeded!
if [ "${MONITOR_ERROR}" == "null" ]; then
    exit 0
fi

# Otherwise - some kind of error occured
MONITOR_ERROR_TYPE=$(echo "${MONITOR_ERROR}" | jq -r '.errorType')
if [ "${MONITOR_ERROR_TYPE}" == "errorString" ]; then
    echo "${MONITOR_ERROR}" | jq -r '.errorMessage' >&2
else
    echo "${MONITOR_ERROR}" | jq >&2
fi
exit 1

#!/bin/bash

set -e
set -o pipefail

MONITOR_ENDPOINT=${1:-"http://localhost:8080"}

# invoke a test monitor run in a lambda monitor
CURL_OPTIONS="--retry 10 --retry-max-time 120 --retry-connrefused"
MONITOR_ERROR=$(curl $CURL_OPTIONS -w '\n' -X POST "${MONITOR_ENDPOINT}/2015-03-31/functions/function/invocations" -d '{}')

# Dump the log file, if it exists
if [ -f "/tmp/autograph-lambda-logs.txt" ]; then
    cat /tmp/autograph-lambda-logs.txt
fi

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


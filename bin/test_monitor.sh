#!/bin/bash

set -e
set -o pipefail

# invoke a test monitor run in a lambda monitor
MONITOR_ERROR=$(curl -w '\n' -X POST 'http://localhost:8080/2015-03-31/functions/function/invocations' -d '{}')

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


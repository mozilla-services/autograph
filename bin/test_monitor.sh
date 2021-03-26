#!/bin/bash

set -e
set -o pipefail

# invoke a test monitor run in a lambda monitor

MONITOR_ERROR=$(curl -w '\n' -X POST 'http://localhost:8080/2015-03-31/functions/function/invocations' -d '{}')
test "$MONITOR_ERROR = null"

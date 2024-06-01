#!/usr/bin/env sh

# Wait for the heartbeat
RESULT=$(curl --silent \
              --connect-timeout 5 \
              --max-time 10 \
              --retry-connrefused \
              --retry 5 \
              --retry-delay 5 \
              --retry-max-time 60 \
              "${AUTOGRAPH_URL}/__heartbeat__")
RETCODE=$?
if [ $RETCODE -ne 0 ]; then
    echo "Failed to reach autograph heartbeat" >&2
    exit $RETCODE
else
    echo "Autograph is running: ${RESULT}"
    echo "Starting test"
fi

# Run the test
set -e
/bin/bash -c "$@"

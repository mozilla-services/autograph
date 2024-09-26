#!/bin/bash

set -o pipefail

/go/bin/autograph-monitor
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "Monitor test failure detected"
  exit 1
fi

#!/bin/bash

set -o pipefail

docker compose run monitor
EXIT_CODE=$?
if [$EXIT_CODE -ne 0]; then
  echo "Monitor test failure detected"
  exit 1
fi

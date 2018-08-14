#!/bin/bash

set -e

cd "$(dirname "$0")"
printf '{"commit":"%s","version":"%s","source":"https://go.mozilla.org/autograph","build":"https://travis-ci.org/mozilla-services/autograph"}\n' \
    "$(git rev-parse HEAD)" \
    "$(git describe --abbrev=0)" > version.json

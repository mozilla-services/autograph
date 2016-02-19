#!/bin/bash

set -e

cd "$(dirname "$0")"
RELEASE=0
VERSION="$(date +%Y%m%d).$RELEASE"
if REV=$(git rev-parse --short HEAD); then
    VERSION="${VERSION}-${REV}"
fi
COMMIT="$(git log --pretty=format:'%H' -n 1)"

cat > version.go <<HERE
package main

const version = "${VERSION}"
const commit = "${COMMIT}"
HERE

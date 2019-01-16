#!/bin/bash

set -e

cd "$(dirname "$0")"

# create a version.json per https://github.com/mozilla-services/Dockerflow/blob/master/docs/version_object.md
printf '{"commit":"%s","version":"%s","source":"https://github.com/%s/%s","build":"%s"}\n' \
"$CIRCLE_SHA1" \
"$CIRCLE_TAG" \
"$CIRCLE_PROJECT_USERNAME" \
"$CIRCLE_PROJECT_REPONAME" \
"$CIRCLE_BUILD_URL" > version.json

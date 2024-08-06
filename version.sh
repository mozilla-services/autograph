#!/bin/bash

set -e

cd "$(dirname "$0")"

# create a version.json per https://github.com/mozilla-services/Dockerflow/blob/main/docs/version_object.md
if [ -n "$CIRCLE_SHA1" ]; then
    # We are running in CircleCI.
    printf '{"commit":"%s","version":"%s","source":"https://github.com/%s/%s","build":"%s"}\n' \
        "$CIRCLE_SHA1" \
        "$CIRCLE_TAG" \
        "$CIRCLE_PROJECT_USERNAME" \
        "$CIRCLE_PROJECT_REPONAME" \
        "$CIRCLE_BUILD_URL" > version.json
elif [ -n "$GITHUB_SHA" ]; then
    # We are running in Github Actions.
    printf '{"commit":"%s","version":"%s","source":"%s","build":"%s"}\n' \
        "$GITHUB_SHA" \
        "$GITHUB_REF_NAME" \
        "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
        "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" > version.json
elif [ -d .git ]; then
    # Try pulling info from git directly.
    printf '{"commit":"%s","version":"%s","source":"%s","build":"%s"}\n' \
        "$(git rev-parse HEAD)" \
        "$(git describe --tags --always)" \
        "$(git remote get-url origin)" \
        "" > version.json
elif [ ! -f version.json ]; then
    # Otherwise, give up and create an empty version file.
    echo '{"commit":"","version":"","source":"","build":""}\n' > version.json
fi

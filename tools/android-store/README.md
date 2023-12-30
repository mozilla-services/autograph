# Play Store Tools

The generation of APK keys, and wrapping for upload, is a somewhat complicated
process requiring specific tools that would be cumbersome for an Autograph
Configuration Maintainer to have available.

This directory contains helper tools for these processes, which should be used
as described in the Confluence [run book][runbook].

## Normal usage

These tools are built into the production autograph container images. The most
recent production version should be used, unless otherwise noted.

For convenience, if one has the [Autograph Repo][repo] checked out locally, the
following command sequence is recommended:

- `make status` # to verify all preconditions are met
- `make docker-run` # will launch the container properly

### Pre-requisites

Only the `docker` command is needed to be working on your machine. (Docker
desktop is not needed, the Community Edition cli tool is sufficient.)

## Development

If you're working on modifying the script `gen-apk-key.sh`, or otherwise want to
test the latest & greatest, you'll want to use a locally built container image.

To build a container with the current files from you working directory:
```bash
make -C ../.. build
```
That will produce a fresh image `autograph-app`. You can have the Makefile use
that image by export the image name:
```bash
export CONTAINER_IMAGE="autograph-app"
```


[repo]: https://github.com/mozilla-services/autograph
[runbook]: https://mozilla-hub.atlassian.net/wiki/spaces/SECENGOPS/pages/27922135/Autograph#Autograph-AndroidAPKOperations

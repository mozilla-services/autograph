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


[repo]: https://github.com/mozilla-services/autograph
[runbook]: https://mozilla-hub.atlassian.net/wiki/spaces/SECENGOPS/pages/27922135/Autograph#Autograph-AndroidAPKOperations

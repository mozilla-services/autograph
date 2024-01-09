# Overview
The script here sanitizes a production configuration file by:
- only outputting data about signers and authorizations
- converting secrets to their sha256 hashes

It also enriches the data somewhat, such as providing the SHA1 fingerprint of
certificates. Google Play identifies APK signing keys by the SHA1 fingerprint.

# Usage

First, install the script.

The script takes input on `stdin`, and outputs files based on the information
found in the input.

Assuming there's no overlap in your app & edge config files (the normal case),
you can run the script over each file separately. If you want to be extra sure
you don't have overlaps, concatenate the files with a YAML document separator in
one pass:
```bash
$ { sops -d app.yaml ; echo "---" ; sops -d edge.yaml ; } | autograph-config-sanitizer
```

This outputs 3 files:
- `signers.csv` -- all the configured signers
- `authorizations_app.csv` -- all the account names and signer access for
  autograph app.
- `authorizations_edge.csv` -- all the signer access via edge.

Process the CSVs with your favorite tooling, or try [Datasette
lite](https://lite.datasette.io).

# Installation

You've got several choices for installation. While the script is pure python, it depends upon packages with system dependent binaries.

## Using local python
If you have a modern python environment, you can get an install within a virtualenv in this directory with:
```bash
make build
```
If you want it installed for you, without needing to remember where the virtualenv is located, continue with:
```bash
pipx install dist/autograph_config_sanitizer*whl
```

## Using docker
If you don't want to maintain a python environment, get someone that has one to build a docker image for you:
```bash
make docker-build
```

Once you have the image on your machine, you can run the script with `make docker-run`, or create a shell alias. (See `make -n docker-run` for the recommended options.)


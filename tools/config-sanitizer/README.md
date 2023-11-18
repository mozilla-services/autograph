# Overview
The script here sanitizes a production configuration file by:
- only outputing data about signers and authorizations
- converting secrets to their sha256 hashes

It also enriches the data somewhat, such as providing the SHA1 fingerprint of
certificates. Google Play identifies APK signing keys by the SHA1 fingerprint.

# Usage

The script takes input on `stdin`, and outputs files based on the information
found in the input.

Assuming there's no overlap in your app & edge config files (the normal case),
you can run the script over each file separately. If you want to be extra sure
you don't have overlaps, concatenate the files with a YAML document seperator in
one pass:
```bash
$ { sops -d app.yaml ; echo "---" ; sops -d edge.yaml ; } | ./sanitize-config.py
```

This outputs 3 files:
- `signers.csv` -- all the configured signers
- `authorizations_app.csv` -- all the account names and signer access for
  autograph app.
- `authorizations_edge.csv` -- all the signer access via edge.

Process the CSVs with your favorite tooling, or try [Datasette
lite](https://lite.datasette.io).

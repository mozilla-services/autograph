# Apple / macOS Signing

This signer adds Apple code signatures to macOS artifacts by shelling out to
[`rcodesign`](https://github.com/indygreg/apple-platform-rs/tree/main/apple-codesign)
(the `apple-codesign` project). It supports, from a single `/sign/file`
endpoint, all of the artifact types `rcodesign` auto-detects:

- **Standalone Mach-O binaries** (including universal/fat)
- **Application bundles** delivered as a **`.tar.gz` containing a `.app`**
  directory. The signer extracts the archive, signs the bundle (recursively),
  and returns a re-created `.tar.gz`.
- **XAR archives (`.pkg` installers)** — signed by a separate installer-mode
  signer using an in-memory PEM key (see "Modes and key material" below).
- **DMG disk images**

Only signing is implemented. Notarization and stapling are handled by a separate
system, but signatures are produced notarization-ready (hardened runtime + secure
timestamp) when `for_notarization` is enabled with an Apple-issued Developer ID
certificate.

## Modes and key material

Apple issues two distinct certificate types, and the two modes also differ in
where the key lives:

| mode | artifacts | certificate | key |
|------|-----------|-------------|-----|
| `application` (default) | Mach-O, `.app` (`.tar.gz`), `.dmg` | Developer ID Application | **HSM (PKCS#11)** |
| `installer` | `.pkg` (XAR) | Developer ID Installer | **in-memory PEM** |

Configure one signer per certificate. The signer validates the detected artifact
type against its mode.

**application mode** signs with an HSM-resident key through PKCS#11. `rcodesign`
opens the same PKCS#11 provider autograph is configured with (the top-level
`hsm:` section) and signs inside the HSM — the private key never leaves it.
`privatekey` is the **PKCS#11 key label**, and `certificate` holds the full
chain (leaf first, then intermediates and root), which is passed to `rcodesign`
via `--pkcs11-certificate-file`. The PIN is written to a short-lived `0400`
config file (never the command line).

**installer mode** signs with an **in-memory PEM key** from `privatekey`. This is
not a choice: `rcodesign`'s XAR (`.pkg`) signer does not support PKCS#11 keys —
it only accepts an in-memory (PEM/p12) key and rejects any HSM key regardless of
token/label/id. Only Mach-O/bundle/DMG signing was taught about PKCS#11 upstream.
Until that changes, `.pkg` installers must be signed with a software Developer ID
Installer key. See the note at the top of `apple.go`.

> `rcodesign` must be built with the `pkcs11` cargo feature, which currently
> exists only on the upstream `main` branch (no released version has it). The
> repo Dockerfile builds it from a pinned commit; see the `rcodesign-builder`
> stage.

## Configuration

```yaml
# top-level: the PKCS#11 provider shared by all HSM-backed signers
hsm:
  path: /usr/lib/softhsm/libsofthsm2.so
  tokenlabel: test
  pin: "0000"

signers:
# application mode — HSM key
- id: some-macos-app
  type: apple
  mode: application
  apple:
    # Pass --for-notarization (requires an Apple Developer ID cert and a
    # timestamp server; enables the hardened runtime on all Mach-O binaries).
    for_notarization: true
    # RFC 3161 timestamp server. Omit to use rcodesign's default (Apple's
    # server). Use "none" to disable timestamping (e.g. local dev/test with a
    # self-signed certificate).
    timestamp_url: ""
    team_name: ABCDE12345
    # Default per-path signing settings, overridable per request. Mirrors
    # Mozilla iscript's hardened-sign-config.
    hardened_sign_config:
      - globs: [""]            # the main entity (@main); empty globs == main
        entitlements: |
          <?xml version="1.0" encoding="UTF-8"?>
          <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
          <plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>
        runtime: true
  # PKCS#11 label of the signing key in the HSM
  privatekey: some-macos-app-key
  certificate: |
      -----BEGIN CERTIFICATE-----
      ... leaf, then intermediates and root ...
      -----END CERTIFICATE-----

# installer mode — in-memory PEM key (.pkg can't use the HSM)
- id: some-macos-installer
  type: apple
  mode: installer
  apple:
    for_notarization: true
  certificate: |
      -----BEGIN CERTIFICATE-----
      ... Developer ID Installer chain ...
      -----END CERTIFICATE-----
  privatekey: |
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
```

Self-signed certificates for local testing can be generated with:

```bash
rcodesign generate-self-signed-certificate --person-name "Dev" \
  --profile developer-id-application --pem-unified-file app.pem
rcodesign generate-self-signed-certificate --person-name "Dev" \
  --profile developer-id-installer --pem-unified-file installer.pem
```

For application mode, import the key into the token and reference its label:

```bash
softhsm2-util --token test --pin 0000 --label some-macos-app-key --id ab \
  --import app-key-pkcs8.pem
```

## Signature request

This signer only supports the `/sign/file` endpoint. The input is the whole
artifact, base64-encoded. Options are optional:

- `hardened_sign_config`: when present, replaces the configured default. A list
  of entries, each with `globs` (bundle-relative paths; `**` matches across
  directories, an empty entry targets the main entity), `entitlements` (inline
  plist XML), and `runtime` (hardened runtime flag).
- `identifier`: `--binary-identifier` for a standalone Mach-O (bundles use their
  `Info.plist` `CFBundleIdentifier`).

```json
[
  {
    "input": "H4sIAAAA...",
    "keyid": "some-macos-app",
    "options": {
      "hardened_sign_config": [
        {
          "globs": ["Contents/MacOS/plugin-container"],
          "entitlements": "<?xml version=\"1.0\"?>...</plist>",
          "runtime": true
        }
      ]
    }
  }
]
```

## Signature response

The response contains the base64 of the signed artifact in the `signed_file`
field. For a bundle request this is the re-created `.tar.gz`; otherwise it is the
signed single file. Base64-decode it and write it out.

```json
[
  {
    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
    "type": "apple",
    "signer_id": "some-macos-app",
    "signed_file": "H4sIAAAA..."
  }
]
```

## Verifying signatures

`rcodesign` can inspect a signature (Mach-O, bundle, DMG, or pkg):

```bash
rcodesign print-signature-info signed-artifact
# Mach-O only:
rcodesign verify signed-artifact
```

## Notes and limitations

- `.pkg`/XAR payloads are **not** rebuilt; the Mach-O binaries inside a `.pkg`
  should already be signed before the package is built (`rcodesign` cannot
  rewrite nested package content).
- On Linux, `rcodesign` signs the DMG wrapper but does not recurse into a DMG's
  HFS+ contents — sign the inner `.app`/Mach-O before building the DMG.
- Notarization-ready signing performs a network request to the timestamp server;
  the signing environment must allow egress to it (or set `timestamp_url: none`).



/*
  Example signer/auth config that could be used for local dev or tests
*/

INSERT INTO signer(id, type, mode, public, comments)
values('remote-settings', 'contentsignaturepki', null, jsonb_build_object(
  'validity', '708h',
  'clockskewtolerance', '1h',
  'chainlocation', '/tmp/autograph/chains/remotesettingsdev/',
  'x5u', 'file:///tmp/autograph/chains/remotesettingsdev/',
  'issuerprivkey', '-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBEk1fq5FMwBSLKDldmW+QRo15eebdJK1DdrUlp2SmwVf85TffXlFsa
accDMiiow/WgBwYFK4EEACKhZANiAARP5dbB0qgDev4IRzVkuHDYf2TDc8YkpNFW
nQ/KonN1EWrMIWNAeuOOJgjswwq0+M2J0/TNcnYlts5tVZh6MFYKwYHG/NlkTZZ5
5wb3GKy8JkoFH/X74Tm3o06hf0BuCfY=
-----END EC PRIVATE KEY-----
', 'issuercert', '-----BEGIN CERTIFICATE-----
MIICWzCCAeKgAwIBAgIIFY4HHiYeU5AwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUzMTg2NzQ3MB4XDTE5MDEyMDE3
NDU0N1oXDTI5MDMyMTE2NDU0N1owYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTU1MzE4Njc0NzB2MBAGByqGSM49AgEGBSuBBAAiA2IABE/l
1sHSqAN6/ghHNWS4cNh/ZMNzxiSk0VadD8qic3URaswhY0B6444mCOzDCrT4zYnT
9M1ydiW2zm1VmHowVgrBgcb82WRNlnnnBvcYrLwmSgUf9fvhObejTqF/QG4J9qNq
MGgwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1UdEwEB
/wQFMAMBAf8wMAYDVR0eAQH/BCYwJKAiMCCCHi5jb250ZW50LXNpZ25hdHVyZS5t
b3ppbGxhLm9yZzAKBggqhkjOPQQDAwNnADBkAjBPi4uhzbCzoFxYD2LZY+hUQ1kX
eHE9YmF0NOBbosIY041UrbLQLpQRXi4LFku9008CMGoSf/UGB6qV9KzsCY3s51Lp
Rw/oK58D2n63FpPnOTICWvWAYsG3HPNCoURfLqlEOQ==
-----END CERTIFICATE-----
', 'cacert', '-----BEGIN CERTIFICATE-----
MIICKjCCAa+gAwIBAgIIFY4HHiViG/gwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUzMTg2NzQ3MB4XDTE5MDExOTE3
NDU0N1oXDTQ5MDMyMTE3NDU0N1owXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRkwFwYD
VQQDExBjc3Jvb3QxNTUzMTg2NzQ3MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEhpId
iezJa9Ab2dCesA0pc5FIBdkA6uWWVU2hN3/CpTWcTbhZ6JRCSsGa31YEUEGkDuGl
C1ti6hzL0gq/vlnRkMoAcdPU8qdeOp/ZAmVYP+CZcQ0F0S/7PFjqE+5AiLGmozgw
NjAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA1UhMQI32zwh4+UmD1tVYRFRLM0sy
raFyXTzUlrYF0YW89gvUXETPTmewAST397LAAjEAzGUC8N7h8BWfj6R9ES88UPgr
yhRZrsaFZybKjZnBwG7lN9AkrjpKC1h2z4naOXX3
-----END CERTIFICATE-----
'), 'Signer for local remote settings development. Will issue a certificate
valid for remote-settings.content-signature.mozilla.org. To use this
with Firefox, set security.content.signature.root_hash to
5E:36:F2:14:DE:82:3F:8B:29:96:89:23:5F:03:41:AC:AF:A0:75:AF:82:CB:4C:D4:30:7C:3D:B3:43:39:2A:FE

Note the private key of the root was not saved. Use tools/genpki to
make a new config as needed.');

INSERT INTO auth(id, key)
values('alice', 'fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu');

INSERT INTO auth_signers(auth, signer)
values('alice', 'remote-settings');

-- test signer config for soft-hsm
INSERT INTO signer(id, type, mode, public, comments)
VALUES('softhsm-testmar', 'mar', null, jsonb_build_object('privatekey', 'testrsa2048'), null),
('softhsm-testmar2', 'mar', null, jsonb_build_object('privatekey', 'testrsa4096'), null),
('softhsm-testmarecdsa', 'mar', null, jsonb_build_object('privatekey', 'testecdsap256'), null),
('softhsm-testcsp384', 'contentsignature', null, jsonb_build_object('privatekey', 'testecdsap384'), null),
('softhsm-hsm-webextensions-rsa', 'xpi', 'add-on', jsonb_build_object(
  'rsacacheconfig', jsonb_build_object(
    'numkeys', 5,
    'numgenerators', 1,
    'generatorsleepduration', '1m',
    'fetchtimeout', '100ms',
    'statssamplerate', '1m'
  ), 'privatekey', 'webextrsa4096',
  'certificate', '-----BEGIN CERTIFICATE-----
MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
bGxpem9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9w
bWVudDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9m
b3hzZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMTIzNDQwNFoX
DTI3MDMxOTIzNDQwNFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQG
A1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlv
bjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rl
di5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3Rj
YUBtb3ppbGxhLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMdX
5soUuvWnkVHRHN5BKByrgpuU3QioE8SNT7BwRFeqbOySdvu5ecQAdNUoRbRyFmNB
ety2rQM9qw6y8eSe9fufIgrv1sg/xj7vweLmuC8Ob+zo5/iwRQw4JUdXnDjwX3W0
auh0QRYfxWGK3hVrP9j1zIJk/yRBornCvXTtn8C/hVSE/PWc6CuV8vTcpyj+TPni
Lvulq17NdlX5qgUdn1yougJxnznkwnoIaBYLdAyZJJIUEomiEIxfabjnh8rfSMIw
AqmslrC8F73yo4JrCqJPt1ipggfpO3ZAjlEoTMcTUgyqR8B35GyuywWR0XrkJV7N
A7BM1qNjLb2to0XQSrGyWA7uPw88LuVk2aUPDE5uNK5Kv//+SGChUn2fDZTsjj3J
KY7f39JVwh/nk8ZkApplne8fKPoknW7er2R+rejyBx1+fJjLegKQsATpgKz4LRf4
ct34oWSV6QXrZ/KKW+frWoHncy8C+UnCC3cDBKs272yqOvBoGMQTrF5oMn8i/Rap
gBbBdwysdJXb+buf/+ZS0PUt7avKFIlXqCNZjG3xotBsTuCL5zAoVKoXJW1FwrcZ
pveQuishKWNf9Id+0HaBdDp/vlbrTwXD1zsxfYvYw8wI7NkNO3TQBni5iyG4B1wh
oR+Z5AebWuJqVnsJyjPakNiuhKNsO/xTa4TF/ymfAgMBAAGjggHcMIIB2DAPBgNV
HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAWBgNVHSUBAf8EDDAKBggrBgEF
BQcDAzAdBgNVHQ4EFgQU2LRpqTdeQ1QlBWNA6fYAqHdpSaUwgekGA1UdIwSB4TCB
3oAU2LRpqTdeQ1QlBWNA6fYAqHdpSaWhgcKkgb8wgbwxCzAJBgNVBAYTAlVTMQsw
CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxs
aXpvbSBDb3Jwb3JhdGlvbjEgMB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1l
bnQxGDAWBgNVBAMTD2Rldi5hbW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94
c2VjK2RldmFtb3Jvb3RjYUBtb3ppbGxhLmNvbYIBATBCBglghkgBhvhCAQQENRYz
aHR0cHM6Ly9jb250ZW50LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jcmwu
cGVtME4GCCsGAQUFBwEBBEIwQDA+BggrBgEFBQcwAoYyaHR0cHM6Ly9jb250ZW50
LXNpZ25hdHVyZS5kZXYubW96YXdzLm5ldC9jYS9jYS5wZW0wDQYJKoZIhvcNAQEL
BQADggIBALqVt54WTkxD5U5fHPRUSZA9rFigoIcrHNrq+gTDd057cBDUWNc0cEHV
qaP0zgzqD2bIhV/WWlfMDY3VnB8L2+Vjvu2CEt8/9Kh5x9IgBmZt5VUMuEdmQOyH
vA7lz3UI+jmUGcojtLsi+sf4kxDZh3QB3T/wGiHg+K7vXnY7GWEy1Cjfwk/dvbT2
ODTb5B3SPGsh75VmfzFGgerzsS71LN4FYBRUklLe8ozqKF8r/jGE2vfDR1Cy09pN
oR9ti+zaBiEtMlWJjxYrv7HvuoDR9xLmPxyV6gQbo6NnbudkpNdg5LhbY3WV1IgL
TnwJ7aHXgzOZ3w/VsSctg4beZZgYnr81vLKyefWJH1VzCe5XTgwXC1R/afGiVJ0P
hA1+T4My9oTaQBsiNYA2keXKJbTKerMTupoLgV/lJjxfF5BfQiy9NL18/bzxqf+J
7w4P/4oHt3QCdISAIhlG4ttXfRR8oz6obAb6QYdCf3x9b2/3UXKd3UJ+gwchPjj6
InnLK8ig9scn4opVNkBkjlMRsq1yd017eQzLSirpKj3br69qyLoyb/nPNJi7bL1K
bf6m5mF5GmKR+Glvq74O8rLQZ3a75v6H+NwOqAlZnWSJmC84R2HHsHPBw+2pExJT
E5bRcttRlhEdN4NJ2vWJnOH0DENHy6TEwACINJVx6ftucfPfvOxI
-----END CERTIFICATE-----
'), null),
('softhsm-hsm-extensions-ecdsa', 'xpi', 'extension', jsonb_build_object(
  'privatekey', 'ext-ecdsa-p384',
  'certificate', '-----BEGIN CERTIFICATE-----
MIIEaDCCA+6gAwIBAgIBATAKBggqhkjOPQQDAjCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tMB4XDTE3MDMyMjExNDg0MFoXDTI3
MDMyMDExNDg0MFowgbwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UE
BxMNTW91bnRhaW4gVmlldzEcMBoGA1UEChMTQWxsaXpvbSBDb3Jwb3JhdGlvbjEg
MB4GA1UECxMXQWxsaXpvbSBBTU8gRGV2ZWxvcG1lbnQxGDAWBgNVBAMTD2Rldi5h
bW8ucm9vdC5jYTEuMCwGCSqGSIb3DQEJARYfZm94c2VjK2RldmFtb3Jvb3RjYUBt
b3ppbGxhLmNvbTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD0rcBU0tirO38TeyZXU
4jz+2v2ngib0I7ABJ4dQg5ZEfC7nW1HvgbKowwjxqPJnpB+W+RUcnsdspj91uwv9
RW22eGPLY8Oot7cgULitIXpBJ1ChHTCMWkzQ/C3jBYAoe6OCAcAwggG8MA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMBYGA1UdJQEB/wQMMAoGCCsGAQUF
BwMDMB0GA1UdDgQWBBQoV8bn7ADMjKLF9XAIwDeEdqn8bDCB6QYDVR0jBIHhMIHe
gBQoV8bn7ADMjKLF9XAIwDeEdqn8bKGBwqSBvzCBvDELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNBbGxp
em9tIENvcnBvcmF0aW9uMSAwHgYDVQQLExdBbGxpem9tIEFNTyBEZXZlbG9wbWVu
dDEYMBYGA1UEAxMPZGV2LmFtby5yb290LmNhMS4wLAYJKoZIhvcNAQkBFh9mb3hz
ZWMrZGV2YW1vcm9vdGNhQG1vemlsbGEuY29tggEBMDQGCWCGSAGG+EIBBAQnFiVo
dHRwczovL2Ftby5kZXYubW96YXdzLm5ldC9jYS9jcmwucGVtMEAGCCsGAQUFBwEB
BDQwMjAwBggrBgEFBQcwAoYkaHR0cHM6Ly9hbW8uZGV2Lm1vemF3cy5uZXQvY2Ev
Y2EucGVtMAoGCCqGSM49BAMCA2gAMGUCMH/W3TjLf0giza8y83S0f4i21b1hSxEv
DZ0QKXuha63GeB4qNOcqqE0Zh7ttWhZ2lQIxANlADi6ZTdDtByJL/QKbk9hKGJCE
wMlTLnlLg0nhVXAEq2SRaF7Tx/v4Ny9kuR7p5A==
-----END CERTIFICATE-----
'), null),
('softhsm-normandy', 'contentsignaturepki', null, jsonb_build_object(
  'validity', '708h',
  'clockskewtolerance', '10m',
  'chainlocation', '/tmp/chains/',
  'x5u', 'file:///tmp/chains/',
  'issuerprivkey', '${NORMANDY_IS_PRIV_KEY}',
  'issuercert', '${NORMANDY_IS_CERT}',
  'cacert', '${NORMANDY_CA_CERT}'), null),
('softhsm-kinto', 'contentsignaturepki', null, jsonb_build_object(
  'validity', '708h',
  'clockskewtolerance', '10m',
  'chainlocation', '/tmp/chains/',
  'x5u', 'file:///tmp/chains/',
  'issuerprivkey', '${KINTO_IS_PRIV_KEY}',
  'issuercert', '${KINTO_IS_CERT}',
  'cacert', '${KINTO_CA_CERT}'), null),
('softhsm-hsm-extensions-ecdsa-expired-chain', 'xpi', 'extension', jsonb_build_object(
  'privatekey', 'ext-ecdsa-p384-2',
  'certificate', '-----BEGIN CERTIFICATE-----
MIICaTCCAfCgAwIBAgIIFpJZf/0ls9swCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNjI2NDYwODIxMB4XDTE5MDYxNDE4
NDAyMVoXDTIxMDExNDE4NDAyMVowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
VQQDExFjc2ludGVyMTYyNjQ2MDgyMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABDw3
+rbWEmoolOex/o83sErQIFzfiUk3rHH1jsjc6Y3JYApiS4kEi/9W6GB170eLevQX
tZlSzR/tQHZ9ckh5TdHDGCqzSW1bQS/Ve6GVBlIMLlL8Odvaiqs8bLtjXoLhb6N4
MHYwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFKEbMQtSCbmKeI0S0AFyN+MUq7WRMB8GA1UdIwQY
MBaAFIMp+z7aIARHJQK6dnqO46cgLFvqMAoGCCqGSM49BAMDA2cAMGQCMF8GvKhZ
9w7E9UEAo23EeImZGDXWP1BPQzLcKJEHNIxd/bBwvQcj4BAsE3xgWEbjCQIwGqed
v+d1uifbc8/SgGVWazxyofFhpRik7UJk5Hz4hebIwm08HT8FYFHvH+d2xIXw
-----END CERTIFICATE-----
'), null)
ON CONFLICT(id) DO UPDATE
SET public = EXCLUDED.public;

INSERT INTO auth(id, key)
VALUES('softhsm-alice', 'fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu')
ON CONFLICT DO NOTHING;

INSERT INTO auth_signers(auth, signer)
VALUES('softhsm-alice', 'softhsm-testmar'),
('softhsm-alice', 'softhsm-testmar2'),
('softhsm-alice', 'softhsm-testmarecdsa'),
('softhsm-alice', 'softhsm-testcsp384'),
('softhsm-alice', 'softhsm-hsm-webextensions-rsa'),
('softhsm-alice', 'softhsm-hsm-extensions-ecdsa'),
('softhsm-alice', 'softhsm-normandy'),
('softhsm-alice', 'softhsm-kinto'),
('softhsm-alice', 'softhsm-hsm-extensions-ecdsa-expired-chain')
ON CONFLICT DO NOTHING;

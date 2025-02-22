package main

// autographDevRootHashes is the SHA2 hashes of the cacerts in the
// autograph dev config:
// https://github.com/mozilla-services/autograph/blob/b3081068f4a9c0c1de02150432f2d02887dd6722/autograph.yaml#L113-L126
// used on the normandy and remote settings development servers
var firefoxPkiLocalDevRoots = []string{
	`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`,
}

var firefoxPkiDevRoots = []string{
	`-----BEGIN CERTIFICATE-----
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
F6GWD+a2U1ugVg==
-----END CERTIFICATE-----
`}

// firefoxPkiStageRoots is the list of CA root certs for the Addon stage code
// signing PKI
var firefoxPkiStageRoots = []string{
	// cas_new, currently used root cert
	`-----BEGIN CERTIFICATE-----
MIIGRDCCBCygAwIBAgIBATANBgkqhkiG9w0BAQwFADBzMQswCQYDVQQGEwJVUzEc
MBoGA1UECgwTTW96aWxsYSBDb3Jwb3JhdGlvbjEoMCYGA1UECwwfTW96aWxsYSBT
dGFnaW5nIFNpZ25pbmcgU2VydmljZTEcMBoGA1UEAwwTY2FzLXJvb3QtY2Etc3Rh
Z2luZzAgFw0yNDAyMTIwMDAwMDBaGA8yMDUwMTIzMTAwMDAwMFowczELMAkGA1UE
BhMCVVMxHDAaBgNVBAoME01vemlsbGEgQ29ycG9yYXRpb24xKDAmBgNVBAsMH01v
emlsbGEgU3RhZ2luZyBTaWduaW5nIFNlcnZpY2UxHDAaBgNVBAMME2Nhcy1yb290
LWNhLXN0YWdpbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJLI7O
heP24t+vR/afP2U80Os1UQIVWmZLd4Z9/ybt9NaXzeCqCd5uV7lpNCvYZLjw57xN
0ZrQiuTw1lAf5IgLKFkjWIWU6YbagQKxX8zGzZ1t8IpvXlP5Qo0kPkYHyJ6FB1GW
JKiHlj0tqDpvfb7oooImsdRvw2lhvXa9m8ttFnUS69Wf9Xh14hSb+Cqg5HfHxBkB
Z/UcrYeOlq5fkxkrTjrCa+XH2942+ZzcWHSjOF3Sf2/gMug1Dc01ORVbloz5e7AI
fdA9Ng9DSjUffCaiTvYqz8f8wZ3gYTd6R8oFfo5Y8y2hjPxPHsTsYaiVvwdx8VBZ
1CBvAGbK4PQHPa4nboJhIuL1JDUhZJAOy/4i2pzn77ce1399CrSLfBzGc6ZWmJ4a
aoG2wdybiGahMasAYf8M+EWlhcnr0YUjnHDWZ50jJ8D62O+SLMRLyWYmZRfYhOHf
3Ed4db1tO2xGDrwoSncbBt706zyBZcNwd1lC21j+cjIDHEmnvv22Csq9KKqMbyd6
v76Ils02uWl63EWlXVbnbNrWW2u+7YvrxZ5DK/GZZIorFZuOzoaFH4VUZ5waxofi
tCN2C7W/QiejqnXUPZQgNQU48aOq3JlvoiwvVFxoejmfw/6EiAMyuE6Tx2odKFBS
1+3EKHpn/AWc2yAos3NfFUhDo3vxonuYwbSlxwIDAQABo4HgMIHdMAwGA1UdEwQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0G
A1UdDgQWBBRnHYjw7dUlrInD0HrEGq1KNJYA9jCBhQYDVR0jBH4wfKF3pHUwczEL
MAkGA1UEBhMCVVMxHDAaBgNVBAoME01vemlsbGEgQ29ycG9yYXRpb24xKDAmBgNV
BAsMH01vemlsbGEgU3RhZ2luZyBTaWduaW5nIFNlcnZpY2UxHDAaBgNVBAMME2Nh
cy1yb290LWNhLXN0YWdpbmeCAQEwDQYJKoZIhvcNAQEMBQADggIBABOMi2kAbJRG
kvGjSeeQXKiXNO/dfLadYG938kl/Xagc7eGWvccHeTPBT7lkiQQko9ucXe4pMzOD
YGyBZyeMc3uFFqjsT9gg/r4KyitxE987qqPS0cjG1up72UyhfNUBgBxCCx0QrRpZ
AbuOAuoTg9tE2uLdqBIemWHHBl/DXKYpmfOd9d6DPI1zxxLp/EegC/mEmiCysA20
wBy/dbK6uhQ+gjqaImjclejaAg07b2HR1HiXNNDdCqL3KE///stTkFCrTq9CFU74
ZdAiCEPSDYU2Qag/jUgzxqNrsPNjA9CkseCezmaNiU28zuEX8xbbhKxoyagAA4mS
lVza5TRvfBo2jbnBFpgfChplDTTfK653k5MF6Q5rPiz4guNqylzq9ZqxGbPGKQbz
0K7PqwKAQTWQ/lo85Q8MFVOSgFeMNOYv6ak+N3QXEpzEtMs1Ta5i9Pla4ia+ZZi8
4lhd/mblxrq8QcpQmrHgXjb/Kpm5BbKnJYUIYidEfW1BMktsPZVbDc0ePa8hu6oZ
Pafl5Rch9rAxeaMFOgYMeOJwlRCt2Fbm+mtnWKFdxy9Peib75pXQD43qYbnK8ucj
xNCR3VBsgIgAhyO11hXiBo5nX5OHn2PG1MPV9+H0RQb6g5zOuKrWoh9CzB8mBl7d
0JMkzy6TFAcAo3KL5ZNvRqqB8xRmIYLK
-----END CERTIFICATE-----`,
	// cas_cur, previous root cert
	`-----BEGIN CERTIFICATE-----
MIIGQjCCBCqgAwIBAgIBATANBgkqhkiG9w0BAQwFADBzMQswCQYDVQQGEwJVUzEc
MBoGA1UECgwTTW96aWxsYSBDb3Jwb3JhdGlvbjEoMCYGA1UECwwfTW96aWxsYSBT
dGFnaW5nIFNpZ25pbmcgU2VydmljZTEcMBoGA1UEAwwTY2FzLXJvb3QtY2Etc3Rh
Z2luZzAeFw0yNDAyMTIwMDAwMDBaFw0yNTAzMTQwMDAwMDBaMHMxCzAJBgNVBAYT
AlVTMRwwGgYDVQQKDBNNb3ppbGxhIENvcnBvcmF0aW9uMSgwJgYDVQQLDB9Nb3pp
bGxhIFN0YWdpbmcgU2lnbmluZyBTZXJ2aWNlMRwwGgYDVQQDDBNjYXMtcm9vdC1j
YS1zdGFnaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAySyOzoXj
9uLfr0f2nz9lPNDrNVECFVpmS3eGff8m7fTWl83gqgneble5aTQr2GS48Oe8TdGa
0Irk8NZQH+SICyhZI1iFlOmG2oECsV/Mxs2dbfCKb15T+UKNJD5GB8iehQdRliSo
h5Y9Lag6b32+6KKCJrHUb8NpYb12vZvLbRZ1EuvVn/V4deIUm/gqoOR3x8QZAWf1
HK2HjpauX5MZK046wmvlx9veNvmc3Fh0ozhd0n9v4DLoNQ3NNTkVW5aM+XuwCH3Q
PTYPQ0o1H3wmok72Ks/H/MGd4GE3ekfKBX6OWPMtoYz8Tx7E7GGolb8HcfFQWdQg
bwBmyuD0Bz2uJ26CYSLi9SQ1IWSQDsv+Itqc5++3Htd/fQq0i3wcxnOmVpieGmqB
tsHcm4hmoTGrAGH/DPhFpYXJ69GFI5xw1medIyfA+tjvkizES8lmJmUX2ITh39xH
eHW9bTtsRg68KEp3Gwbe9Os8gWXDcHdZQttY/nIyAxxJp779tgrKvSiqjG8ner++
iJbNNrlpetxFpV1W52za1ltrvu2L68WeQyvxmWSKKxWbjs6GhR+FVGecGsaH4rQj
dgu1v0Ino6p11D2UIDUFOPGjqtyZb6IsL1RcaHo5n8P+hIgDMrhOk8dqHShQUtft
xCh6Z/wFnNsgKLNzXxVIQ6N78aJ7mMG0pccCAwEAAaOB4DCB3TAMBgNVHRMEBTAD
AQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNV
HQ4EFgQUZx2I8O3VJayJw9B6xBqtSjSWAPYwgYUGA1UdIwR+MHyhd6R1MHMxCzAJ
BgNVBAYTAlVTMRwwGgYDVQQKDBNNb3ppbGxhIENvcnBvcmF0aW9uMSgwJgYDVQQL
DB9Nb3ppbGxhIFN0YWdpbmcgU2lnbmluZyBTZXJ2aWNlMRwwGgYDVQQDDBNjYXMt
cm9vdC1jYS1zdGFnaW5nggEBMA0GCSqGSIb3DQEBDAUAA4ICAQAiB/P5TTOXnEbd
uL9WEG+Ft968oLn6hmCbxxA6pI88R3/TS4iYkSe6H74egohMG9EOCDOt8H4DSD9W
9EVrtsGBE1MI4bXheJKGfdAOP47qPU0boenx6dFegUkztJoL5RyGAvI2afYBqutY
B6RTf7nMVEyEJOa3uWMHixW+Vcgx6mvXLj5t/pEJp3qJiOyf0IopZ3VOOUu31A65
VwR2sAo53XgfJoNOjLsfov9H93LV7yNkk62xEGGvC+cEwqGJIUY3fNHiaJ/cgcep
DiGCwnwq8yCOdHAsrfwwpkfAVX0s+znL1zsk/HG3N28pdarshrKtYFf7+pSTqlnq
5SmFEtpz5NpcyIRXaWoWSPAJ55uy883YotSnXZMwx0Saaqc5hR5zyi0x8ZGxNFT+
DA1IPtdwpScnxOSw3pISJjKBhchI2un1SXroLv2WoTmAhGdBJkJ+Il+T2rfv5Y4b
vM5rHPBNZPlLfco0mCss4JE66br6U6RShC1B5A9kS1fhqk993+yfRZLaLr1JEEnI
mdIvStTVH+eKQ285IY5QTnWtBxmjWoG7/aPNRr62HpSdbjMykcianWk/41Wie/99
wXRYB9M6EjXxXUcv85sQ0IFCqf75RfqYBCYtx9RBZdQPOIDcXLTJXoNU1BC2BDjz
s2UjFKLy1yGxr/gxHq0AfYZa6ptlXw==
-----END CERTIFICATE-----`,
	// old root cert
	`-----BEGIN CERTIFICATE-----
MIIHYzCCBUugAwIBAgIBATANBgkqhkiG9w0BAQwFADCBqDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNB
ZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWduaW5n
LnJvb3QuY2ExMDAuBgkqhkiG9w0BCQEWIW9wc2VjK3N0YWdlcm9vdGFkZG9uc0Bt
b3ppbGxhLmNvbTAeFw0xNTAyMTAxNTI4NTFaFw0yNTAyMDcxNTI4NTFaMIGoMQsw
CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE0FkZG9ucyBUZXN0IFNpZ25pbmcxJDAiBgNVBAMTG3Rlc3QuYWRk
b25zLnNpZ25pbmcucm9vdC5jYTEwMC4GCSqGSIb3DQEJARYhb3BzZWMrc3RhZ2Vy
b290YWRkb25zQG1vemlsbGEuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAv/OSHh5uUMMKKuBh83kikuJ+BW4fQCHVZvADZh2qHNH8pSaME/YqMItP
5XQ1N5oLq1tRQO77AKn+eYPDAQkg+9VV+ct4u76YctcU/gvjieGKQ0fvuDH18QLD
hqa4DHgDmpCa/w+Eqzd54HaFj7ew9Bb7GZPHuZfk7Ct9fcN6kHneEj3KeuLiqzSV
VCRFV9RTlrUdsc1/VwF4A97JTXc3HJeWJO3azOlFpaJ8QHhmgXLLmB59HPeZ10Sf
9QwVGaKcn7yLuwtIA+wDhs8iwGZWcgmknW4DkkRDbQo7L+//4kVK+Yqq0HamZArm
vE4xENvbwOze4XYkCO3PwgmCotU7K5D3sMUUxkOaodlemO9OqRW8vJOJH3b6mhST
aunQR9/GOJ7sl4egrn2fOVZhBvM29lyBCKBffeQgtIMcKpeEKa4TNx4nTrWu1J9k
jHlvNeVL3FzMzJXRPl0RV71cYak+G6GnQ4fg3+4ZSSPxTvbwRJAO2xajkURxFSZo
sXcjYG8iPTSrDazj4LN2+882t4Q2/rMYpkowwLGbvJqHiw2tg9/hpLn1K4W18vcC
vFgzNRrTdKaJ/KjD17eJl8s8oPA7TiophPeezy1WzAc4mdlXS6A85b0mKDDU2A/4
3YmltjsSmizR2LnfeNs125EsCWxSUrAsnUYRO+lJOyNr7GGKGscCAwZVN6OCAZQw
ggGQMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB/wQMMAoG
CCsGAQUFBwMDMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0
aWZpY2F0ZTAzBglghkgBhvhCAQQEJhYkaHR0cDovL2FkZG9ucy5tb3ppbGxhLm9y
Zy9jYS9jcmwucGVtMB0GA1UdDgQWBBSE6l/Nb0ySL+rR9PXIo7LCDLqm9jCB1QYD
VR0jBIHNMIHKgBSE6l/Nb0ySL+rR9PXIo7LCDLqm9qGBrqSBqzCBqDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYD
VQQKExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5z
aWduaW5nLnJvb3QuY2ExMDAuBgkqhkiG9w0BCQEWIW9wc2VjK3N0YWdlcm9vdGFk
ZG9uc0Btb3ppbGxhLmNvbYIBATANBgkqhkiG9w0BAQwFAAOCAgEAck21RaAcTzbT
vmqqcCezBd5Gej6jV53HItXfF06tLLzAxKIU1loLH/330xDdOGyiJdvUATDVn8q6
5v4Kae2awON6ytWZp9b0sRdtlLsRo8EWOoRszCqiMWdl1gnGMaV7e2ycz/tR+PoK
GxHCh8rbOtG0eiVJIyRijLDjtExW8Eg+uz6Zkg1IWXqInj7Gqr23FOqD76uAfE82
YTWW3lzxpP3gL7pmV5G7ob/tIyAfrPEB4w0Nt2HEl9h7NDtKPMprrOLPkrI9eAVU
QeeI3RpAKnXOFQkqPYPXIlAaJ6qxtYa6tWHOqRyS1xKnvy/uWjEtU3tYJ5eUL1+2
vzNTdakJgkZDRdDNg0V3NYwza6BwL80VPSfqc1H6R8CU1uj+kjTlCEsoTPLeW7k5
t+lKHFMj0HZLNymgDD5f9UpI7yiOAIF0z4WKAMv/f12vnAPwmOPuOikRNOv0nNuL
RIpKO53Cd7aV5PdB0pNSPNjc6V+5IPrepALNQhKIpzoHA4oG+LlVVy4R3csPcj4e
zQQ9gt3NC2OXF4hveHfKZdCnb+BBl4S71QMYYCCTe+EDCsIGuyXWD/K2hfLD8TPW
thPX5WNsS8bwno2ccqncVLQ4PZxOIB83DFBFmAvTuBiAYWq874rneTXqInHyeCq+
819l9s72pDsFaGevmm0Us9bYuufTS5U=
-----END CERTIFICATE-----`,
	// previous content signing root cert
	`-----BEGIN CERTIFICATE-----
MIIHbDCCBVSgAwIBAgIEYCWYOzANBgkqhkiG9w0BAQwFADCBqTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRwwGgYDVQQK
ExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0LmFkZG9ucy5zaWdu
aW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytzdGFnZXJvb3RhZGRv
bnNAbW96aWxsYS5jb20wHhcNMjEwMjExMjA0ODU5WhcNMjQxMTE0MjA0ODU5WjCB
qTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBW
aWV3MRwwGgYDVQQKExNBZGRvbnMgVGVzdCBTaWduaW5nMSQwIgYDVQQDExt0ZXN0
LmFkZG9ucy5zaWduaW5nLnJvb3QuY2ExMTAvBgkqhkiG9w0BCQEWInNlY29wcytz
dGFnZXJvb3RhZGRvbnNAbW96aWxsYS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDKRVty/FRsO4Ech6EYleyaKgAueaLYfMSsAIyPC/N8n/P8QcH8
rjoiMJrKHRlqiJmMBSmjUZVzZAP0XJku0orLKWPKq7cATt+xhGY/RJtOzenMMsr5
eN02V3GzUd1jOShUpERjzXdaO3pnfZqhdqNYqP9ocqQpyno7bZ3FZQ2vei+bF52k
51uPioTZo+1zduoR/rT01twGtZm3QpcwU4mO74ysyxxgqEy3kpojq8Nt6haDwzrj
khV9M6DGPLHZD71QaUiz5lOhD9CS8x0uqXhBhwMUBBkHsUDSxbN4ZhjDDWpCmwaD
OtbJMUJxDGPCr9qj49QESccb367OeXLrfZ2Ntu/US2Bw9EDfhyNsXr9dg9NHj5yf
4sDUqBHG0W8zaUvJx5T2Ivwtno1YZLyJwQW5pWeWn8bEmpQKD2KS/3y2UjlDg+YM
NdNASjFe0fh6I5NCFYmFWA73DpDGlUx0BtQQU/eZQJ+oLOTLzp8d3dvenTBVnKF+
uwEmoNfZwc4TTWJOhLgwxA4uK+Paaqo4Ap2RGS2ZmVkPxmroB3gL5n3k3QEXvULh
7v8Psk4+MuNWnxudrPkN38MGJo7ju7gDOO8h1jLD4tdfuAqbtQLduLXzT4DJPA4y
JBTFIRMIpMqP9CovaS8VPtMFLTrYlFh9UnEGpCeLPanJr+VEj7ae5sc8YwIDAQAB
o4IBmDCCAZQwDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwMwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVk
IENlcnRpZmljYXRlMDMGCWCGSAGG+EIBBAQmFiRodHRwOi8vYWRkb25zLm1vemls
bGEub3JnL2NhL2NybC5wZW0wHQYDVR0OBBYEFIbYNBxOWNETXJlf2EKY7RQPGfJd
MIHZBgNVHSMEgdEwgc6AFIbYNBxOWNETXJlf2EKY7RQPGfJdoYGvpIGsMIGpMQsw
CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcx
HDAaBgNVBAoTE0FkZG9ucyBUZXN0IFNpZ25pbmcxJDAiBgNVBAMTG3Rlc3QuYWRk
b25zLnNpZ25pbmcucm9vdC5jYTExMC8GCSqGSIb3DQEJARYic2Vjb3BzK3N0YWdl
cm9vdGFkZG9uc0Btb3ppbGxhLmNvbYIEYCWYOzANBgkqhkiG9w0BAQwFAAOCAgEA
nowyJv8UaIV7NA0B3wkWratq6FgA1s/PzetG/ZKZDIW5YtfUvvyy72HDAwgKbtap
Eog6zGI4L86K0UGUAC32fBjE5lWYEgsxNM5VWlQjbgTG0dc3dYiufxfDFeMbAPmD
DzpIgN3jHW2uRqa/MJ+egHhv7kGFL68uVLboqk/qHr+SOCc1LNeSMCuQqvHwwM0+
AU1GxhzBWDkealTS34FpVxF4sT5sKLODdIS5HXJr2COHHfYkw2SW/Sfpt6fsOwaF
2iiDaK4LPWHWhhIYa6yaynJ+6O6KPlpvKYCChaTOVdc+ikyeiSO6AakJykr5Gy7d
PkkK7MDCxuY6psHj7iJQ59YK7ujQB8QYdzuXBuLLo5hc5gBcq3PJs0fLT2YFcQHA
dj+olGaDn38T0WI8ycWaFhQfKwATeLWfiQepr8JfoNlC2vvSDzGUGfdAfZfsJJZ8
5xZxahHoTFGS0mDRfXqzKH5uD578GgjOZp0fULmzkcjWsgzdpDhadGjExRZFKlAy
iKv8cXTONrGY0fyBDKennuX0uAca3V0Qm6v2VRp+7wG/pywWwc5n+04qgxTQPxgO
6pPB9UUsNbaLMDR5QPYAWrNhqJ7B07XqIYJZSwGP5xB9NqUZLF4z+AOMYgWtDpmg
IKdcFKAt3fFrpyMhlfIKkLfmm0iDjmfmIXbDGBJw9SE=
-----END CERTIFICATE-----`,
}

// firefoxPkiProdRoots are the CA root certs for the Content Signature
// and Addon prod code signing PKI
var firefoxPkiProdRoots = []string{
	`-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`,
	`-----BEGIN CERTIFICATE-----
MIIGZTCCBE2gAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wIhgPMjAyNDAyMDEwMDAwMDBaGA8yMjAwMTIwMzAwMDAw
MFowfTELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24x
LzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNl
MR8wHQYDVQQDExZyb290LWNhLXByb2R1Y3Rpb24tYW1vMIICIDANBgkqhkiG9w0B
AQEFAAOCAg0AMIICCAKCAgEAtLth11268Mt+vjD3in+Y4KAEjHzDc+5iVgXnCYL5
U3+IRyWy8zD7CFGrsyPRhKS3x3WesM0shTm+ADPg9ZsQFobmSdzAwCTn9wdUbOkK
Kx65fKqpTbTxqnqZ6TSXC6OybEqqhNzVJu9jIKiB0YE0bKlLPuyyDxnu9utlPjf0
9Cz2FS3uK2dkQx6GmYWGO2vfuPZhziP4NmBQfvcmYxPl3aZU9pAYAOD/HW+4uyNL
SIuG9AdDesvTIS/gkWScsXRXtsAcpCV9eC7IXirDNWsx42Tuekija1vFQCUy5KUc
QprIk69PH5z8gypmnmdAbbLoInHYqXGaV64iBprGWyNdqucrsI0hC3ZA1elGo6Np
/tsLObl6z9+Nl+9VoloQv3ReXc9SyrYwXZlJMWkDDj/7obVxCga2aNaLpw0UMdY+
/kpEOARMIwd0hLa+1w1hjnDiJKCWVjwAnwSwtzyQgVo0wMgZbndAuZ9wsva3oAAJ
ziKiNbdehlNpWkYe3pSe4D0TYEIMC13mXBccOsL8ohHJgozhEOjzPFEI7YTrCpbM
zIZSsL48jhg6M7ZKkgcv7/gLMezltkO65VXymqy9JkRGXUjH6Mt804LTFQjNL4TZ
es3L3+RzTaKaBHYOcrl6NnIWdadSfqvOm9BuciUTHk9vojlWNhEN+7R66lFEZ3As
uLsCAQOjge0wgeowDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwFgYDVR0l
AQH/BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFLO86lh0q+FueCqyq5wjHqhjLJe3
MIGSBgNVHSMEgYowgYehgYGkfzB9MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96
aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlv
biBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1h
bW+CAQEwDQYJKoZIhvcNAQEMBQADggIBAAAJuN23qDiyAZ8y9DhqTfIfdYBXC7jg
f7p5DNCj6mcfLxCMLuSvLljYWm0IfHYs5W0lnQgm8+N0m3SAjQd18AzWfXNklFjZ
1EcP8MRU/keFEk9SmeHZhP916jQfqQvB45w4QwPcJG0nPkWsYzceqD3uL5g2g4Jg
gk+WYWmtE4eeM2BX6cT0itMErYKWei3SF09TdrCX+XpHMixg4nnDdsGe9wxc8F/o
diQ48f/7AZo06moMyZvIH4PPcVt0osAU18fLO0RrVJkupMraxbM1XXL1UwJlyV+p
kvJutX2xBB1f1BA3xPl3NlQneaLIm3JFsw0r7t0z0n1shC6xCi4+t3Fh6Z38CnbS
WwAe5rA2OCQYMjsehxRK9BhmDCG8U65GVd9t8nV4iEJFTrjntBDEFtVD5s4Qnlyv
OUrWd2du4dLCs+WW2E6+R7jZtrsIqFD6qwCLqcgBgC9CM9UgHeUBOixmZLBKCNDE
N1sRkmcVwXcCl5btdgVVq74Mgsd38xsmYuFoMi6nbDLllm6T2ql8LZExyX2i/vo0
pxhEVRaFwj1J1r3TRNXksjdqFcgpNCMf2FRbjDGtVLXRVG0DCCGRayigKgdH78qM
HpdXrbaTDFsfMLTAMnGFnqOZMuMobNJS5M6/vqdepoC8L7xmI5dQgW8YGyymr8DP
gchMof0tylgn
-----END CERTIFICATE-----
`,
}

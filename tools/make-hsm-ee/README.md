Make an end-entity in the HSM
=============================

To create an end-entity certificate for content signature with an intermediate
key stored in the hsm, use this little helper.

Use `-c` to provide an issuer parent certificate for the generated EE cert.

It works with softhsm and you can set the -p, -t and -s values to use cloudhsm.

```bash
$ go run make-hsm-ee.go -i csinter1555704936 -a normandy
2019/04/19 16:28:35 Using HSM on slot 1623786617
-----BEGIN CERTIFICATE-----
MIIC1DCCAlmgAwIBAgIIFZb6GxhoICAwCgYIKoZIzj0EAwMwgaIxCzAJBgNVBAYT
AlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3
MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcwFQYDVQQLEw5DbG91ZCBT
ZXJ2aWNlczEvMC0GA1UEAxMmbm9ybWFuZHkuY29udGVudC1zaWduYXR1cmUubW96
aWxsYS5vcmcwHhcNMTkwMzIwMjAyODM1WhcNMTkwNjE4MjAyODM1WjCBojELMAkG
A1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWlu
IFZpZXcxHDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xFzAVBgNVBAsTDkNs
b3VkIFNlcnZpY2VzMS8wLQYDVQQDEyZub3JtYW5keS5jb250ZW50LXNpZ25hdHVy
ZS5tb3ppbGxhLm9yZzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJOSQISLw0HYtOr7
T7IlHFZ+w6A/S4sOVlu4kcIrKvvAF0brxjmep4hy3Om/uw0CmoqEjdl+Nz3cE/1a
5DtRg6r2HDyL22nsTVqZoKrp1wwDGgXyYbh9V8oiUFf/M9iMqqNaMFgwDgYDVR0P
AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMDEGA1UdEQQqMCiCJm5vcm1h
bmR5LmNvbnRlbnQtc2lnbmF0dXJlLm1vemlsbGEub3JnMAoGCCqGSM49BAMDA2kA
MGYCMQC8uYmh4IlervdE3jR+4/6C5Ule1y1HDOwCW+unWkcD0vbrqOR6k8S32xys
OeamUrQCMQCXq9qX1fValotzEqhdPKW4iypbyee7H6wRmrMksBLhDubXsgkpBaIv
xuPik9soVSs=
-----END CERTIFICATE-----

-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDmqnXXKxUYAyQuIIucyB4HslkRbfI2tEF4djRZDSnaA4W8t62WF1ax
4dcNFAgo4smgBwYFK4EEACKhZANiAASTkkCEi8NB2LTq+0+yJRxWfsOgP0uLDlZb
uJHCKyr7wBdG68Y5nqeIctzpv7sNApqKhI3Zfjc93BP9WuQ7UYOq9hw8i9tp7E1a
maCq6dcMAxoF8mG4fVfKIlBX/zPYjKo=
-----END EC PRIVATE KEY-----
```

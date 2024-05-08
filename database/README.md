
This directory contains:

* golang source and test files for connecting and querying a postgresql DB
* a Dockerfile to setup a test database for CI and local development
* key and cert files for the development docker DB root CA and server

The key, CSR, and cert files were generated per the "To create a server certificate whose identity can be validated by clients, first create a certificate signing request (CSR) and a public/private key file:" section of https://www.postgresql.org/docs/11/ssl-tcp.html#SSL-CERTIFICATE-CREATION with the `docker compose` CN of `db` i.e.

```console
» openssl req -new -nodes -text -out root.csr -keyout root.key -subj "/CN=db" && chmod og-rwx root.key
Generating a 2048 bit RSA private key
........................+++
......................................................................................+++
writing new private key to 'root.key'
-----
» openssl x509 -req -in root.csr -text -days 3650 -extfile /etc/ssl/openssl.cnf -extensions v3_ca -signkey root.key -out root.crt
Signature ok
subject=CN = db
Getting Private key
» openssl req -new -nodes -text -out server.csr -keyout server.key -subj "/CN=db" && chmod og-rwx server.key
Generating a 2048 bit RSA private key
.................................+++
........+++
writing new private key to 'server.key'
-----
» openssl x509 -req -in server.csr -text -days 365 -CA root.crt -CAkey root.key -CAcreateserial -out server.crt
Signature ok
subject=CN = db
Getting CA Private Key
```

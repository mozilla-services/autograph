#!/bin/bash

# Generate the self-signed root certificate.
if [ ! -f root.key ] || [ ! -f root.crt ]; then
    openssl req -x509 -nodes -out root.crt -keyout root.key \
        -subj "/CN=db-root" -addext "subjectAltName = DNS:db-root"
fi

# Re-use existing server keys, if present.
SERVERKEYARG="-keyout"
if [ -f server.key ]; then 
    SERVERKEYARG="-key"
fi

# Generate the database server certificate.
openssl req -new -nodes -out server.csr ${SERVERKEYARG} server.key \
    -subj "/CN=db" -addext "subjectAltName = DNS:db"
openssl x509 -req -in server.csr -days 3650 -text -out server.crt \
    -CA root.crt -CAkey root.key -copy_extensions copy

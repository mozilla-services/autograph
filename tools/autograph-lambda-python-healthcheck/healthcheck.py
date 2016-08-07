#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from requests_hawk import HawkAuth
import base64
import ecdsa
import hashlib
import json
import requests


def autograph_monitor(event, context):
    inputdata = "AUTOGRAPH MONITORING"
    r = requests.get("http://localhost:8000/__monitor__",
            auth=HawkAuth(
                id="monitor",
                key="19zd4w3xirb5syjgdx8atq6g91m03bdsmzjifs2oddivswlu9qs"
            )
        )
    r.raise_for_status()
    sigresp = json.loads(r.text)

    for sig in sigresp:
        # the public key is converted to regular base64, and loaded
        pubkeystr = un_urlsafe(sig["public_key"])
        vk = ecdsa.VerifyingKey.from_pem(pubkeystr)

        # the signature is b64 decoded to obtain bytes
        sigdata = base64.b64decode(un_urlsafe(sig["signature"].encode("utf-8")))

        hashfunc = None
        if "hash_algorithm" in sig:
            if sig["hash_algorithm"] == "sha384":
                hashfunc = hashlib.sha384
            if sig["hash_algorithm"] == "sha256":
                hashfunc = hashlib.sha256
            if sig["hash_algorithm"] == "sha512":
                hashfunc = hashlib.sha512

        # perform verification
        isgoodsig = False
        hascontentsig = ""
        if hashfunc:
            if "content-signature" in sig:
                hascontentsig = " (content-signature)"
                templatedinput = "Content-Signature:\x00" + inputdata
            else:
                templatedinput = inputdata
            isgoodsig = vk.verify(sigdata,
                    templatedinput,
                    hashfunc=hashfunc,
                    sigdecode=ecdsa.util.sigdecode_string)
        else:
            isgoodsig = vk.verify_digest(sigdata,
                    inputdata,
                    sigdecode=ecdsa.util.sigdecode_string)
        print("%s%s signature validation: %s" % (sig["signer_id"], hascontentsig, isgoodsig))
        if not isgoodsig:
            raise

        # if there's a x5u in the response, retrieve the chain
        # and check the validity of the certificates
        if "x5u" in sig:
            r = requests.get(sig["x5u"])
            r.raise_for_status()
            pos = 0
            raw_certs = []
            raw_cert = ""
            in2weeks = datetime.utcnow() + timedelta(days=15)

            for row in r.text.splitlines():
                raw_cert += str(row) + "\n"
                if row == "-----END CERTIFICATE-----":
                    pos += 1
                    raw_certs.insert(pos, raw_cert)
                    raw_cert = ""

            for raw_cert in raw_certs:
                cert = x509.load_pem_x509_certificate(raw_cert, default_backend())
                print("%s\texpires: %s" % (
                    cert.subject.get_attributes_for_oid(
                        x509.oid.NameOID.COMMON_NAME)[0].value,
                    cert.not_valid_after)
                )
                if cert.not_valid_after < in2weeks:
                    print("Certificate expires soon!")
                    raise


def un_urlsafe(input):
    input = str(input).replace("_", "/")
    input = str(input).replace("-", "+")
    if len(input) % 4 > 0:
        input += "=" * (4 - len(input) % 4)
    return input

if __name__ == '__main__':
    autograph_monitor(None, None)


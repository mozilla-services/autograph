#!/usr/bin/env python

import ecdsa
import json
import hashlib
import base64
import requests
from requests_hawk import HawkAuth


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


def un_urlsafe(input):
    input = str(input).replace("_", "/")
    input = str(input).replace("-", "+")
    if len(input) % 4 > 0:
        input += "=" * (4 - len(input) % 4)
    return input

if __name__ == '__main__':
    autograph_monitor(None, None)


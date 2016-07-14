#!/usr/bin/env python

import ecdsa
import json
import hashlib
import base64
import requests
from requests_hawk import HawkAuth


def autograph_monitor(event, context):
    inputdata = "this is a heartbeat message"
    sigreq = [{
        "input": base64.b64encode(inputdata),
    }]
    r = requests.post("http://ip-172-31-32-24.ec2.internal:8000/sign/data",
            json=sigreq,
            auth=HawkAuth(
                id="alice",
                key="fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu"
            )
        )
    r.raise_for_status()
    sigresp = json.loads(r.text)

    # the public key is converted to regular base64, and loaded
    pubkeystr = un_urlsafe(sigresp[0]["public_key"])
    vk = ecdsa.VerifyingKey.from_pem(pubkeystr)

    # the signature is b64 decoded to obtain bytes
    sigdata = base64.b64decode(un_urlsafe(sigresp[0]["signature"].encode("utf-8")))

    hashfunc = None
    if "hash_algorithm" in sigresp[0]:
        if sigresp[0]["hash_algorithm"] == "sha384":
            hashfunc = hashlib.sha384
        if sigresp[0]["hash_algorithm"] == "sha256":
            hashfunc = hashlib.sha256
        if sigresp[0]["hash_algorithm"] == "sha512":
            hashfunc = hashlib.sha512

    # perform verification
    isgoodsig = False
    if hashfunc:
        isgoodsig = vk.verify(sigdata, 
                inputdata, 
                hashfunc=hashfunc, 
                sigdecode=ecdsa.util.sigdecode_string)
    else:
        isgoodsig = vk.verify_digest(sigdata,
                inputdata,
                sigdecode=ecdsa.util.sigdecode_string)
    print("signature validation: %s" % isgoodsig)
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


#!/usr/bin/env python

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from requests_hawk import HawkAuth
import base64
import ecdsa
import hashlib
import json
import os
import requests
import sops

def autograph_monitor(event, context):
    inputdata = "AUTOGRAPH MONITORING"

    # Get configuration by decrypting the local monitor.autograph.yaml file
    # using sops
    workdir = ""
    key = ""
    if 'LAMBDA_TASK_ROOT' in os.environ:
        workdir = os.environ['LAMBDA_TASK_ROOT'] + "/"
    try:
        path = workdir+"monitor.autograph.yaml"
        pathtype = sops.detect_filetype(path)
        tree = sops.load_file_into_tree(path, pathtype)
        sops_key, tree = sops.get_key(tree)
        tree = sops.walk_and_decrypt(tree, sops_key)
        key = tree.get('monitoringkey')
    except Exception:
        print('Failed to decrypt %s' % path)
        raise

    # call the monitoring endpoint
    r = requests.get("http://localhost:8000/__monitor__",
            auth=HawkAuth(id="monitor", key=key)
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


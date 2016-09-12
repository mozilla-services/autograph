#!/usr/bin/env python

import ecdsa
import json
import hashlib
import base64
import requests
from requests_hawk import HawkAuth
import argparse


def main():
    argparser = argparse.ArgumentParser(
        usage='./client.py [--hashwith <alg>] <inputdata>',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Simple autograph client in Python\n$ python client.py --hashwith sha384 mydatatosign')
    argparser.add_argument('input',
                           help="input string, can be base64, or just raw data")
    argparser.add_argument('--hashwith', dest='hashwith',
                           help="algorithm to hash the input data with (default: none)")
    argparser.add_argument('--template', dest='template',
                           help="template to apply to the data before hashing it (default: None)")
    argparser.add_argument('-u', dest='hawkid', default="alice",
                           help="hawk id (default: alice)")
    argparser.add_argument('-p', dest='hawkkey',
                           default="fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
                           help="hawk key (default: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu)")
    argparser.add_argument('-t', dest='target',
                           default="http://localhost:8000/sign/data",
                           help="signing api URL (default: http://localhost:8000/signature)")
    argparser.add_argument('-e', dest='encoding',
                           default="rs_base64url",
                           help="signature encoding format (default: rs_base64url)")
    args = argparser.parse_args()

    # try to load the input data as base64, and if that fails treat it as raw data instead
    try:
        inputdata = base64.b64decode(args.input)
    except:
        inputdata = args.input

    # build and run the signature request
    sigreq = [{
        "template": args.template,
        "input": base64.b64encode(inputdata),
        "hashwith": args.hashwith,
        "signature_encoding": args.encoding
    }]
    print("signature request: %s" % sigreq)
    r = requests.post(args.target, json=sigreq, auth=HawkAuth(id=args.hawkid, key=args.hawkkey))
    r.raise_for_status()
    print("signature response: %s" % r.text)
    sigresp = json.loads(r.text)

    if args.encoding != "rs_base64url":
        print("unable to verify signature: encoding is %s and I only know rs_base64url" % args.encoding)
        return

    vk = ecdsa.VerifyingKey.from_pem(sigresp[0]["public_key"])

    # the signature is b64 decoded to obtain bytes
    sigdata = base64.urlsafe_b64decode(bytes(sigresp[0]["signature"]))

    hashfunc = None
    hash_algorithm = sigresp[0].get('hash_algorithm')
    if hash_algorithm:
        if hash_algorithm == "sha384":
            hashfunc = hashlib.sha384
        elif hash_algorithm == "sha256":
            hashfunc = hashlib.sha256
        elif hash_algorithm == "sha512":
            hashfunc = hashlib.sha512
        else:
            raise ValueError('Unexpected hash_algorithm "%s"' % hash_algorithm)

    # perform verification
    if hashfunc:
        validation = vk.verify(sigdata, inputdata, hashfunc=hashfunc, sigdecode=ecdsa.util.sigdecode_string)
    else:
        validdation = vk.verify_digest(sigdata, inputdata, sigdecode=ecdsa.util.sigdecode_string)

    print("signature validation: %s", validation)


if __name__ == '__main__':
    main()

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
    argparser.add_argument('-u', dest='hawkid', default="alice",
                           help="hawk id (default: alice)")
    argparser.add_argument('-p', dest='hawkkey',
                           default="fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
                           help="hawk key (default: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu)")
    argparser.add_argument('-t', dest='target',
                           default="http://localhost:8000/signature",
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
        "input": base64.b64encode(inputdata),
        "hashwith": args.hashwith,
        "signature_encoding": args.encoding
    }]
    print("signature request: %s" % sigreq)
    r = requests.post(args.target, json = sigreq, auth = HawkAuth(id=args.hawkid, key=args.hawkkey))
    r.raise_for_status()
    print("signature response: %s" % r.text)
    sigresp = json.loads(r.text)

    if args.encoding != "rs_base64url":
        print("unable to verify signature: encoding is %s and I only know rs_base64url" % args.encoding)
        return

    # the public key is converted to regular base64, and loaded
    pubkeystr = un_urlsafe(sigresp[0]["certificate"]["encryptionkey"])
    vk = ecdsa.VerifyingKey.from_pem(pubkeystr)

    # the signature is b64 decoded to obtain bytes
    sigdata = base64.b64decode(un_urlsafe(sigresp[0]["signatures"][0]["signature"].encode("utf-8")))

    hashfunc = None
    if sigreq[0]["hashwith"] == "sha384":
        hashfunc = hashlib.sha384

    # perform verification
    print("signature validation: %s" % vk.verify(sigdata, inputdata, hashfunc=hashfunc, sigdecode=ecdsa.util.sigdecode_string))

def un_urlsafe(input):
    input = str(input).replace("_", "/")
    input = str(input).replace("-", "+")
    if len(input) % 4 > 0:
        input += "=" * (len(input) % 4)
    return input
  
if __name__ == '__main__':
    main()

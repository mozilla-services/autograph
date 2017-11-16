#!/usr/bin/env python
import argparse
import json
import re
import requests
import shutil
import sys
import tempfile
import zipfile
from base64 import b64encode, b64decode
from requests_hawk import HawkAuth
from signing_clients.apps import JarExtractor


def call_signing(file_path, guid, endpoint, signer, user, key):
    """Get the jar signature and send it to the signing server to be signed."""

    # We only want the (unique) temporary file name.
    with tempfile.NamedTemporaryFile() as temp_file:
        temp_filename = temp_file.name

    # Extract jar signature.
    jar = JarExtractor(path=file_path)
    signed_manifest = jar.signatures

    # create the signing request
    sigreq = [{
        "input": b64encode(bytes(jar.signatures.__str__(), "utf-8")).decode("utf-8"),
        "keyid": signer,
        "options": {
            "id": guid,
        },
    }]

    # post the request
    response = requests.post(endpoint,
                             json=sigreq,
                             auth=HawkAuth(id=user, key=key))

    # convert the base64 encoded pkcs7 signature back to binary
    if response.status_code != 201:
        print('Posting to add-on signing failed: {0}'.format(response.text))
        exit(1)

    sigresp = json.loads(response.text)
    pkcs7 = b64decode(sigresp[0]["signature"])
    jar.make_signed(
        signed_manifest=signed_manifest.__str__(),
        signature=pkcs7,
        sigpath=u'mozilla',
        outpath=temp_filename)
    shutil.move(temp_filename, file_path)

    print("{0} signed!".format(file_path))


def get_guid(file_path):
    """Get e-mail guid of add-on."""
    z = zipfile.ZipFile(file_path)
    zlist = z.namelist()
    if 'install.rdf' in zlist:
        try:
            with z.open('install.rdf') as install:
                match = re.search(r'[\w\.-]+@[\w\.-]+', install.read().decode("utf-8"))
                return match.group(0)
        except:
            print("Failed to get guid from install.rdf:", sys.exc_info()[0])
            exit(1)
    elif 'manifest.json' in zlist:
        try:
            with z.open('manifest.json') as manifest:
                m = json.load(manifest)
                return m['applications']['gecko']['id']
        except:
            print("Failed to get guid from manifest.json:", sys.exc_info()[0])
            exit(1)
    # we didn't find the guid, bail
    else:
        print("Could not find guid, check add-on")
        exit(1)
    print("bar")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="File to sign")
    parser.add_argument("-g", "--guid",
                        help="Override guid",
                        action="store")
    parser.add_argument("-s", "--signer",
                        help="Use a specific signer, not the api default",
                        action="store", required=False)
    parser.add_argument('-t', dest='target',
                        default="http://localhost:8000/sign/data",
                        help="signing api URL (default: http://localhost:8000/sign/data)")
    parser.add_argument('-u', dest='hawkid', default="alice",
                        help="hawk id (default: alice)")
    parser.add_argument('-p', dest='hawkkey',
                        default="fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
                        help="hawk key (default: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu)")

    args = parser.parse_args()

    if args.guid:
        guid = args.guid
    else:
        guid = get_guid(args.filename)

    call_signing(args.filename,
                 guid,
                 args.target,
                 args.signer,
                 args.hawkid,
                 args.hawkkey)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2023-present Hal Wine <hwine@mozilla.com>
#
# SPDX-License-Identifier: Apache-2.0

import csv
import datetime
import hashlib
import sys

import pydantic
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# Prefix to prepend to generated hashes. We hash for 2 reasons:
#   1. to protect secrets, while still allowing equality testing
#   2. to identify large objects for equality testing (e.g. x509 certificate)
safe_prefix = "safe_"

class CertInfo(pydantic.BaseModel):
    pem: str | None
    pem_hash: str | None
    fp_sha1: str | None  # Google Play reports SHA1 of cert, so needed to compare
    fp_sha256: str | None
    date_start: datetime.datetime | None
    date_end: datetime.datetime | None

class Signer(pydantic.BaseModel):
    signer: str     # "id" in yaml, but "signer" in authorizations
    type_: str
    mode: str | None
    # for apks, etc
    private_key: str | None     ### SECRET ###
    certificate: str | None
    # for content signature (type `contentsignaturepki`)
    issuerprivatekey: str | None     ### SECRET ###
    issuercert: str | None
    cacert: str | None
    fp_sha1: str | None
    fp_sha256: str | None
    date_start: str | None
    date_end: str | None

class AuthorizationBase(pydantic.BaseModel):
    # empty super class
    ...


class AuthorizationEdge(AuthorizationBase):
    client_token: str   # this is the API key, so mask     ### SECRET ###
    signer: str
    user_app: str   # this matches the key, which is secret     ### SECRET ###


class AuthorizationApp(AuthorizationBase):
    user_app: str       # this is "id" in yaml, but is effectively the user
    # Signers is an array in the yaml, but I need to expand to multiple rows
    signer: str


def sanitize(secret: str) -> str | None:
    if secret is None:
        # None is None -- don't hash it!
        return None
    return safe_prefix + hashlib.sha256(secret.encode()).hexdigest()

def gather_authorizations_app(doc:dict) -> list[AuthorizationApp]:
    authorizations = []
    if "authorizations" in doc:
        for data in doc["authorizations"]:
            if "client_token" in data:
                assert "id" not in data
                continue
            try:
                id_=str(data.get("id"))        # some ids are numeric
                for signer in [str(x) for x in data.get("signers")]:
                    auth = AuthorizationApp(
                            user_app=id_,
                            signer=signer,
                            )
                    authorizations.append(auth)
            except Exception:
                print(f"choked on {data}")
                raise
    return authorizations


def gather_authorizations_edge(doc:dict) -> list[AuthorizationEdge]:
    authorizations = []
    if "authorizations" in doc:
        for data in doc["authorizations"]:
            if "id" in data:
                assert "client_token" not in data
                continue
            try:
                auth = AuthorizationEdge(
                        client_token=sanitize(data.get("client_token")),
                        signer=data.get("signer"),
                        user_app=data["user"],
                        )
                authorizations.append(auth)
            except Exception:
                print(f"choked on {data}")
                raise
    return authorizations


def extract_cert_info(data: str | None) -> CertInfo:
    if not data:
        cert_info = CertInfo(pem=None, pem_hash=None, fp_sha1=None,
                             fp_sha256=None, date_start=None,
                             date_end=None,)
    else:
        cert = x509.load_pem_x509_certificate(data.encode())
        cert_info = CertInfo(
                pem=data,
                pem_hash=sanitize(data),
                # Format hashes as commonly emitted by other tooling, especially, Google Play UI
                fp_sha1=cert.fingerprint(hashes.SHA1()).hex(sep=":",
                                                            bytes_per_sep=1),
                fp_sha256=cert.fingerprint(hashes.SHA256()).hex(sep=":",
                                                                bytes_per_sep=1),
                date_start=cert.not_valid_before,
                date_end=cert.not_valid_after,
                )
    return cert_info



def gather_signers(doc:dict) -> list[Signer]:
    signers = []
    if "signers" in doc:
        for data in doc["signers"]:
            try:
                cert_info = extract_cert_info(data.get("certificate"))
                signer = Signer(
                        signer=str(data["id"]),        # a few ids are numeric
                        type_=data["type"],
                        mode=data.get("mode"),
                        private_key=sanitize(data.get("privatekey")),
                        certificate=cert_info.pem_hash,
                        issuerprivatekey=data.get("issuerprivatekey"),
                        issuercert=sanitize(data.get("issuercert")),
                        cacert=sanitize(data.get("cacert")),
                        fp_sha1=cert_info.fp_sha1,
                        fp_sha256=cert_info.fp_sha256,
                        date_start=cert_info.date_start and cert_info.date_start.isoformat(),
                        date_end=cert_info.date_end and cert_info.date_end.isoformat(),
                        )
                signers.append(signer)
            except Exception:
                print(f"choked on {data}")
                raise
    return signers

def output_signers(signers: list[Signer]) -> None:
    if not len(signers):
        return
    with open("signers.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile,
                                fieldnames=signers[0].model_dump().keys())
        writer.writeheader()
        for s in signers:
            writer.writerow(s.model_dump())


def output_authorizations(authorizations: list[AuthorizationBase]) -> None:
    if not len(authorizations):
        return
    if isinstance(authorizations[0], AuthorizationApp):
        domain = "app"
    elif isinstance(authorizations[0], AuthorizationEdge):
        domain = "edge"
    else:
        raise TypeError("Unexpected type: " + type(authorizations[0]))
    with open(f"authorizations_{domain}.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile,
                                fieldnames=authorizations[0].model_dump().keys())
        writer.writeheader()
        for a in authorizations:
            writer.writerow(a.model_dump())





def main() -> int:
    """
    main Process decrypted stdin into sanitized CSV

    Read all yaml docs from stdin, as the source is from sops encrypted files.



    Returns:
        int: Unix style exit code
    """

    signers = []
    authorizations_app = []
    authorizations_edge = []
    for doc in yaml.safe_load_all(sys.stdin):
        assert isinstance(doc, dict)
        signers.extend(gather_signers(doc))
        authorizations_app.extend(gather_authorizations_app(doc))
        authorizations_edge.extend(gather_authorizations_edge(doc))

    print(f"found {len(signers)} signers")
    print(f"found {len(authorizations_app)} app authorizations")
    print(f"found {len(authorizations_edge)} edge authorizations")
    output_signers(signers)
    output_authorizations(authorizations_app)
    output_authorizations(authorizations_edge)

    return 0

if __name__ == "__main__":
    sys.exit(main())

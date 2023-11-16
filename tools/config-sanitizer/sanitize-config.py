#!/usr/bin/env python3

import csv
import hashlib
import sys
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes
import pydantic
import yaml

class CertInfo(pydantic.BaseModel):
    pem: str | None
    pem_hash: str | None
    fp_sha1: str | None
    fp_sha256: str | None

class Signer(pydantic.BaseModel):
    id_: str
    type_: str
    mode: str | None
    # for apks, etc
    private_key: str | None
    certificate: str | None
    # for content signature (type `contentsignaturepki`)
    issuerprivatekey: str | None
    issuercert: str | None
    cacert: str | None
    fp_sha1: str | None
    fp_sha256: str | None

class AuthorizationBase(pydantic.BaseModel):
    key: str


class AuthorizationEdge(AuthorizationBase):
    client_token: str
    signer: str


class AuthorizationApp(AuthorizationBase):
    id_: str
    signers: List[str]


def sanitize(secret: str) -> str | None:
    if secret is None:
        # None is None -- don't hash it!
        return None
    return hashlib.sha256(secret.encode()).hexdigest()

def gather_authorizations_app(doc:dict) -> List[AuthorizationApp]:
    authorizations = []
    if "authorizations" in doc:
        for data in doc["authorizations"]:
            if "client_token" in data:
                assert "id" not in data
                continue
            try:
                auth = AuthorizationApp(
                        id_=data.get("id"),
                        key=sanitize(data.get("key")),
                        signers=data.get("signers"),
                        )
                authorizations.append(auth)
            except Exception as e:
                print(f"choked on {data}")
                raise
    return authorizations


def gather_authorizations_edge(doc:dict) -> List[AuthorizationEdge]:
    authorizations = []
    if "authorizations" in doc:
        for data in doc["authorizations"]:
            if "id" in data:
                assert "client_token" not in data
                continue
            try:
                auth = AuthorizationEdge(
                        client_token=data.get("client_token"),
                        key=sanitize(data.get("key")),
                        signer=data.get("signer"),
                        )
                authorizations.append(auth)
            except Exception as e:
                print(f"choked on {data}")
                raise
    return authorizations


def extract_cert_info(data: str | None) -> CertInfo:
    if not data:
        cert_info = CertInfo(pem=None, pem_hash=None, fp_sha1=None,
                             fp_sha256=None)
    else:
        cert = x509.load_pem_x509_certificate(data.encode())
        cert_info = CertInfo(
                pem=data,
                pem_hash=sanitize(data),
                fp_sha1=cert.fingerprint(hashes.SHA1()).hex(sep=":",
                                                            bytes_per_sep=1),
                fp_sha256=cert.fingerprint(hashes.SHA256()).hex(sep=":",
                                                                bytes_per_sep=1),
                )
    return cert_info



def gather_signers(doc:dict) -> List[Signer]:
    signers = []
    if "signers" in doc:
        for data in doc["signers"]:
            try:
                cert_info = extract_cert_info(data.get("certificate"))
                signer = Signer(
                        id_=data["id"],
                        type_=data["type"],
                        mode=data.get("mode"),
                        private_key=sanitize(data.get("privatekey")),
                        certificate=cert_info.pem_hash,
                        issuerprivatekey=data.get("issuerprivatekey"),
                        issuercert=sanitize(data.get("issuercert")),
                        cacert=sanitize(data.get("cacert")),
                        fp_sha1=cert_info.fp_sha1,
                        fp_sha256=cert_info.fp_sha256,
                        )
                signers.append(signer)
            except Exception as e:
                print(f"choked on {data}")
                raise
    return signers

def output_signers(signers: List[Signer]) -> None:
    if not len(signers):
        return
    with open("signers.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile,
                                fieldnames=signers[0].model_dump().keys())
        writer.writeheader()
        for s in signers:
            writer.writerow(s.model_dump())


def output_authorizations(authorizations: List[AuthorizationBase]) -> None:
    if not len(authorizations):
        return
    if isinstance(authorizations[0], AuthorizationApp):
        domain = "app"
    elif isinstance(authorizations[0], AuthorizationEdge):
        domain = "edge"
    else:
        raise TypeError(f"Unexpected type: {type(authorizations[0])}")
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

if __name__ == '__main__':
    exit(main())

#!/usr/bin/env python3

import csv
import hashlib
import sys
from typing import List

import pydantic
import yaml

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

class Authorization(pydantic.BaseModel):
    id_: str | None
    key: str
    client_token: str | None
    signers: List[str] | None
    signer: str | None


def sanitize(secret: str) -> str | None:
    if secret is None:
        # None is None -- don't hash it!
        return None
    return hashlib.sha256(secret.encode()).hexdigest()

def gather_authorizations(doc:dict) -> List[Authorization]:
    authorizations = []
    if "authorizations" in doc:
        for data in doc["authorizations"]:
            try:
                auth = Authorization(
                        id_=data.get("id"),
                        key=sanitize(data.get("key")),
                        client_token=sanitize(data.get("client_token")),
                        signers=data.get("signers"),
                        signer=data.get("signer"),
                        )
                authorizations.append(auth)
            except Exception as e:
                print(f"choked on {data}")
                raise
    return authorizations


def gather_signers(doc:dict) -> List[Signer]:
    signers = []
    if "signers" in doc:
        for data in doc["signers"]:
            try:
                signer = Signer(
                        id_=data["id"],
                        type_=data["type"],
                        mode=data.get("mode"),
                        private_key=sanitize(data.get("privatekey")),
                        certificate=sanitize(data.get("certificate")),
                        issuerprivatekey=data.get("issuerprivatekey"),
                        issuercert=sanitize(data.get("issuercert")),
                        cacert=sanitize(data.get("cacert")),
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


def output_authorizations(authorizations: List[Authorization]) -> None:
    if not len(authorizations):
        return
    with open("authorizations.csv", "w", newline="") as csvfile:
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
    authorizations = []
    for doc in yaml.safe_load_all(sys.stdin):
        assert isinstance(doc, dict)
        signers.extend(gather_signers(doc))
        authorizations.extend(gather_authorizations(doc))

    print(f"found {len(signers)} signers")
    print(f"found {len(authorizations)} authorizations")
    output_signers(signers)
    output_authorizations(authorizations)
    
    return 0

if __name__ == '__main__':
    exit(main())

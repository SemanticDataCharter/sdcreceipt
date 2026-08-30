#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
The party side: hold a key, publish it, sign a trigger.

A settlement identifies each party by a ``key_id`` that **the party controls**,
either an ``https://`` URL or a ``did:web:`` identifier. That keeps
verification independent of the issuer, and it means the party has to publish
one JSON file. This module reduces that to a single command.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from sdcreceipt.verify import trigger_message

#: Owner read/write only. A private key readable by other accounts on a shared
#: machine is a private key you no longer control.
PRIVATE_KEY_MODE = stat.S_IRUSR | stat.S_IWUSR


class PartyError(Exception):
    """Raised when key material or a settlement is not usable."""


def generate_key() -> ec.EllipticCurvePrivateKey:
    """A P-256 key, which is what ES256 means."""
    return ec.generate_private_key(ec.SECP256R1())


def private_key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Serialize a private key, unencrypted.

    Unencrypted is a deliberate, narrow choice: a passphrase this tool prompts
    for would be typed into scripts and CI, which is worse than a file with
    correct permissions and an honest warning. Use a KMS or an HSM if the key
    matters more than that, and this tool will sign with whatever key you
    hand it.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_pem(key) -> str:
    public = key.public_key() if hasattr(key, "public_key") else key
    return public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def write_private_key(key: ec.EllipticCurvePrivateKey, path: Path) -> Path:
    """Write a private key with owner-only permissions, refusing to clobber."""
    if path.exists():
        raise PartyError(
            f"{path} already exists. Refusing to overwrite a private key: if "
            "it is in use, replacing it invalidates every signature made with "
            "it. Move it aside deliberately if you mean to rotate."
        )
    path.write_bytes(private_key_pem(key))
    os.chmod(path, PRIVATE_KEY_MODE)
    return path


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load a P-256 private key, warning if the file is world-readable."""
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise PartyError(f"Could not read a private key from {path}: {exc}") from exc

    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise PartyError(
            f"{path} is not an ECDSA P-256 key, which is the only curve VSL "
            "signatures use (alg ES256)."
        )
    return key


def key_document(key, key_id: str) -> dict[str, Any]:
    """
    The document a party publishes at their ``key_id``.

    Shaped like the issuer's published key set so one verifier reads both.
    """
    return {
        "issuer": key_id,
        "keys": [
            {
                "key_id": key_id,
                "algorithm": "EC_SIGN_P256_SHA256",
                "alg": "ES256",
                "public_key_pem": public_key_pem(key),
                "status": "active",
            }
        ],
    }


def publication_path(key_id: str) -> str:
    """
    Where the key document has to be reachable for `key_id` to resolve.

    Returned so `init` can tell the operator exactly what to publish, rather
    than leaving them to infer it from a specification.
    """
    if key_id.startswith("https://"):
        return key_id
    if key_id.startswith("did:web:"):
        remainder = key_id[len("did:web:"):]
        segments = remainder.split(":")
        domain = segments[0].replace("%3A", ":")
        if len(segments) == 1:
            return f"https://{domain}/.well-known/did.json"
        return f"https://{domain}/{'/'.join(segments[1:])}/did.json"
    raise PartyError(
        f"Unsupported key_id {key_id!r}. It must be an https URL or a did:web "
        "identifier, so that you control it and verification does not route "
        "through the issuer."
    )


def sign_trigger(
    key: ec.EllipticCurvePrivateKey, receipt: dict[str, Any], key_id: str
) -> dict[str, Any]:
    """
    Produce a trigger for a Receipt.

    Signs ``{condition_hash, receipt_id}``. Both are fixed before either party
    signs, so the two can sign alone and in any order, while the signature
    still cannot be replayed into another settlement.

    Raises:
        PartyError: If `key_id` is not a party to this settlement, which is
            worth catching here rather than after a round trip.
    """
    settlement = receipt.get("settlement")
    if not settlement:
        raise PartyError("This Receipt has no settlement block to trigger.")

    parties = settlement.get("parties", [])
    if key_id not in parties:
        raise PartyError(
            f"{key_id} is not a party to this settlement. Listed parties:\n  "
            + "\n  ".join(parties)
        )

    already = {t.get("key_id") for t in settlement.get("triggers", [])}
    if key_id in already:
        raise PartyError(
            f"{key_id} has already triggered this settlement. A second "
            "trigger adds no authorization."
        )

    message = trigger_message(receipt["receipt_id"], settlement["condition_hash"])
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)

    import base64

    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signature = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    from datetime import datetime, timezone

    return {
        "receipt_id": receipt["receipt_id"],
        "key_id": key_id,
        "signature": signature,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def load_key_set(document: dict[str, Any]) -> dict[str, Any]:
    """
    Turn a published key document into ``{key_id: public_key}``.

    Accepts the issuer key-set shape and a did:web DID document, so a party
    does not have to publish a second document just for this tool.
    """
    keys: dict[str, Any] = {}

    for entry in document.get("keys", []):
        pem = entry.get("public_key_pem")
        if pem and entry.get("key_id"):
            keys[entry["key_id"]] = serialization.load_pem_public_key(
                pem.encode("ascii")
            )

    for method in document.get("verificationMethod", []):
        pem = method.get("publicKeyPem")
        if pem and method.get("id"):
            keys[method["id"]] = serialization.load_pem_public_key(pem.encode("ascii"))

    if not keys:
        raise PartyError(
            "No usable keys in that document. Expected a `keys` array with "
            "key_id and public_key_pem, or a DID document verificationMethod."
        )
    return keys


def load_key_set_file(path: Path) -> dict[str, Any]:
    try:
        return load_key_set(json.loads(path.read_text()))
    except json.JSONDecodeError as exc:
        raise PartyError(f"{path} is not valid JSON: {exc}") from exc

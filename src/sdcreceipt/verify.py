#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Verify a VSL Settlement Receipt.

Implements the published verification procedure. Nothing here contacts a
network or requires an account: keys are supplied by the caller, because the
procedure permits verifying from a key retained earlier. **If this module ever
needs to fetch something to do its job, the property it exists to demonstrate
has quietly stopped being true.**

★ Keys are parameters, and that is a security property rather than a
convenience. The caller decides which keys are acceptable *before* this reads
the Receipt, so a Receipt cannot nominate the key used to judge it. Resolving
a key from a location carried inside the artifact lets a forged document name
the forger's key and verify against it. Do not add an overload that fetches.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from sdcreceipt.canonical import canonicalize_bytes

#: Excluded from `receipt_hash`. Signatures sign the hash, so they cannot be
#: inside it, and triggers are appended after hashing so the parties can sign
#: independently and out of order.
HASH_EXCLUDED = ("receipt_hash", "signatures")


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""

    def __str__(self) -> str:
        return f"{'PASS' if self.passed else 'FAIL'}  {self.name}: {self.detail}"


@dataclass
class Result:
    """
    Every check that ran, not just the first failure.

    Stopping early tells an implementer one thing per run, and hides the case
    that matters most: a Receipt whose signature verifies but whose governance
    binding does not.
    """

    checks: list[Check] = field(default_factory=list)

    def record(self, name: str, passed: bool, detail: str = "") -> None:
        self.checks.append(Check(name, passed, detail))

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    def __str__(self) -> str:
        return "\n".join(str(c) for c in self.checks)


def canonical_content(receipt: dict[str, Any]) -> bytes:
    """The exact bytes `receipt_hash` commits to."""
    content = {k: v for k, v in receipt.items() if k not in HASH_EXCLUDED}
    if "settlement" in content:
        content["settlement"] = {
            k: v for k, v in receipt["settlement"].items() if k != "triggers"
        }
    return canonicalize_bytes(content)


def receipt_digest(receipt: dict[str, Any]) -> bytes:
    """
    The 32 raw bytes a signature covers.

    Identical to the value `receipt_hash` records in hex, so a verifier
    computes it once and uses it for both checks.
    """
    return hashlib.sha256(canonical_content(receipt)).digest()


def trigger_message(receipt_id: str, condition_hash: str) -> bytes:
    """
    What a party signs to trigger a settlement.

    `receipt_id` is included deliberately: a signature over `condition_hash`
    alone is replayable into any other Receipt sharing that release condition,
    and repeat trading relationships reuse conditions as a matter of course.
    """
    return canonicalize_bytes(
        {"condition_hash": condition_hash, "receipt_id": receipt_id}
    )


def _b64url_to_raw(value: str) -> bytes:
    import base64

    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != 64:
        raise ValueError(
            f"expected a 64-byte P1363 signature, got {len(raw)} bytes "
            "(a DER signature is variable length and will not be 64)"
        )
    return raw


def _verify_ecdsa(public_key, message: bytes, signature: str, *, prehashed: bool) -> str:
    """Return "" on success, or the reason it failed."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    try:
        raw = _b64url_to_raw(signature)
    except Exception as exc:
        return f"malformed signature: {exc}"

    algorithm = (
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        if prehashed
        else ec.ECDSA(hashes.SHA256())
    )
    try:
        public_key.verify(
            utils.encode_dss_signature(
                int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            ),
            message,
            algorithm,
        )
    except InvalidSignature:
        return "does not verify against the stated key"
    return ""


def verify(
    receipt: dict[str, Any],
    *,
    issuer_keys: dict[str, Any],
    party_keys: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
    governance_receipt: dict[str, Any] | None = None,
    payload: bytes | None = None,
) -> Result:
    """
    Run the verification procedure over one Receipt.

    Args:
        receipt: The Receipt.
        issuer_keys: ``{key_id: public_key}``. Held or fetched beforehand.
        party_keys: ``{key_id: public_key}`` for triggers. Omit to skip that
            step, which is legitimate when the keys are not held.
        schema: The published JSON Schema, to check shape first.
        governance_receipt: The governance Receipt, if held.
        payload: The payload, if held.
    """
    result = Result()

    if schema is not None:
        try:
            import jsonschema
        except ImportError:
            # The caller asked for a check that cannot run. Recording it as a
            # failure rather than skipping it: a verifier that quietly omits a
            # requested check and still says VERIFIED is worse than one that
            # stops, because the operator believes the check happened.
            result.record(
                "schema",
                False,
                "cannot check: jsonschema is not installed. Install it with "
                "`pip install 'sdcreceipt[schema]'`, or omit --schema to run "
                "the cryptographic checks alone",
            )
            return result

        errors = sorted(
            jsonschema.Draft202012Validator(schema).iter_errors(receipt),
            key=lambda e: list(e.absolute_path),
        )
        result.record(
            "schema",
            not errors,
            "conforms" if not errors else f"{len(errors)} violation(s): {errors[0].message}",
        )
        if errors:
            return result

    recomputed = hashlib.sha256(canonical_content(receipt)).hexdigest()
    matches = recomputed == receipt.get("receipt_hash")
    result.record(
        "receipt_hash",
        matches,
        "matches the canonical content"
        if matches
        else (
            f"recorded {receipt.get('receipt_hash')} but content hashes to "
            f"{recomputed}. If this is your only failure, suspect "
            "canonicalization: RFC 8785 renders an integral float as 1, not 1.0"
        ),
    )

    digest = receipt_digest(receipt)
    for signature in receipt.get("signatures", []):
        key_id = signature.get("key_id", "")
        label = f"signature[{key_id}]"

        if signature.get("alg") != "ES256":
            result.record(label, False, f"alg is {signature.get('alg')!r}, expected ES256")
            continue

        key = issuer_keys.get(key_id)
        if key is None:
            result.record(
                label,
                False,
                f"no key held for {key_id!r}. Resolve it from the published "
                "key set, never from a location inside the Receipt",
            )
            continue

        reason = _verify_ecdsa(key, digest, signature.get("sig", ""), prehashed=True)
        result.record(label, not reason, reason or "verifies over receipt_hash")

    if not receipt.get("signatures"):
        result.record("signatures", False, "the Receipt carries no signature")

    settlement = receipt.get("settlement", {})
    parties = settlement.get("parties", [])
    triggers = settlement.get("triggers", [])

    if party_keys is not None:
        message = trigger_message(
            receipt.get("receipt_id", ""), settlement.get("condition_hash", "")
        )
        for trig in triggers:
            key_id = trig.get("key_id", "")
            label = f"trigger[{key_id}]"

            if key_id not in parties:
                result.record(label, False, f"{key_id!r} is not a listed party")
                continue

            key = party_keys.get(key_id)
            if key is None:
                result.record(label, False, f"no key held for party {key_id!r}")
                continue

            reason = _verify_ecdsa(
                key, message, trig.get("signature", ""), prehashed=False
            )
            result.record(
                label,
                not reason,
                reason or "verifies over {condition_hash, receipt_id}",
            )
            if reason:
                result.checks[-1].detail += (
                    ". If it is well formed, check whether it belongs to a "
                    "different Receipt sharing this release condition"
                )

        duplicated = len(triggers) != len({t.get("key_id") for t in triggers})
        result.record(
            "triggers.unique",
            not duplicated,
            "one trigger per party"
            if not duplicated
            else "a party appears more than once, overstating agreement",
        )

    if party_keys is None and triggers:
        # `settlement.complete` is a claim about authorization, not about which
        # strings appear in the document. With no party keys, not one trigger
        # signature was checked, so the claim cannot be established: a Receipt
        # carrying fabricated triggers would otherwise reach VERIFIED on a set
        # comparison alone. Same principle as the schema check above. A
        # verifier that quietly omits a check and still says VERIFIED is worse
        # than one that stops, because the operator believes the check ran.
        result.record(
            "settlement.complete",
            False,
            "cannot establish: no party keys were supplied, so no trigger "
            "signature was checked. Pass the parties' published keys in "
            "--keys, or read this Receipt as unsettled",
        )
    else:
        complete = bool(parties) and {t.get("key_id") for t in triggers} >= set(parties)
        result.record(
            "settlement.complete",
            complete,
            "every listed party has triggered"
            if complete
            else f"awaiting {sorted(set(parties) - {t.get('key_id') for t in triggers})}",
        )

    if governance_receipt is not None:
        expected = receipt.get("governance", {}).get("receipt_hash")
        actual = governance_receipt.get("receipt_hash")
        result.record(
            "governance.receipt_hash",
            actual == expected,
            "binds the governance Receipt that produced the verdict"
            if actual == expected
            else (
                f"commits to {expected} but the held Receipt is {actual}. "
                "The verdict is signed and unsupported"
            ),
        )

        verdict = receipt.get("governance", {}).get("decision")
        held = governance_receipt.get("decision")
        result.record(
            "governance.decision",
            verdict == held,
            f"matches ({verdict})"
            if verdict == held
            else f"Receipt says {verdict!r}, governance Receipt says {held!r}",
        )

    if payload is not None:
        expected = receipt.get("payload_hash")
        actual = hashlib.sha256(payload).hexdigest()
        result.record(
            "payload_hash",
            actual == expected,
            "commits to the payload held"
            if actual == expected
            else f"recorded {expected} but the payload hashes to {actual}",
        )

    return result

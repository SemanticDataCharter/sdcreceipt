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
import re
from dataclasses import dataclass, field
from datetime import datetime
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


#: The signature algorithms a Receipt may name, and the raw length each one
#: fixes. ``ES256`` (RFC 7518 §3.4) is ECDSA P-256 with the P1363 ``r||s`` pair,
#: 64 bytes, 86 base64url characters. ``ML-DSA-65`` (Receipt 1.1) is the pure
#: FIPS 204 signature over the same 32 digest bytes as its message, 3309 bytes,
#: 4412 characters, named as the IETF "ML-DSA for JOSE and COSE" draft names it.
#: Naming the algorithm pins the encoding; there is no separate encoding field.
SIGNATURE_BYTES = {"ES256": 64, "ML-DSA-65": 3309}
_B64URL_SIGNATURE = {
    alg: __import__("re").compile(r"^[A-Za-z0-9_-]{%d}$" % (-(-length * 4 // 3)))
    for alg, length in SIGNATURE_BYTES.items()
}


def _b64url_to_raw(value: Any, alg: str = "ES256") -> bytes:
    """
    Decode a base64url signature strictly, at the length ``alg`` fixes.

    ★ `base64.urlsafe_b64decode` discards characters outside the alphabet and
    tolerates padding, so two different strings could decode to one signature
    and a corrupted value could still "decode" (Lee, F-09). A signature is
    accepted only in the one spelling the specification produces: exactly the
    characters its algorithm's length needs, from the base64url alphabet, no
    padding (86 for ES256, 4412 for ML-DSA-65).
    """
    import base64

    length = SIGNATURE_BYTES[alg]
    chars = -(-length * 4 // 3)
    if not isinstance(value, str) or not _B64URL_SIGNATURE[alg].match(value):
        hint = (
            "a 64-byte P1363 signature); a DER signature is variable length and will not fit"
            if alg == "ES256"
            else "a 3309-byte ML-DSA-65 signature)"
        )
        raise ValueError(f"expected {chars} unpadded base64url characters ({hint}")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != length:
        raise ValueError(f"expected a {length}-byte {alg} signature, got {len(raw)} bytes")
    # ★ 86 characters carry 516 bits for 512, so the last character has
    # unused bits and 16 spellings decoded to one ES256 signature (Lee,
    # 4.3.x review, F-04). Only the spelling that re-encodes exactly is the
    # one the specification produces.
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError("not the canonical base64url spelling of its bytes")
    return raw


def _verify_mldsa65(public_key, message: bytes, signature: str) -> str:
    """
    Return "" on success, or the reason an ML-DSA-65 signature failed.

    Pure ML-DSA signs the message itself (FIPS 204), so for an issuer
    signature ``message`` is the 32-byte receipt digest, the same bytes ES256
    signs as a digest. Needs ``cryptography`` 48 or later.
    """
    from cryptography.exceptions import InvalidSignature

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        return "cannot check an ML-DSA-65 signature: cryptography 48 or later is required"

    try:
        raw = _b64url_to_raw(signature, "ML-DSA-65")
    except Exception as exc:
        return f"malformed signature: {exc}"
    if not isinstance(public_key, mldsa.MLDSA65PublicKey):
        return "the stated key is not an ML-DSA-65 key"
    try:
        public_key.verify(raw, message)
    except InvalidSignature:
        return "does not verify against the stated key"
    return ""


def _verify_ecdsa(public_key, message: bytes, signature: str, *, prehashed: bool) -> str:
    """Return "" on success, or the reason it failed."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    try:
        raw = _b64url_to_raw(signature)
    except Exception as exc:
        return f"malformed signature: {exc}"
    # ★ An ES256 signature or a trigger naming an ML-DSA-65 key reached
    # ECDSA's verify and ended in a traceback (Lee, 4.3.x review, F-05).
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        return "the stated key is not an ECDSA P-256 key"

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


#: The Receipt formats this implementation verifies. Independent of the
#: package version: a Receipt says ``"version": "1.0"`` or ``"1.1"`` and that
#: is the wire format. 1.1 is 1.0 signed twice: every listed signature must
#: verify, and these algorithms must all be present.
SUPPORTED_RECEIPT_VERSIONS = ("1.0", "1.1")
REQUIRED_ALGS = {"1.0": ("ES256",), "1.1": ("ES256", "ML-DSA-65")}


def _shape_problems(receipt: Any) -> list[str]:
    """
    Why a document cannot be verified at all, before any rule is applied.

    ★ A verifier is the one component whose input is chosen by whoever wants
    it to fail badly. Six malformed shapes reached an unhandled exception in
    4.2.1 (a list where an object was expected, a string for `settlement`, a
    trigger that was not an object, an unhashable `key_id`, and so on), and
    over MCP that exception was the tool's whole answer (Lee, F-03). Every
    place the procedure indexes into the document is checked here first, so a
    malformed Receipt is reported as malformed and nothing else runs.
    """
    problems: list[str] = []
    if not isinstance(receipt, dict):
        return ["the Receipt is not a JSON object"]

    for name in ("receipt_id", "receipt_hash", "version", "payload_hash"):
        if name in receipt and not isinstance(receipt[name], str):
            problems.append(f"`{name}` must be a string")

    signatures = receipt.get("signatures", [])
    if not isinstance(signatures, list):
        problems.append("`signatures` must be an array")
    else:
        for i, signature in enumerate(signatures):
            if not isinstance(signature, dict):
                problems.append(f"`signatures[{i}]` must be an object")
            else:
                for name in ("key_id", "alg", "sig"):
                    if name in signature and not isinstance(signature[name], str):
                        problems.append(f"`signatures[{i}].{name}` must be a string")

    settlement = receipt.get("settlement", {})
    if not isinstance(settlement, dict):
        problems.append("`settlement` must be an object")
    else:
        parties = settlement.get("parties", [])
        if not isinstance(parties, list) or not all(isinstance(x, str) for x in parties):
            problems.append("`settlement.parties` must be an array of strings")
        triggers = settlement.get("triggers", [])
        if not isinstance(triggers, list):
            problems.append("`settlement.triggers` must be an array")
        else:
            for i, trigger in enumerate(triggers):
                if not isinstance(trigger, dict):
                    problems.append(f"`settlement.triggers[{i}]` must be an object")
                else:
                    for name in ("key_id", "signature"):
                        if name in trigger and not isinstance(trigger[name], str):
                            problems.append(
                                f"`settlement.triggers[{i}].{name}` must be a string"
                            )
        if "condition_hash" in settlement and not isinstance(
            settlement["condition_hash"], str
        ):
            problems.append("`settlement.condition_hash` must be a string")

    governance = receipt.get("governance", {})
    if not isinstance(governance, dict):
        problems.append("`governance` must be an object")

    return problems


def _revoked(keys: dict[str, Any], key_id: str) -> bool:
    """Whether the key document that supplied this key marked it revoked."""
    revoked = getattr(keys, "revoked", None)
    return bool(revoked(key_id)) if callable(revoked) else False


#: The time form the Receipt's ``timestamp`` and a key document's window use.
_UTC_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")


def parse_instant(value: Any) -> datetime:
    """
    An RFC 3339 UTC time ending in ``Z``, as a datetime, or ``ValueError``.

    Only the ``Z`` form is accepted. Offsets would compare correctly once
    parsed, but two implementations that disagree on parsing them would
    disagree on a window, so the form is fixed rather than interpreted.
    """
    if not isinstance(value, str) or not _UTC_INSTANT.fullmatch(value):
        raise ValueError(f"{value!r} is not an RFC 3339 UTC time ending in Z")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _window(keys: dict[str, Any], key_id: str) -> dict[str, Any] | None:
    """The validity window the key document published for this key, if the key set kept one."""
    window = getattr(keys, "window", None)
    return window(key_id) if callable(window) else None


def _issuer_window_reason(window: dict[str, Any] | None, timestamp: Any) -> str:
    """
    "" when the Receipt's ``timestamp`` lies in the issuer key's window, else why not.

    ★ Half-open, ``not_before <= timestamp < not_after``, because a retired
    key's ``not_after`` is its successor's ``not_before``: one instant belongs
    to one key. A null bound is no bound, and a key with no window stated has
    nothing to check. Status is not consulted here: ``retired`` inside its
    window passes, so rotating a key never breaks the Receipts it signed, and
    ``revoked`` has already failed, whatever its window says, because a
    compromised key can write any timestamp it likes.
    """
    if not window:
        return ""
    try:
        at = parse_instant(timestamp)
        not_before = window.get("not_before")
        not_after = window.get("not_after")
        if not_before is not None and at < parse_instant(not_before):
            return f"timestamp {timestamp} is before the key's not_before {not_before}"
        if not_after is not None and at >= parse_instant(not_after):
            return f"timestamp {timestamp} is not before the key's not_after {not_after}"
    except ValueError as exc:
        return f"cannot compare the key's window with the timestamp: {exc}"
    return ""


def _party_window_reason(window: dict[str, Any] | None, timestamp: Any) -> str:
    """
    "" unless the party key was retired or revoked by the Receipt's ``timestamp``.

    A trigger's own timestamp is not signed, so it proves nothing. What a
    trigger does sign is ``receipt_id``, which did not exist before the
    Receipt's signed ``timestamp``; a key whose ``not_after`` is at or before
    that instant could not have made it while valid. ``not_before`` is not
    judged: nothing signed says how late a trigger came.
    """
    not_after = (window or {}).get("not_after")
    if not_after is None:
        return ""
    try:
        if parse_instant(not_after) <= parse_instant(timestamp):
            return (
                f"the party key's not_after {not_after} is not after the Receipt's "
                f"timestamp {timestamp}; a trigger signs receipt_id, which did not "
                "exist before that time"
            )
    except ValueError as exc:
        return f"cannot compare the party key's window with the timestamp: {exc}"
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
        issuer_keys: ``{key_id: public_key}``. Held or fetched beforehand. A
            :class:`~sdcreceipt.party.KeySet` also carries each key's
            published ``status``; a key marked ``revoked`` fails the signature
            it is named on.
        party_keys: ``{key_id: public_key}`` for triggers. Omit to skip that
            step, which is legitimate when the keys are not held.
        schema: The published JSON Schema, to check shape first.
        governance_receipt: The governance Receipt, if held.
        payload: The payload, if held.
    """
    result = Result()

    problems = _shape_problems(receipt)
    if problems:
        result.record(
            "shape",
            False,
            "not a Receipt this procedure can read: " + "; ".join(problems[:4]),
        )
        return result

    version = receipt.get("version")
    if version not in SUPPORTED_RECEIPT_VERSIONS:
        # ★ Refused, not assumed. Without this a "2.0" document was checked
        # under 1.0 rules and could pass them; a verifier that applies the
        # wrong rules and says VERIFIED is the schema-check problem again.
        result.record(
            "version",
            False,
            f"Receipt version {version!r} is not one this tool implements "
            f"({', '.join(SUPPORTED_RECEIPT_VERSIONS)}). Refusing to apply "
            "those rules to a document that says it follows others",
        )
        return result

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

    try:
        content = canonical_content(receipt)
    except Exception as exc:
        # RFC 8785 refuses what JSON cannot round-trip (NaN, integers beyond
        # 2^53). A Receipt carrying one cannot have been hashed by a
        # conformant issuer, and the refusal is the finding.
        result.record("receipt_hash", False, f"cannot canonicalize the Receipt: {exc}")
        return result

    recomputed = hashlib.sha256(content).hexdigest()
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
    required = REQUIRED_ALGS[version]
    for signature in receipt.get("signatures", []):
        key_id = signature.get("key_id", "")
        alg = signature.get("alg")
        label = f"signature[{key_id}]"

        # ★ Every listed signature must verify, with the algorithm its ``alg``
        # names. One this tool does not implement is a failure, not a skip,
        # and one the version does not call for is a failure too: a 1.0
        # Receipt carrying an ML-DSA-65 signature is not what 1.0 means.
        if alg not in required:
            result.record(
                label, False, f"alg is {alg!r}; version {version} allows {', '.join(required)}"
            )
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

        if _revoked(issuer_keys, key_id):
            # ★ A revoked key is not a missing key. The document that
            # published it says it must not be trusted, and a signature it
            # made is exactly what that status exists to reject.
            result.record(
                label, False, f"key {key_id!r} is marked revoked in the key document"
            )
            continue

        if alg == "ML-DSA-65":
            reason = _verify_mldsa65(key, digest, signature.get("sig", ""))
        else:
            reason = _verify_ecdsa(key, digest, signature.get("sig", ""), prehashed=True)
        if not reason:
            # ★ A genuine signature made outside the window the issuer itself
            # published for that key is not the issuer's Receipt.
            reason = _issuer_window_reason(_window(issuer_keys, key_id), receipt.get("timestamp"))
        result.record(label, not reason, reason or f"verifies over receipt_hash ({alg})")

    if not receipt.get("signatures"):
        result.record("signatures", False, "the Receipt carries no signature")
    else:
        # ★ The version says which algorithms must be there. A Receipt that
        # says 1.1 with only its ES256 signature verifying is not a 1.1
        # Receipt, however good that one signature is.
        present = {s.get("alg") for s in receipt.get("signatures", [])}
        missing = [alg for alg in required if alg not in present]
        result.record(
            "signatures.algorithms",
            not missing,
            f"carries every signature version {version} requires ({', '.join(required)})"
            if not missing
            else f"version {version} requires {', '.join(required)}; missing {', '.join(missing)}",
        )

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

            if _revoked(party_keys, key_id):
                result.record(
                    label, False, f"key {key_id!r} is marked revoked in the key document"
                )
                continue

            reason = _verify_ecdsa(
                key, message, trig.get("signature", ""), prehashed=False
            )
            if not reason:
                window_reason = _party_window_reason(
                    _window(party_keys, key_id), receipt.get("timestamp")
                )
                if window_reason:
                    result.record(label, False, window_reason)
                    continue
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
            "--party-keys, or read this Receipt as unsettled",
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


# ---------------------------------------------------------------------------
# Chains: following previous_hash through Receipts the caller holds.
# ---------------------------------------------------------------------------

#: How many earlier Receipts ``verify_chain`` follows before giving up. A
#: verifier's input is chosen by whoever wants it to fail badly.
CHAIN_CEILING = 10_000


def chain_link_label(n: int, previous_hash: Any) -> str:
    """The prefix for link ``n`` back from the Receipt verified: ``chain.link[1 3fa9c1d2…]``."""
    return f"chain.link[{n} {str(previous_hash)[:8]}\u2026]"


def content_hash(receipt: dict[str, Any]) -> str:
    """The recomputed ``receipt_hash``: SHA-256 over the canonical content, whatever the Receipt records."""
    return hashlib.sha256(canonical_content(receipt)).hexdigest()


def _content_hash_or_none(document: Any) -> str | None:
    """The recomputed hash, or None for a held document that is not a canonicalizable Receipt."""
    if not isinstance(document, dict) or _shape_problems(document):
        return None
    try:
        return content_hash(document)
    except Exception:
        return None


def verify_chain(
    receipt: dict[str, Any],
    *,
    held: list[dict[str, Any]],
    issuer_keys: dict[str, Any],
    party_keys: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
    governance_receipt: dict[str, Any] | None = None,
    payload: bytes | None = None,
    ceiling: int = CHAIN_CEILING,
) -> Result:
    """
    Verify ``receipt`` and every earlier Receipt its ``previous_hash`` reaches.

    ``held`` are earlier Receipts the caller already has. Like keys they are
    parameters and never fetched: the caller decides what evidence is in play
    before anything is read, so a Receipt cannot nominate the Receipt it is
    judged against. An empty ``held`` is still a chain, with nothing held.

    ★ **Held Receipts are found by recomputed hash, never the recorded one**,
    so a document cannot claim a place in the chain by writing a
    ``receipt_hash`` it does not have. When no held Receipt hashes to a
    ``previous_hash``, a held one that *records* that hash is still examined,
    so the failure says which link was edited rather than only that the chain
    stops; it always fails, on its own ``receipt_hash`` and on the join.

    The walk ends at a Receipt whose ``previous_hash`` is null
    (``chain.head``). Every earlier link runs the full procedure with the same
    keys (and their windows) and schema; governance and payload evidence apply
    to ``receipt`` only. An earlier link that was never fully triggered
    therefore fails: VERIFIED over a chain means every settlement in it
    completed. Each earlier link's checks are recorded with the prefix
    :func:`chain_link_label` gives, and each join adds two:

    * ``<prefix> previous_hash``: the later Receipt names a held Receipt;
    * ``<prefix> timestamp``: the earlier signed ``timestamp`` is not after
      the later one.

    The chain cannot be established, recorded on the bare prefix, when two
    different held documents hash to the named value (they can differ only in
    what the hash excludes, ``signatures`` and ``settlement.triggers``), when
    the named Receipt is not held, or past ``ceiling`` links. When it is not
    found but other held Receipts are left over, the join fails on
    ``previous_hash`` instead: the caller supplied an earlier Receipt and this
    one names a different one.

    The names match the VSL conformance kit 1.2 ("Chains").
    """
    result = verify(
        receipt,
        issuer_keys=issuer_keys,
        party_keys=party_keys,
        schema=schema,
        governance_receipt=governance_receipt,
        payload=payload,
    )
    if any(c.name in ("shape", "version") for c in result.failures):
        # Nothing about this document can be read as a chain link.
        return result

    held = list(held)
    by_hash: dict[str, list[dict[str, Any]]] = {}
    for document in held:
        recomputed = _content_hash_or_none(document)
        if recomputed is None:
            continue  # cannot be canonicalized, so nothing can name it
        documents = by_hash.setdefault(recomputed, [])
        if document not in documents:  # byte-identical copies are one document
            documents.append(document)

    used: list[dict[str, Any]] = []
    later, n = receipt, 0
    while True:
        previous_hash = later.get("previous_hash")
        if previous_hash is None:
            result.record(
                "chain.head",
                True,
                "this Receipt is the head"
                if n == 0
                else f"reached the head after {n} earlier Receipt(s)",
            )
            return result

        n += 1
        prefix = chain_link_label(n, previous_hash)
        if n > ceiling:
            result.record(prefix, False, f"more than {ceiling} links; the chain cannot be established")
            return result

        candidates = by_hash.get(previous_hash, []) if isinstance(previous_hash, str) else []
        if len(candidates) > 1:
            result.record(
                prefix,
                False,
                f"{len(candidates)} different held documents hash to {previous_hash}. They can "
                "differ only in signatures or settlement.triggers, and the chain cannot say "
                "which is the Receipt",
            )
            return result

        if candidates:
            earlier = candidates[0]
            result.record(f"{prefix} previous_hash", True, "names a held Receipt by its recomputed hash")
        else:
            left_over = [
                d for d in held
                if isinstance(d, dict) and d is not receipt and d != receipt
                and not any(d is u for u in used)
            ]
            claiming = [d for d in left_over if d.get("receipt_hash") == previous_hash]
            if claiming:
                earlier = claiming[0]
                recomputed = _content_hash_or_none(earlier)
                result.record(
                    f"{prefix} previous_hash",
                    False,
                    f"names {previous_hash}; a held Receipt records that receipt_hash, but its "
                    + (
                        f"content hashes to {recomputed}, so it was edited after it was hashed"
                        if recomputed
                        else "content cannot be read as a Receipt"
                    ),
                )
            elif left_over:
                hashes = sorted(h or "(not a Receipt)" for h in map(_content_hash_or_none, left_over))
                result.record(
                    f"{prefix} previous_hash",
                    False,
                    f"names {previous_hash}, which no held Receipt hashes to; the held Receipts "
                    f"left over hash to {hashes}",
                )
                return result
            else:
                result.record(
                    prefix,
                    False,
                    f"names {previous_hash}, which is not held; the chain cannot be established "
                    "without it",
                )
                return result

        if any(earlier is u for u in used):
            result.record(prefix, False, "the chain returns to a Receipt already on it")
            return result
        used.append(earlier)

        link = verify(earlier, issuer_keys=issuer_keys, party_keys=party_keys, schema=schema)
        for check in link.checks:
            result.record(f"{prefix} {check.name}", check.passed, check.detail)
        if any(c.name in ("shape", "version") for c in link.failures):
            return result

        try:
            in_order = parse_instant(earlier.get("timestamp")) <= parse_instant(later.get("timestamp"))
            detail = (
                f"{earlier.get('timestamp')} is not after {later.get('timestamp')}"
                if in_order
                else f"the earlier Receipt's timestamp {earlier.get('timestamp')} is after the "
                f"later one's {later.get('timestamp')}"
            )
        except ValueError as exc:
            in_order, detail = False, f"cannot compare timestamps: {exc}"
        result.record(f"{prefix} timestamp", in_order, detail)
        later = earlier

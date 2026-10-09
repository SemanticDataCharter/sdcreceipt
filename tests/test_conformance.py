#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Run the published conformance vectors against this implementation.

★ This is the test that matters. Everything else here checks that the code
does what I meant; this checks that it does what the *specification* means,
using vectors published by the issuer and generated independently of this
tool.

Each invalid vector encodes a real defect. Failing one for the wrong reason
does not count: the manifest names the check that must break, and so does
this test.
"""

import json
import pathlib

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from sdcreceipt.verify import verify

KIT = pathlib.Path(__file__).parent / "conformance"


@pytest.fixture(scope="module")
def kit():
    keys = json.loads((KIT / "keys.json").read_text())
    return {
        "manifest": json.loads((KIT / "manifest.json").read_text()),
        # One schema per Receipt version; a vector is checked against the one
        # its own ``version`` names.
        "schemas": {
            v: json.loads((KIT / f"settlement-receipt-{v}.schema.json").read_text())
            for v in ("1.0", "1.1")
        },
        "issuer_keys": {
            k: load_pem_public_key(v.encode()) for k, v in keys["issuer_keys"].items()
        },
        "party_keys": {
            k: load_pem_public_key(v.encode()) for k, v in keys["party_keys"].items()
        },
        "governance": json.loads((KIT / "governance-receipt.json").read_text()),
        "payload": (KIT / "payload.xml").read_bytes(),
    }


def run(kit, filename, withhold=()):
    """
    ``withhold`` names arguments the caller deliberately does not supply.

    Every vector used to run with the full key set, which is why the 4.2.0
    trigger defect shipped: the one arrangement that broke it, a settled
    Receipt verified without party keys, could not be expressed here.
    """
    receipt = json.loads((KIT / filename).read_text())
    args = {
        "issuer_keys": kit["issuer_keys"],
        "party_keys": kit["party_keys"],
        "schema": kit["schemas"][receipt["version"]],
        "governance_receipt": kit["governance"],
        "payload": kit["payload"],
    }
    for name in withhold:
        args[name] = None
    return verify(receipt, **args)


def test_the_kit_is_present(kit):
    assert len(kit["manifest"]["vectors"]) == 16


def test_every_vector_behaves_as_the_manifest_says(kit):
    """
    The whole conformance claim in one assertion.

    An invalid vector must fail *on the named check*. A vector that fails for
    some other reason would let this tool look conformant while carrying the
    bug the vector exists to catch.
    """
    problems = []

    for entry in kit["manifest"]["vectors"]:
        result = run(kit, entry["file"], entry.get("withhold", ()))
        failed = {c.name for c in result.failures}

        if entry["expect"] == "valid":
            if failed:
                problems.append(
                    f"{entry['name']}: expected valid, broke {sorted(failed)}"
                )
        elif entry["breaks"] not in failed:
            problems.append(
                f"{entry['name']}: must break {entry['breaks']!r}, "
                f"broke {sorted(failed) or 'nothing'}"
            )

    assert not problems, "\n".join(problems)


def test_canonicalization_vector_passes(kit):
    """
    Contains a number RFC 8785 renders as 1, not 1.0. Failing this one alone
    means the canonicalization is not conformant, which is why the tool reuses
    sdcgovernance rather than rendering JSON itself.
    """
    assert run(kit, "valid-canonicalization-integral-float.json").ok


def test_a_der_signature_is_rejected(kit):
    """RFC 7518 ES256 requires P1363; DER is neither 64 bytes nor fixed."""
    assert not run(kit, "signature-der-not-p1363.json").ok


def test_a_replayed_trigger_is_rejected(kit):
    """
    A trigger lifted from another Receipt sharing this release condition.
    Repeat trading relationships reuse conditions, so a verifier that checks
    only the condition accepts last month's signature for this month's goods.
    """
    result = run(kit, "trigger-replayed-from-another-receipt.json")
    assert not result.ok
    assert any(c.name.startswith("trigger[") for c in result.failures)


def test_an_unsupported_governance_binding_is_caught(kit):
    """
    Signature and hash both correct; the Receipt commits to different
    governance evidence than the one held. A signed, unsupported verdict.
    """
    result = run(kit, "governance-binding-does-not-match.json")
    assert not result.ok
    assert any(c.name == "governance.receipt_hash" for c in result.failures)


def test_verification_needs_no_network(kit, monkeypatch):
    """
    ★ The property the tool exists to demonstrate, asserted rather than
    claimed. If verification ever reaches the network, it has a dependency
    the format does not.
    """
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("verification attempted a network connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    assert run(kit, "valid-settled.json").ok


def test_every_check_is_reported_not_just_the_first(kit):
    """
    Stopping early hides the case that matters most: a Receipt whose
    signature verifies but whose governance binding does not.
    """
    result = run(kit, "governance-binding-does-not-match.json")
    names = [c.name for c in result.checks]

    assert "receipt_hash" in names
    assert "governance.receipt_hash" in names
    assert any(c.name == "receipt_hash" and c.passed for c in result.checks)


def test_a_missing_key_is_reported_not_silently_skipped(kit):
    """
    An unverified signature must never read as a verified one.
    """
    receipt = json.loads((KIT / "valid-settled.json").read_text())
    result = verify(receipt, issuer_keys={}, schema=kit["schemas"]["1.0"])

    assert not result.ok
    assert any("no key held" in c.detail for c in result.failures)


def test_a_missing_optional_dependency_is_reported_not_a_traceback(kit, monkeypatch):
    """
    ★ Found by installing from PyPI into a clean venv, which all 15 tests
    missed because the dev environment already had jsonschema.

    Recorded as a failure rather than skipped: a verifier that quietly omits a
    requested check and still says VERIFIED is worse than one that stops,
    because the operator believes the check happened.
    """
    import builtins

    real_import = builtins.__import__

    def no_jsonschema(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("No module named 'jsonschema'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_jsonschema)

    receipt = json.loads((KIT / "valid-settled.json").read_text())
    result = verify(receipt, issuer_keys=kit["issuer_keys"], schema=kit["schemas"]["1.0"])

    assert not result.ok
    detail = next(c.detail for c in result.failures if c.name == "schema")
    assert "sdcreceipt[schema]" in detail


# --- Receipt 1.1: the same content signed twice, ES256 and ML-DSA-65 ---


def test_the_1_1_vector_verifies_with_both_signatures(kit):
    result = run(kit, "valid-settled-1.1.json")
    assert result.ok, result.failures
    names = {c.name for c in result.checks}
    assert "signature[sdcstudio-pq-signing-key-v1]" in names
    assert "signatures.algorithms" in names


def test_a_1_1_receipt_missing_its_mldsa_signature_fails_without_the_schema(kit):
    """The schema catches it first; without one, the version's promise must still be checked."""
    receipt = json.loads((KIT / "valid-settled-1.1.json").read_text())
    receipt["signatures"] = [s for s in receipt["signatures"] if s["alg"] == "ES256"]
    result = verify(receipt, issuer_keys=kit["issuer_keys"], party_keys=kit["party_keys"])
    assert {c.name for c in result.failures} == {"signatures.algorithms"}


def test_a_1_0_receipt_carrying_an_mldsa_signature_is_not_1_0(kit):
    good = json.loads((KIT / "valid-settled.json").read_text())
    extra = json.loads((KIT / "valid-settled-1.1.json").read_text())["signatures"][1]
    good["signatures"].append(extra)
    result = verify(good, issuer_keys=kit["issuer_keys"], party_keys=kit["party_keys"])
    assert not result.ok
    assert any(c.name == "signature[sdcstudio-pq-signing-key-v1]" and "allows ES256" in c.detail for c in result.failures)


def test_an_mldsa_signature_is_decoded_strictly():
    from sdcreceipt.verify import _b64url_to_raw

    with pytest.raises(ValueError, match="4412 unpadded"):
        _b64url_to_raw("A" * 86, "ML-DSA-65")
    with pytest.raises(ValueError, match="86 unpadded"):
        _b64url_to_raw("A" * 4412, "ES256")
    assert len(_b64url_to_raw("A" * 4412, "ML-DSA-65")) == 3309


def test_the_key_document_loader_admits_an_mldsa_key_and_nothing_else_new():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

    from sdcreceipt.party import PartyError, load_key_set

    def pem(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    keys = load_key_set({"keys": [{"key_id": "pq-v1", "public_key_pem": pem(mldsa.MLDSA65PrivateKey.generate())}]})
    assert isinstance(keys["pq-v1"], mldsa.MLDSA65PublicKey)
    with pytest.raises(PartyError, match="not an ECDSA P-256 or an ML-DSA-65"):
        load_key_set({"keys": [{"key_id": "ed", "public_key_pem": pem(ed25519.Ed25519PrivateKey.generate())}]})


def test_an_es256_key_cannot_check_an_mldsa_signature(kit):
    """A key of the wrong type for the alg is reported on that signature, not as a crash."""
    receipt = json.loads((KIT / "valid-settled-1.1.json").read_text())
    swapped = dict(kit["issuer_keys"])
    swapped["sdcstudio-pq-signing-key-v1"] = kit["issuer_keys"]["sdcstudio-signing-key-v1"]
    result = verify(receipt, issuer_keys=swapped, party_keys=kit["party_keys"])
    failed = {c.name: c.detail for c in result.failures}
    assert list(failed) == ["signature[sdcstudio-pq-signing-key-v1]"]
    assert "not an ML-DSA-65 key" in failed["signature[sdcstudio-pq-signing-key-v1]"]

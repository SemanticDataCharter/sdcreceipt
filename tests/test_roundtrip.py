#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Round trip: what this tool signs, this tool verifies.

★ Worth its own file because the two halves are easy to get consistently
wrong. If `sign_trigger` and `verify` disagreed about what a trigger covers,
every test in the other files would still pass — the conformance vectors were
signed by the issuer, not by us, and they exercise verification only.

This is the only place that checks the *signing* side produces something a
verifier accepts, which is the half a counterparty actually uses.
"""

import json
import pathlib

import pytest

from sdcreceipt.party import (
    PartyError,
    generate_key,
    key_document,
    load_key_set,
    public_key_pem,
    sign_trigger,
)
from sdcreceipt.verify import verify

KIT = pathlib.Path(__file__).parent / "conformance"
VENDOR = "https://vendor.example/.well-known/vsl-key.json"
PARTNER = "did:web:partner.example"


@pytest.fixture
def open_receipt():
    """The settled vector with its triggers removed."""
    receipt = json.loads((KIT / "valid-settled.json").read_text())
    receipt["settlement"]["triggers"] = []
    return receipt


@pytest.fixture
def issuer_keys():
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    keys = json.loads((KIT / "keys.json").read_text())
    return {k: load_pem_public_key(v.encode()) for k, v in keys["issuer_keys"].items()}


def test_a_trigger_we_sign_verifies(open_receipt, issuer_keys):
    vendor = generate_key()
    partner = generate_key()

    for key_id, key in ((VENDOR, vendor), (PARTNER, partner)):
        trigger = sign_trigger(key, open_receipt, key_id)
        open_receipt["settlement"]["triggers"].append(
            {
                "key_id": trigger["key_id"],
                "signature": trigger["signature"],
                "timestamp": trigger["timestamp"],
            }
        )

    result = verify(
        open_receipt,
        issuer_keys=issuer_keys,
        party_keys={VENDOR: vendor.public_key(), PARTNER: partner.public_key()},
    )

    assert result.ok, str(result)


def test_appending_triggers_does_not_disturb_receipt_hash(open_receipt, issuer_keys):
    """
    Triggers live outside receipt_hash, which is what lets parties sign days
    apart without invalidating the issuer signature.
    """
    before = verify(open_receipt, issuer_keys=issuer_keys)
    signature_before = [
        c.passed for c in before.checks if c.name.startswith("signature[")
    ]

    vendor = generate_key()
    trigger = sign_trigger(vendor, open_receipt, VENDOR)
    open_receipt["settlement"]["triggers"].append(
        {k: trigger[k] for k in ("key_id", "signature", "timestamp")}
    )

    after = verify(open_receipt, issuer_keys=issuer_keys)
    signature_after = [
        c.passed for c in after.checks if c.name.startswith("signature[")
    ]

    assert signature_before == signature_after == [True]
    assert any(c.name == "receipt_hash" and c.passed for c in after.checks)


def test_a_trigger_does_not_transfer_to_another_receipt(open_receipt, issuer_keys):
    """
    ★ The replay the format binds receipt_id to prevent, from the signing side.
    Two settlements, same release condition, which is the normal case.
    """
    other = json.loads((KIT / "valid-settled.json").read_text())
    other["settlement"]["triggers"] = []
    other["receipt_id"] = "zq4wt8nx2mvhc6bdjrkfsy93"

    assert (
        other["settlement"]["condition_hash"]
        == open_receipt["settlement"]["condition_hash"]
    )

    vendor = generate_key()
    trigger = sign_trigger(vendor, open_receipt, VENDOR)

    # Replay it onto the other Receipt.
    other["settlement"]["triggers"].append(
        {k: trigger[k] for k in ("key_id", "signature", "timestamp")}
    )

    result = verify(
        other, issuer_keys=issuer_keys, party_keys={VENDOR: vendor.public_key()}
    )

    assert not result.ok
    assert any(c.name == f"trigger[{VENDOR}]" for c in result.failures)


def test_a_published_key_document_round_trips(open_receipt, issuer_keys):
    """
    `init` produces the document a party publishes; a verifier must be able to
    read it back into a usable key. If these two drifted, onboarding would
    produce a file that verifies nothing.
    """
    vendor = generate_key()
    document = key_document(vendor, VENDOR)

    keys = load_key_set(document)
    assert VENDOR in keys
    assert public_key_pem(keys[VENDOR]) == public_key_pem(vendor)

    trigger = sign_trigger(vendor, open_receipt, VENDOR)
    open_receipt["settlement"]["triggers"].append(
        {k: trigger[k] for k in ("key_id", "signature", "timestamp")}
    )

    result = verify(
        open_receipt, issuer_keys=issuer_keys, party_keys={VENDOR: keys[VENDOR]}
    )
    assert any(
        c.name == f"trigger[{VENDOR}]" and c.passed for c in result.checks
    ), str(result)


def test_signing_twice_is_refused(open_receipt):
    """A second trigger from one party adds no authorization."""
    vendor = generate_key()
    trigger = sign_trigger(vendor, open_receipt, VENDOR)
    open_receipt["settlement"]["triggers"].append(
        {k: trigger[k] for k in ("key_id", "signature", "timestamp")}
    )

    with pytest.raises(PartyError, match="already triggered"):
        sign_trigger(vendor, open_receipt, VENDOR)


def test_signing_for_a_key_id_you_are_not_is_refused(open_receipt):
    """
    Caught locally rather than after a round trip, because the Receipt already
    says who the parties are.
    """
    with pytest.raises(PartyError, match="not a party"):
        sign_trigger(generate_key(), open_receipt, "https://stranger.example/k.json")

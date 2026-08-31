#!/usr/bin/env python3
#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
One settlement, end to end, with nothing from us.

Run it:

    pip install sdcreceipt
    python examples/settle.py

No account, no network, no API key. It uses the Receipt shipped in the
conformance kit, generates two party keys on the spot, has both parties sign,
and verifies the result. Everything it writes lands in `examples/out/`.

★ Why this file exists. The open question in VSL-PRD §13.6 is not "can a
counterparty implement this", it is "will a pair try it". A README does not get
forwarded to the receiving side. A script that runs and prints VERIFIED does.
"""

import json
import pathlib
import sys

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from sdcreceipt.party import (
    generate_key,
    key_document,
    private_key_pem,
    sign_trigger,
)
from sdcreceipt.verify import verify

HERE = pathlib.Path(__file__).parent
KIT = HERE.parent / "tests" / "conformance"
OUT = HERE / "out"

VENDOR = "https://vendor.example/.well-known/vsl-key.json"
PARTNER = "did:web:partner.example"


def step(n, text):
    print(f"\n{n}. {text}")


def main() -> int:
    OUT.mkdir(exist_ok=True)

    step(1, "The issuer settles, and hands each party a Receipt.")
    # Normally this comes from POST /api/v1/vsl/settle. Here it is the
    # conformance vector, so the example needs no account.
    receipt = json.loads((KIT / "valid-settled.json").read_text())
    receipt["settlement"]["triggers"] = []
    print(f"   receipt_id      {receipt['receipt_id']}")
    print(f"   condition_hash  {receipt['settlement']['condition_hash'][:32]}...")
    print(f"   parties         {', '.join(receipt['settlement']['parties'])}")
    (OUT / "1-receipt-as-issued.json").write_text(json.dumps(receipt, indent=2))

    step(2, "Each party generates a keypair and publishes a key document.")
    # `sdcreceipt init --key-id <uri>` does exactly this at a terminal.
    keys = {}
    for key_id, name in ((VENDOR, "vendor"), (PARTNER, "partner")):
        key = generate_key()
        keys[key_id] = key
        (OUT / f"2-{name}-key.pem").write_bytes(private_key_pem(key))
        doc = key_document(key, key_id)
        (OUT / f"2-{name}-key-document.json").write_text(json.dumps(doc, indent=2))
        print(f"   {name:8} publishes its public key at {key_id}")

    print("\n   ★ The key_id is a URI the PARTY controls, not one we issue.")
    print("     That is what keeps verification independent of us.")

    step(3, "Each party signs a trigger. Alone, and in any order.")
    for key_id, name in ((PARTNER, "partner"), (VENDOR, "vendor")):
        # Partner first, deliberately: the order is not the order in `parties`.
        trigger = sign_trigger(keys[key_id], receipt, key_id)
        receipt["settlement"]["triggers"].append(
            {
                "key_id": trigger["key_id"],
                "signature": trigger["signature"],
                "timestamp": trigger["timestamp"],
            }
        )
        (OUT / f"3-{name}-trigger.json").write_text(json.dumps(trigger, indent=2))
        print(f"   {name:8} signed  {trigger['signature'][:24]}...")

    print("\n   ★ Both signed {condition_hash, receipt_id}, which was fixed")
    print("     before either of them started. That is why they can sign")
    print("     independently, and why neither signature can be replayed")
    print("     into a different settlement.")

    step(4, "Anyone verifies. Offline.")
    issuer_keys = {
        k: load_pem_public_key(v.encode())
        for k, v in json.loads((KIT / "keys.json").read_text())["issuer_keys"].items()
    }
    result = verify(
        receipt,
        issuer_keys=issuer_keys,
        party_keys={k: v.public_key() for k, v in keys.items()},
    )

    (OUT / "4-receipt-settled.json").write_text(json.dumps(receipt, indent=2))
    (OUT / "4-verification.txt").write_text(str(result))

    for check in result.checks:
        print(f"   {'PASS' if check.passed else 'FAIL'}  {check.name}")

    print()
    if result.ok:
        print("   VERIFIED. No network was used. Nothing was asked of the issuer.")
    else:
        print("   FAILED:", ", ".join(c.name for c in result.failures))

    print(f"\nArtifacts in {OUT.relative_to(pathlib.Path.cwd()) if OUT.is_relative_to(pathlib.Path.cwd()) else OUT}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())

#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Command line interface.

    sdcreceipt verify  receipt.json --keys keys.json
    sdcreceipt init    --key-id https://vendor.example/.well-known/vsl-key.json
    sdcreceipt trigger receipt.json --key party.pem --key-id <id>

`verify` exits 0 only if every check passed, so it composes in a shell without
anyone having to parse the output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sdcreceipt import __version__
from sdcreceipt.party import (
    PartyError,
    generate_key,
    key_document,
    load_key_set_file,
    load_private_key,
    publication_path,
    sign_trigger,
    write_private_key,
)
from sdcreceipt.verify import verify


def _load_json(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise SystemExit(f"error: no {what} at {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON: {exc}")


def cmd_verify(args) -> int:
    receipt = _load_json(Path(args.receipt), "receipt")

    issuer_keys = {}
    party_keys = None
    if args.keys:
        try:
            keyset = load_key_set_file(Path(args.keys))
        except PartyError as exc:
            raise SystemExit(f"error: {exc}")
        # One file may carry both; the Receipt says which id is which.
        issuer_ids = {s.get("key_id") for s in receipt.get("signatures", [])}
        issuer_keys = {k: v for k, v in keyset.items() if k in issuer_ids}
        party_keys = {k: v for k, v in keyset.items() if k not in issuer_ids} or None

    schema = _load_json(Path(args.schema), "schema") if args.schema else None
    governance = (
        _load_json(Path(args.governance), "governance receipt")
        if args.governance
        else None
    )
    payload = Path(args.payload).read_bytes() if args.payload else None

    result = verify(
        receipt,
        issuer_keys=issuer_keys,
        party_keys=party_keys,
        schema=schema,
        governance_receipt=governance,
        payload=payload,
    )

    print(result)
    if result.ok:
        print("\nVERIFIED")
        return 0

    print(f"\nNOT VERIFIED - {len(result.failures)} check(s) failed")
    if not args.keys:
        print(
            "\nNo --keys given, so no signature could be checked. Fetch the "
            "issuer's published key set and pass it; never take a key from a "
            "location inside the Receipt."
        )
    return 1


def cmd_init(args) -> int:
    key_id = args.key_id
    try:
        publish_at = publication_path(key_id)
    except PartyError as exc:
        raise SystemExit(f"error: {exc}")

    key = generate_key()
    private_path = Path(args.out)
    document_path = private_path.with_name(private_path.stem + "-key-document.json")

    try:
        write_private_key(key, private_path)
    except PartyError as exc:
        raise SystemExit(f"error: {exc}")

    document_path.write_text(json.dumps(key_document(key, key_id), indent=2) + "\n")

    print(f"private key      {private_path}  (mode 0600, keep it)")
    print(f"key document     {document_path}")
    print()
    print("Publish the key document so it is reachable, unauthenticated, at:")
    print(f"  {publish_at}")
    print()
    print(
        "Until it is reachable there, a verifier cannot resolve your triggers.\n"
        "Give the issuer this key_id when the settlement is created:\n"
        f"  {key_id}"
    )
    return 0


def cmd_trigger(args) -> int:
    receipt = _load_json(Path(args.receipt), "receipt")

    try:
        key = load_private_key(Path(args.key))
        trigger = sign_trigger(key, receipt, args.key_id)
    except PartyError as exc:
        raise SystemExit(f"error: {exc}")

    body = json.dumps(trigger, indent=2)

    if not args.submit:
        # Default: print and stop. Signing is inert and pipeable; submitting
        # is a side effect and should be asked for.
        print(body)
        print(
            "\n# Not submitted. Send it with --submit <url>, or pipe this to "
            "whatever you use.",
            file=sys.stderr,
        )
        return 0

    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        args.submit,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            print(response.read().decode("utf-8"))
        return 0
    except urllib.error.HTTPError as exc:
        print(f"error: {exc.code} from {args.submit}", file=sys.stderr)
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"error: could not reach {args.submit}: {exc.reason}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdcreceipt",
        description="Verify and settle VSL Settlement Receipts.",
    )
    parser.add_argument("--version", action="version", version=f"sdcreceipt {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("verify", help="verify a Receipt (no network, no account)")
    p.add_argument("receipt")
    p.add_argument("--keys", help="published key set, JSON")
    p.add_argument("--schema", help="the published JSON Schema")
    p.add_argument("--governance", help="the governance Receipt, if held")
    p.add_argument("--payload", help="the payload, if held")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("init", help="generate a keypair and the document to publish")
    p.add_argument("--key-id", required=True, help="https:// URL or did:web: identifier")
    p.add_argument("--out", default="vsl-party.pem", help="private key path")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("trigger", help="sign a trigger for a settlement")
    p.add_argument("receipt")
    p.add_argument("--key", required=True, help="your private key")
    p.add_argument("--key-id", required=True, help="your key_id, as listed on the settlement")
    p.add_argument("--submit", metavar="URL", help="POST it rather than printing it")
    p.set_defaults(func=cmd_trigger)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

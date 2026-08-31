#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Command line interface.

    sdcreceipt verify  receipt.json --keys keys.json
    sdcreceipt init    --key-id https://vendor.example/.well-known/vsl-key.json
    sdcreceipt settle  payload.xml --party <id> --party <id>
    sdcreceipt trigger receipt.json --key party.pem --key-id <id>

`settle` asks an issuer for a Receipt and is the only verb needing an account.
It prompts for anything it needs and was not given, because two of its fields
are not guessable: the condition is hashed and never stored, and the states
come from a workflow defined in a schema the issuer holds. It exits 2 on a
refused transition, which is recoverable, and 1 on a failure, which is not.

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
from sdcreceipt.issue import (
    DEFAULT_ENDPOINT,
    SettleError,
    SettleRejected,
    settle,
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


def _ask(prompt: str, *, default: str = "") -> str:
    """
    Ask for one value, or explain why we cannot.

    ★ Only when someone is there to answer. Prompting from a script or a CI
    job hangs forever on a read that will never come, which looks like a
    network stall and is the worst way to learn a flag was missing.
    """
    if not sys.stdin.isatty():
        raise SystemExit(
            f"error: missing --{prompt.split()[0].strip(':').replace('_', '-')} "
            "and stdin is not a terminal, so there is nobody to ask. "
            "Pass it as a flag."
        )
    shown = f"{prompt} [{default}] " if default else f"{prompt} "
    try:
        answer = input(shown).strip()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\ncancelled")
    return answer or default


def cmd_settle(args) -> int:
    payload_path = Path(args.payload)
    try:
        payload = payload_path.read_text()
    except FileNotFoundError:
        raise SystemExit(f"error: no payload at {payload_path}")

    token = args.token
    if not token:
        import os

        token = os.environ.get("SDCRECEIPT_TOKEN", "")
    if not token:
        # Asked for, never defaulted, and never echoed into a shell history by
        # us. The environment variable is the better habit and is named here.
        token = _ask("API token (or set SDCRECEIPT_TOKEN):")
    if not token:
        raise SystemExit("error: issuing needs a token. Everything else here does not.")

    current_state = args.current_state or _ask("current_state:")
    target_state = args.target_state or _ask("target_state:")

    if args.condition:
        try:
            condition = json.loads(args.condition)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"error: --condition is not valid JSON: {exc}")
    elif args.condition_file:
        condition = _load_json(Path(args.condition_file), "condition")
    else:
        print(
            "\nThe release condition is hashed by the issuer and never stored, "
            "so it can hold\nterms neither party wants published. Give it as "
            'JSON, e.g. {"on": "goods received"}.',
            file=sys.stderr,
        )
        raw = _ask("condition:")
        try:
            condition = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"error: that is not valid JSON: {exc}")
    if not isinstance(condition, dict):
        raise SystemExit("error: the condition must be a JSON object.")

    parties = list(args.party or [])
    if len(set(parties)) < 2:
        print(
            "\nA settlement needs at least two parties. Each is a key_id URI "
            "that party\ncontrols (https://... or did:web:...), which is what "
            "lets a verifier check\ntheir signature without asking the issuer.",
            file=sys.stderr,
        )
        while len(set(parties)) < 2:
            nth = "first" if not parties else "next"
            value = _ask(f"{nth} party key_id:")
            if value:
                parties.append(value)

    try:
        receipt = settle(
            payload,
            endpoint=args.endpoint,
            token=token,
            current_state=current_state,
            target_state=target_state,
            condition=condition,
            parties=parties,
            previous_receipt_id=args.previous or "",
        )
    except SettleRejected as exc:
        # ★ The whole reason the issuer returns this shape. Printing the status
        # code and stopping would throw away the only answer to "then what
        # should I have said?"
        print(exc.explain(), file=sys.stderr)
        return 2
    except SettleError as exc:
        raise SystemExit(f"error: {exc}")

    body = json.dumps(receipt, indent=2)
    if args.out:
        Path(args.out).write_text(body)
        print(f"receipt {receipt.get('receipt_id', '')} -> {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


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

    p = sub.add_parser(
        "settle",
        help="ask an issuer for a Receipt (the one verb that needs an account)",
    )
    p.add_argument("payload", help="the SDC4 XML instance to settle")
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="issuer settle URL")
    p.add_argument("--token", help="API token; or set SDCRECEIPT_TOKEN")
    p.add_argument("--current-state", dest="current_state")
    p.add_argument("--target-state", dest="target_state")
    p.add_argument("--condition", help='release condition as JSON, e.g. \'{"on":"goods received"}\'')
    p.add_argument("--condition-file", dest="condition_file", help="the condition, from a file")
    p.add_argument("--party", action="append", help="a party key_id; give it twice or more")
    p.add_argument("--previous", help="receipt_id to chain onto")
    p.add_argument("--out", help="write the Receipt here instead of stdout")
    p.set_defaults(func=cmd_settle)

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

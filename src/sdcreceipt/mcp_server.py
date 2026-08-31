#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
MCP stdio server for `sdcreceipt`.

`sdcvalidator` and `sdcgovernance` are both registered MCP servers, so an agent
can already validate an instance and evaluate governance over it. It could not
settle, which left the chain one verb short of the thing VSL exists to do. This
closes that gap.

**Two tools, not three.** The CLI has `verify`, `init` and `trigger`; this
exposes `verify_receipt` and `sign_trigger` and stops there. The omissions are
the design, not an oversight:

`init` is not exposed because it generates a private key, and a private key
generated inside an agent session has no clear custody story. Key generation
stays a human act at a terminal.

`submit_trigger` is not exposed because it would be the one tool that reaches
the network, and therefore the one that could be pointed at an arbitrary host.
The SSRF guards that protect party key resolution live on the VSL server, not
here. A signed trigger is inert and safe to hand back; posting it is a side
effect a human or a queue should own. Decided 2026-08-31 (Tim): take the
conservative default, because loosening this later is safe and tightening it
after something has shipped is not.

**The signing key is configured at server start, never passed per call.** The
CLI takes `--key party.pem` on each invocation, which is right for a terminal
and wrong here: a key path arriving in tool arguments means the key travels
through the conversation and whatever records it. Binding the key to the server
process at launch keeps it out of the transcript, and means an operator decides
once which identity this server can sign as.

Reuse, do not reimplement: every tool calls the same functions the CLI calls. If
the two interfaces ever produce different bytes for one Receipt, the product is
broken.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from sdcreceipt import __version__
from sdcreceipt.party import PartyError, load_key_set, load_private_key, sign_trigger
from sdcreceipt.verify import verify

JSONRPC_VERSION = "2.0"

#: Newest revision this server implements. `initialize` negotiates rather than
#: asserting, so a client on an older supported revision is honoured.
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-11-25")

SERVER_NAME = "sdcreceipt"
SERVER_VERSION = __version__

#: Set once by `main()` from --key/--key-id, never from tool arguments.
_SIGNING_KEY_PATH: Path | None = None
_SIGNING_KEY_ID: str | None = None


TOOLS = [
    {
        "name": "verify_receipt",
        "description": (
            "Verify a VSL Settlement Receipt. Runs every check and reports all "
            "of them, including the ones that passed, rather than stopping at "
            "the first failure. Requires no network and no account: the issuer "
            "key document is supplied by the caller. Use this to decide whether "
            "a Receipt you were sent is trustworthy before acting on it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt": {
                    "type": "object",
                    "description": "The Settlement Receipt document to verify.",
                },
                "issuer_keys": {
                    "type": "object",
                    "description": (
                        "The issuer's published key document, as JSON. Either "
                        "the key-set shape with a `keys` array, or a did:web "
                        "DID document."
                    ),
                },
                "party_keys": {
                    "type": "object",
                    "description": (
                        "Optional. Party key document, to verify triggers. "
                        "Omitting it skips the trigger check, which is honest "
                        "when the keys are not held; the result says so."
                    ),
                },
                "governance_receipt": {
                    "type": "object",
                    "description": "Optional. The governance Receipt, if held.",
                },
            },
            "required": ["receipt", "issuer_keys"],
        },
    },
    {
        "name": "sign_trigger",
        "description": (
            "Sign a trigger for a settlement, using the key this server was "
            "started with. Signs {condition_hash, receipt_id}, which is fixed "
            "before either party signs, so parties can sign alone and in any "
            "order while the signature cannot be replayed into another "
            "settlement. Returns the signed trigger WITHOUT submitting it: "
            "this server never reaches the network. Hand the result to whoever "
            "owns submission."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt": {
                    "type": "object",
                    "description": "The Receipt whose settlement is being triggered.",
                },
                "key_id": {
                    "type": "string",
                    "description": (
                        "Optional. The party key_id to sign as. Defaults to the "
                        "--key-id this server was started with. Must be one of "
                        "the Receipt's listed parties."
                    ),
                },
            },
            "required": ["receipt"],
        },
    },
]


def _handle_verify_receipt(args: dict[str, Any]) -> Any:
    receipt = args["receipt"]
    issuer_keys = load_key_set(args["issuer_keys"])

    party_keys = None
    if args.get("party_keys"):
        party_keys = load_key_set(args["party_keys"])

    result = verify(
        receipt,
        issuer_keys=issuer_keys,
        party_keys=party_keys,
        governance_receipt=args.get("governance_receipt"),
    )

    return {
        "verified": result.ok,
        "checks": [
            {"name": c.name, "passed": c.passed, "detail": c.detail}
            for c in result.checks
        ],
        "failures": [c.name for c in result.failures],
        # Named so a reader cannot mistake an unrun check for a passed one.
        "trigger_signatures_checked": party_keys is not None,
    }


def _handle_sign_trigger(args: dict[str, Any]) -> Any:
    if _SIGNING_KEY_PATH is None:
        raise PartyError(
            "This server was started without a signing key, so it can verify "
            "but not sign. Restart it with --key <path> --key-id <uri>."
        )

    key_id = args.get("key_id") or _SIGNING_KEY_ID
    if not key_id:
        raise PartyError(
            "No key_id. Pass one, or start the server with --key-id <uri>."
        )

    key = load_private_key(_SIGNING_KEY_PATH)
    trigger = sign_trigger(key, args["receipt"], key_id)

    return {
        "trigger": trigger,
        "submitted": False,
        "next_step": (
            "Not submitted. This server does not reach the network by design. "
            "POST this to the VSL trigger endpoint yourself, or hand it to "
            "whatever owns submission."
        ),
    }


TOOL_HANDLERS = {
    "verify_receipt": _handle_verify_receipt,
    "sign_trigger": _handle_sign_trigger,
}


def _jsonrpc_response(id: Any, result: Any) -> dict:
    """Build a JSON-RPC 2.0 success response."""
    return {"jsonrpc": JSONRPC_VERSION, "id": id, "result": result}


def _jsonrpc_error(id: Any, code: int, message: str, data: Any = None) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": id, "error": error}


def _handle_request(request: dict) -> dict | None:
    """
    Handle a single JSON-RPC 2.0 request.

    Returns a response dict, or None for notifications (no id).
    """
    method = request.get("method", "")
    params = request.get("params", {})
    req_id = request.get("id")

    if method == "initialize":
        # Negotiate rather than assert: honour the client's revision when we
        # implement it, otherwise answer with our newest and let the client
        # decide whether to continue.
        requested = params.get("protocolVersion")
        negotiated = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else MCP_PROTOCOL_VERSION
        )
        can_sign = _SIGNING_KEY_PATH is not None
        return _jsonrpc_response(
            req_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Verify and settle VSL Settlement Receipts. `verify_receipt` "
                    "needs no network and no account. `sign_trigger` signs with "
                    "the key this server was started with and returns the trigger "
                    "unsubmitted; this server never reaches the network. "
                    + (
                        f"Signing is available as {_SIGNING_KEY_ID}."
                        if can_sign
                        else "No signing key was configured, so signing is "
                        "unavailable and only verification will work."
                    )
                ),
            },
        )

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        # A server with no key advertises only what it can actually do, rather
        # than offering a tool whose every call would fail.
        tools = TOOLS if _SIGNING_KEY_PATH is not None else [TOOLS[0]]
        return _jsonrpc_response(req_id, {"tools": tools})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return _jsonrpc_error(req_id, -32601, f"Unknown tool: {tool_name}")

        try:
            result = handler(tool_args)
            return _jsonrpc_response(
                req_id,
                {"content": [{"type": "text", "text": json.dumps(result, default=str)}]},
            )
        except Exception as exc:
            # SEP-1303: execution and input-validation failures are tool errors,
            # not protocol errors. Returned in the result so the calling model
            # can see what went wrong and correct itself; a JSON-RPC error is
            # invisible to it.
            return _jsonrpc_response(
                req_id,
                {
                    "content": [{"type": "text", "text": f"Tool execution error: {exc}"}],
                    "isError": True,
                },
            )

    elif method == "ping":
        return _jsonrpc_response(req_id, {})

    else:
        if req_id is not None:
            return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")
        return None


def run_stdio() -> None:
    """
    Run the MCP server on stdio.

    Reads JSON-RPC 2.0 messages from stdin (one per line), processes them, and
    writes responses to stdout. stdio and no SDK, matching `sdcgovernance` and
    `sdcvalidator`: that is what made both immune to the MCP 2.0 HTTP transport
    change of 2026-07-28.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
            continue

        response = _handle_request(request)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


def main(argv: list[str] | None = None) -> None:
    """Entry point for `sdcreceipt-mcp`."""
    import argparse

    global _SIGNING_KEY_PATH, _SIGNING_KEY_ID

    parser = argparse.ArgumentParser(
        prog="sdcreceipt-mcp",
        description="MCP stdio server for verifying and settling VSL Receipts.",
    )
    parser.add_argument(
        "--key",
        type=Path,
        help=(
            "Private key PEM to sign triggers with. Configured here rather than "
            "per call so the key never travels through the conversation. "
            "Omit to run verify-only."
        ),
    )
    parser.add_argument(
        "--key-id",
        help="The party key_id this server signs as: a URI you control.",
    )
    args = parser.parse_args(argv)

    if args.key and not args.key_id:
        parser.error("--key needs --key-id: a signature is only meaningful with the URI it is attributed to.")
    if args.key_id and not args.key:
        parser.error("--key-id without --key cannot sign anything.")

    if args.key:
        if not args.key.exists():
            parser.error(f"no such key file: {args.key}")
        # Fail at start rather than on the first call: an operator watching a
        # launch will see this, and an agent mid-task will not.
        try:
            load_private_key(args.key)
        except PartyError as exc:
            parser.error(str(exc))
        _SIGNING_KEY_PATH = args.key
        _SIGNING_KEY_ID = args.key_id

    run_stdio()


if __name__ == "__main__":
    main()

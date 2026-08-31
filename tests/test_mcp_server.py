#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
The MCP server.

Two things carry the weight here, and neither is the JSON-RPC plumbing.

**The omissions have to stay omitted.** `init` and `submit_trigger` were left
out deliberately: one generates a private key, the other reaches the network.
Both are the kind of thing a later change adds back for convenience without
anyone noticing, so the absence is asserted rather than assumed.

**The two interfaces must agree.** The CLI and the MCP server share `verify.py`
and `party.py`, and the point of that sharing is that a Receipt gets the same
answer either way. A test that only exercised the server would not notice them
drifting apart.
"""

import json
import pathlib

import pytest

from sdcreceipt import mcp_server
from sdcreceipt.party import (
    generate_key,
    key_document,
    private_key_pem,
    sign_trigger,
)
from sdcreceipt.verify import verify

KIT = pathlib.Path(__file__).parent / "conformance"
VENDOR = "https://vendor.example/.well-known/vsl-key.json"
PARTNER = "did:web:partner.example"


@pytest.fixture
def open_receipt():
    receipt = json.loads((KIT / "valid-settled.json").read_text())
    receipt["settlement"]["triggers"] = []
    return receipt


@pytest.fixture
def settled_receipt():
    return json.loads((KIT / "valid-settled.json").read_text())


@pytest.fixture
def issuer_key_document():
    """The issuer keys in the published document shape the tool accepts."""
    keys = json.loads((KIT / "keys.json").read_text())
    return {
        "keys": [
            {"key_id": k, "public_key_pem": v}
            for k, v in keys["issuer_keys"].items()
        ]
    }


@pytest.fixture
def signing_server(tmp_path):
    """A server configured with a key, as `main()` would leave it."""
    key = generate_key()
    path = tmp_path / "party.pem"
    path.write_bytes(private_key_pem(key))

    mcp_server._SIGNING_KEY_PATH = path
    mcp_server._SIGNING_KEY_ID = VENDOR
    yield key
    mcp_server._SIGNING_KEY_PATH = None
    mcp_server._SIGNING_KEY_ID = None


@pytest.fixture
def verify_only_server():
    mcp_server._SIGNING_KEY_PATH = None
    mcp_server._SIGNING_KEY_ID = None
    yield


def call(name, arguments):
    """Drive a tool the way a client would, through the dispatcher."""
    response = mcp_server._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    return response["result"]


def payload(result):
    return json.loads(result["content"][0]["text"])


class TestTheOmissionsStayOmitted:
    """
    ★ The security posture of this server is what it does NOT expose. These
    tests exist so adding either back is a deliberate act with a failing test
    in front of it, not a convenience someone slips in.
    """

    def test_no_tool_generates_a_private_key(self, signing_server):
        names = {t["name"] for t in mcp_server.TOOLS}
        assert "init" not in names
        assert not any("init" in n or "generate" in n or "keygen" in n for n in names)

    def test_no_tool_submits_anything(self, signing_server):
        names = {t["name"] for t in mcp_server.TOOLS}
        assert "submit_trigger" not in names
        assert not any("submit" in n or "post" in n or "send" in n for n in names)

    def test_the_server_module_makes_no_network_calls(self):
        """
        Grep-level, deliberately. The claim being defended is "this server never
        reaches the network", and the cheapest durable way to hold it is to
        assert that nothing in the module can.
        """
        source = pathlib.Path(mcp_server.__file__).read_text()
        for forbidden in ("urllib", "requests", "httpx", "socket", "urlopen"):
            assert forbidden not in source, f"{forbidden} appeared in the MCP server"

    def test_signing_reports_that_it_did_not_submit(self, signing_server, open_receipt):
        body = payload(call("sign_trigger", {"receipt": open_receipt}))
        assert body["submitted"] is False
        assert "not submitted" in body["next_step"].lower()


class TestTheKeyIsNotTakenFromTheCaller:
    """
    ★ The other half of the posture. A key path arriving in tool arguments
    would put the key in the conversation, which is what configuring it at
    start-up avoids.
    """

    def test_no_tool_accepts_a_key_path(self):
        for tool in mcp_server.TOOLS:
            props = tool["inputSchema"]["properties"]
            assert "key" not in props
            assert "key_path" not in props
            assert "private_key" not in props

    def test_signing_uses_the_configured_key(self, signing_server, open_receipt):
        body = payload(call("sign_trigger", {"receipt": open_receipt}))
        assert body["trigger"]["key_id"] == VENDOR

    def test_a_verify_only_server_refuses_to_sign(self, verify_only_server, open_receipt):
        result = call("sign_trigger", {"receipt": open_receipt})
        assert result.get("isError") is True
        assert "without a signing key" in result["content"][0]["text"]

    def test_a_verify_only_server_does_not_advertise_signing(self, verify_only_server):
        response = mcp_server._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        names = {t["name"] for t in response["result"]["tools"]}
        assert names == {"verify_receipt"}


class TestVerify:
    def test_a_valid_receipt_verifies(self, verify_only_server, settled_receipt, issuer_key_document):
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert body["verified"] is True
        assert body["failures"] == []

    def test_a_tampered_receipt_fails(self, verify_only_server, settled_receipt, issuer_key_document):
        settled_receipt["payload_hash"] = "f" * 64
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert body["verified"] is False
        assert body["failures"]

    def test_every_check_is_reported_not_just_failures(
        self, verify_only_server, settled_receipt, issuer_key_document
    ):
        """Reporting only failures hides which checks actually ran."""
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert len(body["checks"]) > 1
        assert all("name" in c and "passed" in c for c in body["checks"])

    def test_an_unrun_trigger_check_is_named_as_unrun(
        self, verify_only_server, settled_receipt, issuer_key_document
    ):
        """
        ★ Silence about a check that did not run is how a verifier starts lying.
        Without party keys the trigger signatures cannot be checked, and the
        result has to say so rather than reporting a clean pass.
        """
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert body["trigger_signatures_checked"] is False


class TestTheTwoInterfacesAgree:
    """
    ★ The reason one package ships both. If these ever disagree, the product is
    broken in the way that is hardest to notice.
    """

    def test_mcp_signing_produces_a_trigger_the_library_verifies(
        self, signing_server, open_receipt, issuer_key_document
    ):
        from sdcreceipt.party import load_key_set

        body = payload(call("sign_trigger", {"receipt": open_receipt}))
        trigger = body["trigger"]

        partner = generate_key()
        open_receipt["settlement"]["triggers"] = [
            {
                "key_id": trigger["key_id"],
                "signature": trigger["signature"],
                "timestamp": trigger["timestamp"],
            },
            dict(sign_trigger(partner, open_receipt, PARTNER)),
        ]

        result = verify(
            open_receipt,
            issuer_keys=load_key_set(issuer_key_document),
            party_keys={
                VENDOR: signing_server.public_key(),
                PARTNER: partner.public_key(),
            },
        )
        assert result.ok, result.failures

    def test_mcp_verify_matches_the_library(
        self, verify_only_server, settled_receipt, issuer_key_document
    ):
        from sdcreceipt.party import load_key_set

        direct = verify(
            settled_receipt, issuer_keys=load_key_set(issuer_key_document)
        )
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert body["verified"] is direct.ok
        assert [c["name"] for c in body["checks"]] == [c.name for c in direct.checks]


class TestProtocol:
    def test_initialize_negotiates_a_supported_version(self, verify_only_server):
        response = mcp_server._handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            }
        )
        assert response["result"]["protocolVersion"] == "2025-06-18"

    def test_an_unknown_version_falls_back_to_ours(self, verify_only_server):
        response = mcp_server._handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "1999-01-01"},
            }
        )
        assert response["result"]["protocolVersion"] == mcp_server.MCP_PROTOCOL_VERSION

    def test_instructions_say_whether_signing_is_available(self, verify_only_server):
        response = mcp_server._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert "unavailable" in response["result"]["instructions"]

    def test_a_tool_failure_is_a_tool_error_not_a_protocol_error(
        self, signing_server, settled_receipt
    ):
        """
        SEP-1303. A JSON-RPC error is invisible to the calling model, so a
        recoverable failure has to come back in the result.
        """
        result = call("sign_trigger", {"receipt": settled_receipt})
        assert result.get("isError") is True
        assert "error" in result["content"][0]["text"].lower()

    def test_an_unknown_tool_is_a_protocol_error(self, verify_only_server):
        response = mcp_server._handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "nope", "arguments": {}},
            }
        )
        assert response["error"]["code"] == -32601

    def test_notifications_get_no_response(self, verify_only_server):
        assert (
            mcp_server._handle_request(
                {"jsonrpc": "2.0", "method": "notifications/initialized"}
            )
            is None
        )

    def test_malformed_json_does_not_kill_the_server(self, verify_only_server, monkeypatch, capsys):
        import io as _io

        monkeypatch.setattr("sys.stdin", _io.StringIO('{"bad json\n{"jsonrpc":"2.0","id":9,"method":"ping"}\n'))
        mcp_server.run_stdio()

        lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
        assert json.loads(lines[0])["error"]["code"] == -32700
        assert json.loads(lines[1])["id"] == 9


class TestStartup:
    def test_a_key_without_a_key_id_is_refused(self, tmp_path):
        path = tmp_path / "k.pem"
        path.write_bytes(private_key_pem(generate_key()))
        with pytest.raises(SystemExit):
            mcp_server.main(["--key", str(path)])

    def test_a_key_id_without_a_key_is_refused(self):
        with pytest.raises(SystemExit):
            mcp_server.main(["--key-id", VENDOR])

    def test_a_missing_key_file_fails_at_startup(self, tmp_path):
        """
        An operator watching a launch sees this. An agent mid-task does not.
        """
        with pytest.raises(SystemExit):
            mcp_server.main(
                ["--key", str(tmp_path / "absent.pem"), "--key-id", VENDOR]
            )

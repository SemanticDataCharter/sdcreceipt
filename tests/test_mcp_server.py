#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
The MCP server.

Two things carry the weight here, and neither is the JSON-RPC plumbing.

**The omissions have to stay omitted.** `init` generates a private key and
`submit_trigger` would take a destination from the caller. Both are the kind of
thing a later change adds back for convenience without anyone noticing, so the
absence is asserted rather than assumed.

**No tool may take a URL.** `settle` reaches the network, so "this server makes
no connections" is not the guarantee any more. The one that replaced it is that
every destination is fixed at start-up, and a caller can never choose one.

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
def party_key_document():
    """The party keys, in the same published document shape."""
    keys = json.loads((KIT / "keys.json").read_text())
    return {
        "keys": [
            {"key_id": k, "public_key_pem": v}
            for k, v in keys["party_keys"].items()
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
    mcp_server._ISSUER_ENDPOINT = None
    mcp_server._ISSUER_TOKEN = None
    yield key
    mcp_server._SIGNING_KEY_PATH = None
    mcp_server._SIGNING_KEY_ID = None


@pytest.fixture
def verify_only_server():
    mcp_server._SIGNING_KEY_PATH = None
    mcp_server._SIGNING_KEY_ID = None
    mcp_server._ISSUER_ENDPOINT = None
    mcp_server._ISSUER_TOKEN = None
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

    def test_no_tool_takes_a_url(self):
        """
        ★ The invariant that replaced "this server never reaches the network".

        `settle` made the old claim false: it posts to an issuer. What keeps
        that safe is not abstinence but that the destination is fixed at
        start-up, so a caller cannot choose it. Encoded as: no tool argument
        may be a URL, an endpoint, or a host.

        This is the property to defend if anyone adds a tool. `submit_trigger`
        was refused for failing exactly this test.
        """
        for tool in mcp_server.TOOLS:
            for name, spec in tool["inputSchema"]["properties"].items():
                assert name not in ("url", "endpoint", "host", "submit_to", "target_url"), (
                    f"{tool['name']} takes {name!r}, which lets a caller choose "
                    "where this server connects"
                )
                described = (spec.get("description") or "").lower()
                assert "url to post" not in described

    def test_the_only_destination_is_the_configured_one(self, signing_server):
        """
        `settle` is the sole networked tool, and it must refuse rather than
        invent a destination when none was configured.
        """
        result = call(
            "settle",
            {
                "payload": "<root/>",
                "current_state": "draft",
                "target_state": "review",
                "condition": {"on": "x"},
                "parties": ["https://a.example/k.json", "did:web:b.example"],
            },
        )
        assert result.get("isError") is True
        assert "without an issuer" in result["content"][0]["text"]

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

    def test_no_tool_lets_the_caller_choose_an_identity(self):
        """
        Regression for the 4.2.0 defect.

        The key never travelled through the conversation, but until 4.2.1 the
        identity did: `sign_trigger` took an optional `key_id` that overrode
        `--key-id`, so a session caller could pick which listed party this
        server signed as.
        """
        for tool in mcp_server.TOOLS:
            if tool["name"] == "sign_trigger":
                assert "key_id" not in tool["inputSchema"]["properties"]

    def test_signing_refuses_a_caller_supplied_identity(self, signing_server, open_receipt):
        result = call("sign_trigger", {"receipt": open_receipt, "key_id": PARTNER})
        assert result.get("isError") is True
        assert "not selectable" in result["content"][0]["text"]

    def test_signing_ignores_nothing_and_still_signs_as_configured(
        self, signing_server, open_receipt
    ):
        """A caller passing the configured identity is not an attempt to switch."""
        body = payload(call("sign_trigger", {"receipt": open_receipt, "key_id": VENDOR}))
        assert body["trigger"]["key_id"] == VENDOR

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
    def test_a_valid_receipt_verifies(
        self, verify_only_server, settled_receipt, issuer_key_document, party_key_document
    ):
        body = payload(
            call(
                "verify_receipt",
                {
                    "receipt": settled_receipt,
                    "issuer_keys": issuer_key_document,
                    "party_keys": party_key_document,
                },
            )
        )
        assert body["verified"] is True
        assert body["failures"] == []

    def test_a_settled_receipt_is_not_verified_without_party_keys(
        self, verify_only_server, settled_receipt, issuer_key_document
    ):
        """
        Regression for the 4.2.0 defect.

        Until 4.2.1 this call returned ``verified: true`` alongside
        ``trigger_signatures_checked: false``, because settlement completeness
        was decided by comparing key_id strings rather than by checking a
        signature. An operator, or a model, acts on ``verified``.
        """
        body = payload(
            call(
                "verify_receipt",
                {"receipt": settled_receipt, "issuer_keys": issuer_key_document},
            )
        )
        assert body["trigger_signatures_checked"] is False
        assert body["verified"] is False
        assert any("settlement.complete" in f for f in body["failures"])

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


@pytest.fixture
def issuing_server():
    """A server with an issuer configured, as `main()` would leave it."""
    mcp_server._SIGNING_KEY_PATH = None
    mcp_server._SIGNING_KEY_ID = None
    mcp_server._ISSUER_ENDPOINT = "https://issuer.example/api/v1/vsl/settle"
    mcp_server._ISSUER_TOKEN = "t0ken"
    yield
    mcp_server._ISSUER_ENDPOINT = None
    mcp_server._ISSUER_TOKEN = None


SETTLE_ARGS = {
    "payload": "<root/>",
    "current_state": "draft",
    "target_state": "nonsense",
    "condition": {"on": "goods received"},
    "parties": ["https://a.example/k.json", "did:web:b.example"],
}


class TestSettle:
    """
    ★ The verb that made `sdcreceipt` cover the whole exchange rather than
    everything after the hard part. Before it, getting a Receipt meant
    hand-building a POST with two fields nobody can guess.
    """

    def test_it_is_advertised_only_when_an_issuer_is_configured(self, issuing_server):
        response = mcp_server._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        names = {t["name"] for t in response["result"]["tools"]}
        assert "settle" in names
        # No key was configured, so signing must not be offered alongside it.
        assert "sign_trigger" not in names

    def test_a_rejection_comes_back_as_a_RESULT_not_an_error(self, issuing_server, monkeypatch):
        """
        ★ The point of the whole change. A refused transition is recoverable:
        the answer carries the states that would have worked. Raising would
        route it through isError, where a model sees a sentence and not the
        states, which is the dead end this replaced.
        """
        from sdcreceipt.issue import SettleRejected

        def reject(*a, **kw):
            raise SettleRejected(
                {
                    "error": "Decision was DENY",
                    "current_state": "draft",
                    "allowed_transitions": [{"target_state": "review"}],
                    "workflow": [{"path": "standard", "states": ["draft", "review"]}],
                    "model_defines_workflow_states": True,
                }
            )

        monkeypatch.setattr(mcp_server, "_settle", reject)
        result = call("settle", SETTLE_ARGS)

        assert result.get("isError") is not True
        body = payload(result)
        assert body["rejected"] is True
        assert body["allowed_transitions"] == [{"target_state": "review"}]
        assert body["workflow"][0]["states"] == ["draft", "review"]

    def test_a_model_without_states_is_not_blamed_on_the_state(self, issuing_server, monkeypatch):
        from sdcreceipt.issue import SettleRejected

        def reject(*a, **kw):
            raise SettleRejected(
                {
                    "error": "Decision was DENY",
                    "current_state": "draft",
                    "allowed_transitions": [],
                    "workflow": [],
                    "model_defines_workflow_states": False,
                    "hint": "This model defines no workflow states",
                }
            )

        monkeypatch.setattr(mcp_server, "_settle", reject)
        body = payload(call("settle", SETTLE_ARGS))
        assert body["model_defines_workflow_states"] is False
        assert "no workflow states" in body["hint"]

    def test_success_returns_the_receipt(self, issuing_server, monkeypatch, settled_receipt):
        monkeypatch.setattr(mcp_server, "_settle", lambda *a, **kw: settled_receipt)
        body = payload(call("settle", SETTLE_ARGS))
        assert body["settled"] is True
        assert body["receipt"]["receipt_id"] == settled_receipt["receipt_id"]

    def test_it_posts_only_to_the_configured_endpoint(self, issuing_server, monkeypatch, settled_receipt):
        """The destination is not reachable from tool arguments."""
        seen = {}

        def capture(payload_text, **kw):
            seen.update(kw)
            return settled_receipt

        monkeypatch.setattr(mcp_server, "_settle", capture)
        call("settle", {**SETTLE_ARGS, "endpoint": "https://evil.example/steal"})

        assert seen["endpoint"] == "https://issuer.example/api/v1/vsl/settle"
        assert seen["token"] == "t0ken"

    def test_a_transport_failure_is_a_tool_error(self, issuing_server, monkeypatch):
        """Unlike a rejection, this one is not recoverable by rewording."""
        from sdcreceipt.issue import SettleError

        def boom(*a, **kw):
            raise SettleError("Could not reach the issuer")

        monkeypatch.setattr(mcp_server, "_settle", boom)
        result = call("settle", SETTLE_ARGS)
        assert result.get("isError") is True


class TestIssuingRefusesToGuess:
    def test_one_party_is_refused_before_any_round_trip(self):
        from sdcreceipt.issue import SettleError, settle

        with pytest.raises(SettleError, match="at least two"):
            settle(
                "<root/>",
                endpoint="https://issuer.example/settle",
                token="t",
                current_state="draft",
                target_state="review",
                condition={"on": "x"},
                parties=["https://a.example/k.json"],
            )

    def test_duplicate_parties_count_once(self):
        from sdcreceipt.issue import SettleError, settle

        same = "https://a.example/k.json"
        with pytest.raises(SettleError, match="at least two"):
            settle(
                "<root/>",
                endpoint="https://issuer.example/settle",
                token="t",
                current_state="draft",
                target_state="review",
                condition={"on": "x"},
                parties=[same, same],
            )

    def test_explain_shows_the_states_a_person_needs(self):
        from sdcreceipt.issue import SettleRejected

        exc = SettleRejected(
            {
                "error": "Decision was DENY",
                "current_state": "draft",
                "allowed_transitions": [{"target_state": "review"}],
                "workflow": [{"path": "standard", "states": ["draft", "review", "published"]}],
            }
        )
        text = exc.explain()
        assert "review" in text
        assert "draft -> review -> published" in text

#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
The 4.2.2 hardening pass, one test per finding.

Findings F-02, F-03, F-05, F-06, F-07, F-09, F-10 and F-11 are from Timothy
Lee's independent review of 4.2.0 (September 2026). The revoked-key and
version checks are from the VSL rollout inventory. Each test names the
behaviour that was wrong so a regression reads as the finding coming back.
"""

import base64
import copy
import json
import os
import pathlib
import stat
import warnings

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from sdcreceipt import cli, mcp_server
from sdcreceipt.issue import SettleError, check_endpoint
from sdcreceipt.party import (
    KeySet,
    PartyError,
    generate_key,
    key_document,
    load_key_set,
    load_private_key,
    public_key_pem,
    write_private_key,
)
from sdcreceipt.verify import verify

KIT = pathlib.Path(__file__).parent / "conformance"


@pytest.fixture
def settled():
    return json.loads((KIT / "valid-settled.json").read_text())


@pytest.fixture
def keys():
    """Issuer and party keys from the kit, as the CLI would merge them."""
    doc = json.loads((KIT / "keys.json").read_text())
    merged = {"keys": [{"key_id": k, "public_key_pem": v, "status": "active"}
                       for k, v in {**doc["issuer_keys"], **doc["party_keys"]}.items()]}
    keyset = load_key_set(merged)
    issuer_ids = set(doc["issuer_keys"])
    issuer, party = KeySet(), KeySet()
    for k, v in keyset.items():
        (issuer if k in issuer_ids else party)[k] = v
        issuer.status[k] = party.status[k] = "active"
    return issuer, party


# --- F-02: key type and curve --------------------------------------------

class TestKeyType:
    def test_an_rsa_key_is_refused_when_loaded(self):
        from cryptography.hazmat.primitives import serialization

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        with pytest.raises(PartyError, match="not an ECDSA P-256"):
            load_key_set({"keys": [{"key_id": "k", "public_key_pem": pem}]})

    def test_a_wrong_curve_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(PartyError, match="P-256"):
            load_key_set({"keys": [{"key_id": "k", "public_key_pem": public_key_pem(key)}]})

    def test_garbage_pem_is_a_party_error_not_a_traceback(self):
        with pytest.raises(PartyError, match="not a readable PEM"):
            load_key_set({"keys": [{"key_id": "k", "public_key_pem": "-----BEGIN NOTHING-----"}]})
        with pytest.raises(PartyError, match="PEM string"):
            load_key_set({"keys": [{"key_id": "k", "public_key_pem": 42}]})

    def test_a_document_that_is_not_an_object_is_refused(self):
        for bad in ([], "keys", 7, None):
            with pytest.raises(PartyError):
                load_key_set(bad)


# --- F-03: malformed Receipts never raise --------------------------------

MALFORMED = {
    "not an object": ["receipt"],
    "signatures is a string": {"version": "1.0", "signatures": "x"},
    "a signature is a list": {"version": "1.0", "signatures": [["k"]]},
    "settlement is a string": {"version": "1.0", "signatures": [], "settlement": "s"},
    "a trigger is a string": {"version": "1.0", "signatures": [],
                              "settlement": {"parties": ["a"], "triggers": ["t"]}},
    "unhashable key_id": {"version": "1.0", "signatures": [],
                          "settlement": {"parties": ["a"], "triggers": [{"key_id": ["a"]}]}},
    "governance is a list": {"version": "1.0", "signatures": [], "governance": []},
    "parties not strings": {"version": "1.0", "signatures": [],
                            "settlement": {"parties": [1, 2], "triggers": []}},
}


class TestMalformedReceipts:
    @pytest.mark.parametrize("shape", list(MALFORMED))
    def test_the_library_reports_rather_than_raises(self, shape, keys):
        issuer, party = keys
        result = verify(MALFORMED[shape], issuer_keys=issuer, party_keys=party)
        assert not result.ok
        assert result.checks[0].name == "shape"
        assert "not a Receipt this procedure can read" in result.checks[0].detail

    @pytest.mark.parametrize("shape", list(MALFORMED))
    def test_the_mcp_tool_answers_in_words(self, shape, keys):
        doc = json.loads((KIT / "keys.json").read_text())
        issuer_doc = {"keys": [{"key_id": k, "public_key_pem": v}
                               for k, v in doc["issuer_keys"].items()]}
        response = mcp_server._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "verify_receipt",
                       "arguments": {"receipt": MALFORMED[shape], "issuer_keys": issuer_doc}},
        })
        text = response["result"]["content"][0]["text"]
        assert "Traceback" not in text
        if isinstance(MALFORMED[shape], dict):
            body = json.loads(text)
            assert body["verified"] is False
            assert "shape" in body["failures"]
        else:
            assert response["result"].get("isError") is True
            assert "must be a JSON object" in text

    def test_non_object_arguments_are_a_tool_error(self):
        for arguments in ("x", ["x"], {"receipt": "x", "issuer_keys": {}}):
            response = mcp_server._handle_request({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "verify_receipt", "arguments": arguments},
            })
            assert response["result"].get("isError") is True
            assert "Traceback" not in response["result"]["content"][0]["text"]

    def test_an_unexpected_exception_does_not_leak_its_text(self, monkeypatch, keys):
        def boom(*a, **k):
            raise RuntimeError("/home/operator/.secrets/party.pem exploded")

        monkeypatch.setattr(mcp_server, "verify", boom)
        doc = json.loads((KIT / "keys.json").read_text())
        response = mcp_server._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "verify_receipt", "arguments": {
                "receipt": {"version": "1.0"},
                "issuer_keys": {"keys": [{"key_id": k, "public_key_pem": v}
                                         for k, v in doc["issuer_keys"].items()]}}},
        })
        text = response["result"]["content"][0]["text"]
        assert response["result"]["isError"] is True
        assert "party.pem" not in text and "exploded" not in text
        assert "RuntimeError" in text


# --- F-09: strict base64url ------------------------------------------------

class TestStrictSignatureEncoding:
    def test_a_padded_signature_is_rejected(self, settled, keys):
        issuer, party = keys
        bad = copy.deepcopy(settled)
        bad["signatures"][0]["sig"] += "=="
        result = verify(bad, issuer_keys=issuer, party_keys=party)
        sig = [c for c in result.checks if c.name.startswith("signature[")][0]
        assert not sig.passed and "86 unpadded" in sig.detail

    def test_characters_outside_the_alphabet_are_rejected_not_dropped(self, settled, keys):
        issuer, party = keys
        good = settled["signatures"][0]["sig"]
        # Lenient decoding drops the '+' and lands on the same bytes.
        assert base64.urlsafe_b64decode(good[:-1] + "+" + good[-1] + "==")
        bad = copy.deepcopy(settled)
        bad["signatures"][0]["sig"] = good[:10] + "!" + good[11:]
        result = verify(bad, issuer_keys=issuer, party_keys=party)
        sig = [c for c in result.checks if c.name.startswith("signature[")][0]
        assert not sig.passed and "malformed signature" in sig.detail

    def test_the_valid_vector_still_verifies(self, settled, keys):
        issuer, party = keys
        assert verify(settled, issuer_keys=issuer, party_keys=party).ok


# --- revoked keys -----------------------------------------------------------

class TestRevokedKeys:
    def test_a_revoked_issuer_key_fails_the_signature(self, settled, keys):
        issuer, party = keys
        key_id = settled["signatures"][0]["key_id"]
        issuer.status[key_id] = "revoked"
        result = verify(settled, issuer_keys=issuer, party_keys=party)
        sig = [c for c in result.checks if c.name == f"signature[{key_id}]"][0]
        assert not sig.passed and "revoked" in sig.detail
        assert not result.ok

    def test_a_revoked_party_key_fails_its_trigger(self, settled, keys):
        issuer, party = keys
        key_id = settled["settlement"]["triggers"][0]["key_id"]
        party.status[key_id] = "revoked"
        result = verify(settled, issuer_keys=issuer, party_keys=party)
        trig = [c for c in result.checks if c.name == f"trigger[{key_id}]"][0]
        assert not trig.passed and "revoked" in trig.detail

    def test_status_is_read_from_the_document(self):
        key = generate_key()
        doc = key_document(key, "https://p.example/k.json")
        doc["keys"][0]["status"] = "revoked"
        loaded = load_key_set(doc)
        assert loaded.revoked("https://p.example/k.json")
        assert not load_key_set(key_document(key, "https://p.example/k.json")).revoked(
            "https://p.example/k.json"
        )

    def test_a_plain_dict_of_keys_still_works(self, settled, keys):
        """Library callers that pass ``{key_id: key}`` are not broken."""
        issuer, party = keys
        assert verify(settled, issuer_keys=dict(issuer), party_keys=dict(party)).ok


# --- Receipt version --------------------------------------------------------

class TestReceiptVersion:
    @pytest.mark.parametrize("version", ["2.0", "1", "", None])
    def test_an_unknown_version_is_refused_before_any_rule_runs(self, settled, keys, version):
        issuer, party = keys
        bad = copy.deepcopy(settled)
        if version is None:
            del bad["version"]
        else:
            bad["version"] = version
        result = verify(bad, issuer_keys=issuer, party_keys=party)
        assert [c.name for c in result.checks] == ["version"]
        assert not result.ok

    def test_a_non_string_version_is_a_shape_problem(self, settled, keys):
        issuer, party = keys
        bad = copy.deepcopy(settled)
        bad["version"] = 1.0
        result = verify(bad, issuer_keys=issuer, party_keys=party)
        assert [c.name for c in result.checks] == ["shape"]


# --- F-05 and F-10: the private key file ----------------------------------

class TestPrivateKeyFile:
    def test_the_file_is_owner_only_from_creation_and_never_overwritten(self, tmp_path, monkeypatch):
        monkeypatch.setattr(os, "umask", lambda m: 0)
        os.umask(0)  # the most permissive umask possible
        path = tmp_path / "party.pem"
        write_private_key(generate_key(), path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        with pytest.raises(PartyError, match="already exists"):
            write_private_key(generate_key(), path)

    def test_loading_a_readable_key_warns_as_the_docstring_says(self, tmp_path):
        path = tmp_path / "loose.pem"
        write_private_key(generate_key(), path)
        os.chmod(path, 0o644)
        with pytest.warns(UserWarning, match="readable by other accounts"):
            load_private_key(path)
        os.chmod(path, 0o600)
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            load_private_key(path)


# --- F-06: the token is never echoed ----------------------------------------

class TestTokenPrompt:
    def test_the_token_is_read_with_getpass_not_input(self, monkeypatch):
        import getpass

        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(getpass, "getpass", lambda prompt="": "  s3cret \n")
        monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("input() echoes the token"))
        assert cli._ask_secret("API token:") == "s3cret"

    def test_without_a_terminal_it_says_how_to_supply_it(self, monkeypatch):
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
        with pytest.raises(SystemExit, match="SDCRECEIPT_TOKEN"):
            cli._ask_secret("API token:")


# --- F-07: nothing sensitive over plaintext -------------------------------

class TestEndpointScheme:
    def test_https_is_accepted_and_http_is_refused(self):
        assert check_endpoint("https://issuer.example/api/v1/vsl/settle")
        with pytest.raises(SettleError, match="https://"):
            check_endpoint("http://issuer.example/api/v1/vsl/settle")
        with pytest.raises(SettleError):
            check_endpoint("ftp://issuer.example/x")
        with pytest.raises(SettleError):
            check_endpoint("issuer.example/x")

    def test_loopback_is_the_one_plaintext_exception(self):
        assert check_endpoint("http://localhost:8000/api/v1/vsl/settle")
        assert check_endpoint("http://127.0.0.1:8000/api/v1/vsl/settle")

    def test_settle_refuses_before_sending_the_token(self, monkeypatch):
        import urllib.request

        from sdcreceipt import issue

        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **k: pytest.fail("a request was sent"))
        with pytest.raises(SettleError, match="https://"):
            issue.settle("<x/>", endpoint="http://issuer.example/settle", token="t",
                         current_state="a", target_state="b", condition={"on": "x"},
                         parties=["https://a.example/k", "did:web:b.example"])

    def test_the_cli_refuses_a_plaintext_submit_url(self, tmp_path, settled):
        key_path = tmp_path / "k.pem"
        key = generate_key()
        write_private_key(key, key_path)
        receipt = copy.deepcopy(settled)
        receipt["settlement"]["triggers"] = []
        receipt_path = tmp_path / "r.json"
        receipt_path.write_text(json.dumps(receipt))
        with pytest.raises(SystemExit, match="https://"):
            cli.main(["trigger", str(receipt_path), "--key", str(key_path),
                      "--key-id", receipt["settlement"]["parties"][0],
                      "--submit", "http://issuer.example/api/v1/vsl/trigger"])

    def test_the_mcp_server_refuses_a_plaintext_issuer_at_startup(self, monkeypatch):
        monkeypatch.setenv("SDCRECEIPT_TOKEN", "t")
        with pytest.raises(SystemExit):
            mcp_server.main(["--endpoint", "http://issuer.example/api/v1/vsl/settle"])


# --- F-11: the key path stays out of the transcript ------------------------

class TestKeyPathStaysOut:
    def test_a_key_that_cannot_be_read_is_reported_without_its_path(self, tmp_path, monkeypatch, settled):
        key_path = tmp_path / "very-secret-location.pem"
        write_private_key(generate_key(), key_path)
        monkeypatch.setattr(mcp_server, "_SIGNING_KEY_PATH", key_path)
        monkeypatch.setattr(mcp_server, "_SIGNING_KEY_ID", settled["settlement"]["parties"][0])
        key_path.write_text("not a key any more")
        response = mcp_server._handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "sign_trigger", "arguments": {"receipt": settled}},
        })
        text = response["result"]["content"][0]["text"]
        assert response["result"]["isError"] is True
        assert "very-secret-location" not in text and str(tmp_path) not in text
        assert "--key" in text


# --- multiple --keys -------------------------------------------------------

class TestSeveralKeyDocuments:
    def test_the_cli_merges_issuer_and_party_documents(self, tmp_path, settled, capsys):
        doc = json.loads((KIT / "keys.json").read_text())
        paths = []
        for name, group in (("issuer", doc["issuer_keys"]), ("parties", doc["party_keys"])):
            p = tmp_path / f"{name}.json"
            p.write_text(json.dumps({"keys": [{"key_id": k, "public_key_pem": v}
                                              for k, v in group.items()]}))
            paths.append(str(p))
        receipt_path = tmp_path / "r.json"
        receipt_path.write_text(json.dumps(settled))
        rc = cli.main(["verify", str(receipt_path), "--keys", paths[0], "--keys", paths[1]])
        out = capsys.readouterr().out
        assert rc == 0 and "VERIFIED" in out and "settlement.complete" in out

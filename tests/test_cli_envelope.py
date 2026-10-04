#
# Copyright (c) 2026, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
`verify` and `trigger` on the file a reader actually has: the issuer's
`/receipt/{id}` answer, which wraps the Receipt in a status envelope. Found on
2026-10-03 while writing the announcement's instructions; until 4.2.4 the CLI
refused it with `Receipt version None`.
"""

import json
import pathlib
import types

import pytest

from sdcreceipt import cli

KIT = pathlib.Path(__file__).parent / "conformance"


@pytest.fixture
def receipt():
    return json.loads((KIT / "valid-settled.json").read_text())


def status_envelope(receipt):
    parties = receipt["settlement"]["parties"]
    return {"receipt": receipt, "receipt_id": receipt["receipt_id"], "status": "settled", "decision": "PERMIT",
            "settleable": True, "parties": parties, "triggered": parties, "awaiting": []}


def key_document(tmp_path):
    """The kit's keys as one published key document (issuer and parties together, as a verifier holds them)."""
    doc = json.loads((KIT / "keys.json").read_text())
    merged = {"keys": [{"key_id": k, "public_key_pem": v} if isinstance(v, str) else {"key_id": k, **v}
                       for k, v in {**doc["issuer_keys"], **doc["party_keys"]}.items()]}
    path = tmp_path / "keys.json"
    path.write_text(json.dumps(merged))
    return str(path)


def run_verify(tmp_path, doc, capsys):
    path = tmp_path / "download.json"
    path.write_text(json.dumps(doc))
    args = types.SimpleNamespace(receipt=str(path), keys=[key_document(tmp_path)], schema=None, governance=None, payload=None, json=False)
    code = cli.cmd_verify(args)
    out, err = capsys.readouterr()
    return code, out, err


def test_verify_reads_the_receipt_out_of_the_status_envelope(tmp_path, receipt, capsys):
    code, out, err = run_verify(tmp_path, status_envelope(receipt), capsys)
    assert code == 0, out
    assert "VERIFIED" in out and "Receipt version None" not in out
    assert "read the Receipt out of the issuer's response" in err


def test_verify_still_takes_a_bare_receipt(tmp_path, receipt, capsys):
    code, out, err = run_verify(tmp_path, receipt, capsys)
    assert code == 0, out
    assert "read the Receipt out of" not in err


def test_load_receipt_unwraps_the_settle_envelope(tmp_path, receipt, capsys):
    path = tmp_path / "settle-response.json"
    path.write_text(json.dumps({"receipt": receipt, "governance": {"decision": "PERMIT"}, "verification": {}, "wallet": {"charged": "1.00"}}))
    assert cli._load_receipt(path) == receipt
    assert "governance, verification, wallet" in capsys.readouterr().err

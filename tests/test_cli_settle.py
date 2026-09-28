#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
`settle` from the command line, against the issuer's real response shape.

Two defects found on the first outside settlement (28 September 2026), both in
the CLI and neither reachable by the earlier tests, which mocked the issuer as
if it answered with a bare Receipt:

1. `--out` wrote the issuer's whole envelope, so `verify` and `trigger` refused
   the file and the receipt id printed blank.
2. An omitted `--current-state` was a blind prompt, although the payload carries
   `<current-state>` and the issuer treats it as authoritative.
"""

import json
import pathlib
import sys
import types

import pytest

from sdcreceipt import cli
from sdcreceipt.issue import payload_current_state, split_response

KIT = pathlib.Path(__file__).parent / "conformance"

PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<sdc4:dm-abc xmlns:sdc4="https://semanticdatacharter.com/ns/sdc4/">
  <dm-label>Example</dm-label>
  <current-state>arrived</current-state>
</sdc4:dm-abc>
"""


@pytest.fixture
def receipt():
    return json.loads((KIT / "valid-settled.json").read_text())


def envelope(receipt, decision="PERMIT"):
    return {
        "receipt": receipt,
        "governance": {
            "decision": decision,
            "settleable": decision == "PERMIT",
            "current_state": "arrived",
            "allowed_transitions": [],
            "workflow": [{"path": "p", "states": ["arrived", "triaged"]}],
        },
        "verification": {"tool": "pip install sdcreceipt"},
        "wallet": {"charged": "1.00", "balance": "9.00"},
    }


def run_settle(monkeypatch, tmp_path, response, *extra, capture=None):
    payload = tmp_path / "payload.xml"
    payload.write_text(PAYLOAD)
    seen = {}

    def fake_settle(text, **kw):
        seen.update(kw)
        return response

    monkeypatch.setattr(cli, "settle", fake_settle)
    monkeypatch.setenv("SDCRECEIPT_TOKEN", "t")
    # A prompt in a test is a failure: stdin is not a terminal, so `_ask` exits.
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    argv = [
        "settle", str(payload),
        "--endpoint", "https://issuer.example/api/v1/vsl/settle",
        "--target-state", "triaged",
        "--condition", '{"on": "x"}',
        "--party", "https://a.example/k.json",
        "--party", "https://b.example/k.json",
        *extra,
    ]
    args = cli.build_parser().parse_args(argv)
    code = args.func(args)
    return code, seen


class TestSplitResponse:
    def test_envelope(self, receipt):
        inner, meta = split_response(envelope(receipt))
        assert inner == receipt
        assert meta["governance"]["decision"] == "PERMIT"
        assert "receipt" not in meta

    def test_bare_receipt_passes_through(self, receipt):
        inner, meta = split_response(receipt)
        assert inner == receipt
        assert meta == {}


class TestPayloadCurrentState:
    def test_plain_element(self):
        assert payload_current_state(PAYLOAD) == "arrived"

    def test_prefixed_element_and_whitespace(self):
        text = "<x:current-state>\n  Documented \n</x:current-state>"
        assert payload_current_state(text) == "Documented"

    def test_absent(self):
        assert payload_current_state("<dm/>") == ""


class TestOut:
    def test_out_is_the_receipt_not_the_envelope(self, monkeypatch, tmp_path, receipt, capsys):
        out = tmp_path / "receipt.json"
        code, _ = run_settle(monkeypatch, tmp_path, envelope(receipt), "--out", str(out))
        assert code == 0
        written = json.loads(out.read_text())
        assert written == receipt
        assert written["version"] == "1.0"
        err = capsys.readouterr().err
        assert f"receipt {receipt['receipt_id']} ->" in err
        assert "governance: PERMIT" in err

    def test_response_keeps_the_envelope(self, monkeypatch, tmp_path, receipt):
        out, resp = tmp_path / "receipt.json", tmp_path / "response.json"
        run_settle(monkeypatch, tmp_path, envelope(receipt), "--out", str(out), "--response", str(resp))
        assert json.loads(resp.read_text())["wallet"]["charged"] == "1.00"
        assert json.loads(out.read_text()) == receipt

    def test_stdout_is_the_receipt(self, monkeypatch, tmp_path, receipt, capsys):
        run_settle(monkeypatch, tmp_path, envelope(receipt))
        assert json.loads(capsys.readouterr().out) == receipt

    def test_a_deny_is_said_plainly(self, monkeypatch, tmp_path, receipt, capsys):
        out = tmp_path / "receipt.json"
        code, _ = run_settle(monkeypatch, tmp_path, envelope(receipt, "DENY"), "--out", str(out))
        err = capsys.readouterr().err
        assert code == 0
        assert "governance: DENY" in err
        assert "accepts no triggers" in err
        assert "arrived -> triaged" in err


class TestCurrentState:
    def test_defaults_to_the_payload(self, monkeypatch, tmp_path, receipt, capsys):
        _, seen = run_settle(monkeypatch, tmp_path, envelope(receipt))
        assert seen["current_state"] == "arrived"
        assert "from the payload" in capsys.readouterr().err

    def test_the_flag_wins_with_a_warning_on_mismatch(self, monkeypatch, tmp_path, receipt, capsys):
        _, seen = run_settle(monkeypatch, tmp_path, envelope(receipt), "--current-state", "planned")
        assert seen["current_state"] == "planned"
        assert "differs from the payload" in capsys.readouterr().err

    def test_a_matching_flag_is_quiet(self, monkeypatch, tmp_path, receipt, capsys):
        _, seen = run_settle(monkeypatch, tmp_path, envelope(receipt), "--current-state", "arrived")
        assert seen["current_state"] == "arrived"
        assert "differs" not in capsys.readouterr().err

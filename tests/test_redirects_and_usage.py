#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
4.3.4: findings from Timothy Lee's release assurance review of 4.3.3
(October 2026).

F-14: `settle` and `trigger --submit` followed HTTP redirects to hosts nobody
checked, and urllib carries the Authorization header along. A redirect is now
refused and named. F-17: `verify` without the issuer's key document is a usage
error, not a NOT VERIFIED that reads like a verdict about the Receipt.
"""

import http.server
import json
import pathlib
import threading

import pytest

from sdcreceipt import cli
from sdcreceipt.issue import SettleError, settle
from sdcreceipt.party import generate_key, write_private_key

KIT = pathlib.Path(__file__).parent / "conformance"


class _Server:
    """A loopback HTTP server that redirects every POST, and one that records what reaches it."""

    def __init__(self, status: int = 302, target: str = ""):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                seen.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                             "body": self.rfile.read(length)})
                if target:
                    self.send_response(status)
                    self.send_header("Location", target)
                    self.end_headers()
                else:
                    body = b'{"ok": true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            do_GET = do_POST

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    made = []

    def make(**kw):
        s = _Server(**kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


SETTLE_ARGS = dict(token="secret-token", current_state="Published", target_state="Settled",
                   condition={"on": "goods received"}, parties=["did:web:a.example", "did:web:b.example"])


class TestF14Redirects:
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_settle_refuses_a_redirect_and_the_token_goes_nowhere_else(self, servers, status):
        elsewhere = servers()
        issuer = servers(status=status, target=elsewhere.url + "steal")
        with pytest.raises(SettleError, match="refusing to follow it"):
            settle("<payload/>", endpoint=issuer.url + "settle", **SETTLE_ARGS)
        assert issuer.seen and issuer.seen[0]["authorization"] == "Token secret-token"
        assert elsewhere.seen == []  # the redirect target never heard from us

    def test_settle_without_a_redirect_still_works(self, servers):
        issuer = servers()
        assert settle("<payload/>", endpoint=issuer.url + "settle", **SETTLE_ARGS) == {"ok": True}

    def test_trigger_submit_refuses_a_redirect(self, servers, tmp_path, capsys):
        elsewhere = servers()
        endpoint = servers(status=302, target=elsewhere.url)
        receipt = json.loads((KIT / "valid-settled.json").read_text())
        receipt["settlement"]["triggers"] = []  # awaiting both parties, so this one may sign
        key_id = receipt["settlement"]["parties"][0]
        key_path = tmp_path / "party.pem"
        write_private_key(generate_key(), key_path)
        (tmp_path / "r.json").write_text(json.dumps(receipt))
        rc = cli.main(["trigger", str(tmp_path / "r.json"), "--key", str(key_path), "--key-id", key_id,
                       "--submit", endpoint.url])
        assert rc == 1 and "refusing to follow it" in capsys.readouterr().err
        assert elsewhere.seen == []


class TestF17IssuerKeysRequired:
    def test_verify_without_issuer_keys_is_a_usage_error(self, tmp_path, capsys):
        (tmp_path / "r.json").write_text((KIT / "valid-settled.json").read_text())
        rc = cli.main(["verify", str(tmp_path / "r.json")])
        captured = capsys.readouterr()
        assert rc == 2 and "--issuer-keys FILE is required" in captured.err
        assert "VERIFIED" not in captured.out

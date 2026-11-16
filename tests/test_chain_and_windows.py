#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
4.4.0: `verify` follows `previous_hash` (--chain, #26) and compares key
validity windows with the Receipt's `timestamp` (#27).

Two limits `verify` used to print under "Not covered by this result", from
Timothy Lee's 4.3.x review (F-03, F-11 to F-13). Check names follow the VSL
conformance kit 1.2 ("Chains", "Key windows"); the kit's own vectors arrive
with #30. These build their own Receipts so each rule is tested on its own.
"""

import base64
import copy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from sdcreceipt import cli
from sdcreceipt.party import KeySet, PartyError, load_key_set, public_key_pem, sign_trigger
from sdcreceipt.verify import canonical_content, chain_link_label, receipt_digest, verify, verify_chain

ISSUER_ID = "issuer-key-v1"
VENDOR = "https://vendor.example/.well-known/vsl-key.json"
PARTNER = "did:web:partner.example"


@pytest.fixture(scope="module")
def keys():
    return {name: ec.generate_private_key(ec.SECP256R1()) for name in ("issuer", VENDOR, PARTNER)}


def _key_doc(entries):
    return {"keys": [dict(e) for e in entries]}


def _entry(key, key_id, **extra):
    return {"key_id": key_id, "alg": "ES256", "public_key_pem": public_key_pem(key), "status": "active", **extra}


def _issuer_keys(keys, **window):
    return load_key_set(_key_doc([_entry(keys["issuer"], ISSUER_ID, **window)]))


def _party_keys(keys, vendor_window=None):
    party = KeySet()
    party.add_document(load_key_set(_key_doc([_entry(keys[VENDOR], VENDOR, **(vendor_window or {}))])), "vendor")
    party.add_document(load_key_set(_key_doc([_entry(keys[PARTNER], PARTNER)])), "partner")
    return party


def _receipt(keys, receipt_id, timestamp, previous_hash=None, *, triggered=(VENDOR, PARTNER)):
    """A 1.0 Receipt with real hashes and signatures; schema is not passed, so only the procedure is tested."""
    r = {
        "version": "1.0",
        "canonicalization": "rfc8785",
        "receipt_id": receipt_id,
        "timestamp": timestamp,
        "payload_hash": hashlib.sha256(receipt_id.encode()).hexdigest(),
        "governance": {"decision": "PERMIT", "receipt_hash": "1" * 64},
        "settlement": {"condition_hash": "2" * 64, "parties": [VENDOR, PARTNER], "triggers": []},
        "previous_hash": previous_hash,
    }
    r["receipt_hash"] = hashlib.sha256(canonical_content(r)).hexdigest()
    der = keys["issuer"].sign(receipt_digest(r), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    rs = utils.decode_dss_signature(der)
    sig = base64.urlsafe_b64encode(rs[0].to_bytes(32, "big") + rs[1].to_bytes(32, "big")).rstrip(b"=").decode()
    r["signatures"] = [{"alg": "ES256", "key_id": ISSUER_ID, "sig": sig}]
    for key_id in triggered:
        r["settlement"]["triggers"].append(sign_trigger(keys[key_id], r, key_id))
    return r


@pytest.fixture(scope="module")
def chain(keys):
    head = _receipt(keys, "aaaaaaaaaaaaaaaaaaaaaaaa", "2026-10-01T00:00:00Z")
    middle = _receipt(keys, "bbbbbbbbbbbbbbbbbbbbbbbb", "2026-10-02T00:00:00Z", head["receipt_hash"])
    tip = _receipt(keys, "cccccccccccccccccccccccc", "2026-10-03T00:00:00Z", middle["receipt_hash"])
    return head, middle, tip


def _failed(result):
    return {c.name for c in result.failures}


def _evidence(keys):
    return {"issuer_keys": _issuer_keys(keys), "party_keys": _party_keys(keys)}


# --- key windows (#27) --------------------------------------------------------


class TestIssuerWindow:
    SIG = f"signature[{ISSUER_ID}]"

    def test_inside_the_window_verifies(self, keys, chain):
        ik = _issuer_keys(keys, not_before="2026-09-01T00:00:00Z", not_after=None)
        assert verify(chain[0], issuer_keys=ik, party_keys=_party_keys(keys)).ok

    def test_a_retired_key_inside_its_window_verifies(self, keys, chain):
        ik = _issuer_keys(keys, status="retired", not_before="2026-09-01T00:00:00Z",
                          not_after="2026-11-01T00:00:00Z")
        assert verify(chain[0], issuer_keys=ik, party_keys=_party_keys(keys)).ok

    def test_before_not_before_fails_on_the_signature(self, keys, chain):
        ik = _issuer_keys(keys, not_before="2026-10-01T00:00:01Z")
        result = verify(chain[0], issuer_keys=ik, party_keys=_party_keys(keys))
        assert _failed(result) == {self.SIG}
        assert "before the key's not_before" in result.failures[0].detail

    def test_the_window_is_half_open(self, keys, chain):
        at_end = _issuer_keys(keys, status="retired", not_after="2026-10-01T00:00:00Z")
        assert _failed(verify(chain[0], issuer_keys=at_end, party_keys=_party_keys(keys))) == {self.SIG}
        just_after = _issuer_keys(keys, status="retired", not_after="2026-10-01T00:00:01Z")
        assert verify(chain[0], issuer_keys=just_after, party_keys=_party_keys(keys)).ok

    def test_a_revoked_key_fails_whatever_its_window_says(self, keys, chain):
        ik = _issuer_keys(keys, status="revoked", not_before="2026-01-01T00:00:00Z",
                          not_after="2027-01-01T00:00:00Z")
        result = verify(chain[0], issuer_keys=ik, party_keys=_party_keys(keys))
        assert _failed(result) == {self.SIG}
        assert "revoked" in result.failures[0].detail

    def test_a_plain_dict_of_keys_has_no_window_to_check(self, keys, chain):
        assert verify(chain[0], issuer_keys={ISSUER_ID: keys["issuer"].public_key()},
                      party_keys=_party_keys(keys)).ok


class TestPartyWindow:
    TRIG = f"trigger[{VENDOR}]"

    def test_a_key_retired_before_the_receipt_fails_its_trigger(self, keys, chain):
        pk = _party_keys(keys, {"status": "retired", "not_after": "2026-09-30T00:00:00Z"})
        result = verify(chain[0], issuer_keys=_issuer_keys(keys), party_keys=pk)
        assert self.TRIG in _failed(result)
        assert "receipt_id" in next(c for c in result.failures if c.name == self.TRIG).detail

    def test_not_after_equal_to_the_timestamp_fails(self, keys, chain):
        pk = _party_keys(keys, {"not_after": "2026-10-01T00:00:00Z"})
        assert self.TRIG in _failed(verify(chain[0], issuer_keys=_issuer_keys(keys), party_keys=pk))

    def test_not_before_is_not_judged(self, keys, chain):
        # Trigger timestamps are not signed: nothing says how late the trigger came.
        pk = _party_keys(keys, {"not_before": "2026-12-01T00:00:00Z"})
        assert verify(chain[0], issuer_keys=_issuer_keys(keys), party_keys=pk).ok


class TestWindowsInTheKeyDocument:
    def test_a_bound_not_in_z_form_refuses_the_document(self, keys):
        with pytest.raises(PartyError, match="not_after"):
            _issuer_keys(keys, not_after="2026-10-01T00:00:00+00:00")
        with pytest.raises(PartyError, match="not_before"):
            _issuer_keys(keys, not_before="yesterday")

    def test_a_revoked_keys_window_is_not_read(self, keys):
        ks = _issuer_keys(keys, status="revoked", not_after="whenever")
        assert ks.revoked(ISSUER_ID) and ks.window(ISSUER_ID) is None

    def test_add_document_carries_windows(self, keys):
        ks = KeySet()
        ks.add_document(_issuer_keys(keys, not_before="2026-01-01T00:00:00Z"), "issuer")
        assert ks.window(ISSUER_ID) == {"not_before": "2026-01-01T00:00:00Z", "not_after": None}


# --- chain (#26) ----------------------------------------------------------------


class TestChain:
    def test_a_chain_of_three_verifies_to_the_head(self, keys, chain):
        head, middle, tip = chain
        result = verify_chain(tip, held=[head, middle], **_evidence(keys))
        assert result.ok, str(result)
        names = [c.name for c in result.checks]
        p1, p2 = chain_link_label(1, middle["receipt_hash"]), chain_link_label(2, head["receipt_hash"])
        assert f"{p1} previous_hash" in names and f"{p1} timestamp" in names
        assert f"{p2} signature[{ISSUER_ID}]" in names
        assert names[-1] == "chain.head"

    def test_the_prefix_is_the_kits(self):
        assert chain_link_label(1, "3fa9c1d2" + "0" * 56) == "chain.link[1 3fa9c1d2…]"

    def test_a_head_is_its_own_chain(self, keys, chain):
        result = verify_chain(chain[0], held=[], **_evidence(keys))
        assert result.ok and result.checks[-1].detail == "this Receipt is the head"

    def test_an_empty_chain_is_still_a_chain(self, keys, chain):
        tip = chain[2]
        result = verify_chain(tip, held=[], **_evidence(keys))
        assert _failed(result) == {chain_link_label(1, tip["previous_hash"])}

    def test_a_link_naming_a_receipt_not_held_fails_on_previous_hash(self, keys, chain):
        head, middle, tip = chain
        other = _receipt(keys, "dddddddddddddddddddddddd", "2026-10-02T00:00:00Z", head["receipt_hash"])
        result = verify_chain(tip, held=[head, other], **_evidence(keys))
        assert _failed(result) == {f"{chain_link_label(1, tip['previous_hash'])} previous_hash"}

    def test_an_edited_earlier_link_is_examined_and_fails(self, keys, chain):
        head, middle, tip = chain
        edited = copy.deepcopy(middle)
        edited["payload_hash"] = "0" * 64  # recorded receipt_hash still names its place
        result = verify_chain(tip, held=[head, edited], **_evidence(keys))
        prefix = chain_link_label(1, tip["previous_hash"])
        assert {f"{prefix} previous_hash", f"{prefix} receipt_hash"} <= _failed(result)

    def test_an_earlier_link_with_a_later_timestamp_fails(self, keys):
        head = _receipt(keys, "eeeeeeeeeeeeeeeeeeeeeeee", "2026-10-05T00:00:00Z")
        tip = _receipt(keys, "ffffffffffffffffffffffff", "2026-10-04T00:00:00Z", head["receipt_hash"])
        result = verify_chain(tip, held=[head], **_evidence(keys))
        assert _failed(result) == {f"{chain_link_label(1, head['receipt_hash'])} timestamp"}

    def test_two_documents_with_one_hash_is_a_refusal(self, keys, chain):
        head, middle, tip = chain
        fewer = copy.deepcopy(middle)
        fewer["settlement"]["triggers"] = fewer["settlement"]["triggers"][:1]
        result = verify_chain(tip, held=[head, middle, fewer], **_evidence(keys))
        assert _failed(result) == {chain_link_label(1, tip["previous_hash"])}

    def test_byte_identical_copies_are_one_document(self, keys, chain):
        head, middle, tip = chain
        assert verify_chain(tip, held=[head, middle, copy.deepcopy(middle)], **_evidence(keys)).ok

    def test_an_earlier_link_never_fully_triggered_fails_the_chain(self, keys, chain):
        head = chain[0]
        middle = _receipt(keys, "gggggggggggggggggggggggg", "2026-10-02T00:00:00Z", head["receipt_hash"],
                          triggered=(VENDOR,))
        tip = _receipt(keys, "hhhhhhhhhhhhhhhhhhhhhhhh", "2026-10-03T00:00:00Z", middle["receipt_hash"])
        result = verify_chain(tip, held=[head, middle], **_evidence(keys))
        assert _failed(result) == {f"{chain_link_label(1, middle['receipt_hash'])} settlement.complete"}

    def test_the_ceiling_stops_the_walk(self, keys, chain):
        head, middle, tip = chain
        result = verify_chain(tip, held=[head, middle], ceiling=1, **_evidence(keys))
        assert _failed(result) == {chain_link_label(2, head["receipt_hash"])}

    def test_windows_apply_to_every_link(self, keys, chain):
        head, middle, tip = chain
        ik = _issuer_keys(keys, not_before="2026-10-01T12:00:00Z")  # after the head was signed
        result = verify_chain(tip, held=[head, middle], issuer_keys=ik, party_keys=_party_keys(keys))
        assert _failed(result) == {f"{chain_link_label(2, head['receipt_hash'])} signature[{ISSUER_ID}]"}


# --- the command line -------------------------------------------------------------


@pytest.fixture
def files(keys, chain, tmp_path):
    head, middle, tip = chain
    (tmp_path / "issuer.json").write_text(json.dumps(_key_doc([_entry(keys["issuer"], ISSUER_ID)])))
    (tmp_path / "vendor.json").write_text(json.dumps(_key_doc([_entry(keys[VENDOR], VENDOR)])))
    (tmp_path / "partner.json").write_text(json.dumps(_key_doc([_entry(keys[PARTNER], PARTNER)])))
    held = tmp_path / "held"
    held.mkdir()
    (held / "head.json").write_text(json.dumps(head))
    (held / "middle.json").write_text(json.dumps(middle))
    (tmp_path / "tip.json").write_text(json.dumps(tip))
    base = ["verify", str(tmp_path / "tip.json"), "--issuer-keys", str(tmp_path / "issuer.json"),
            "--party-keys", str(tmp_path / "vendor.json"), "--party-keys", str(tmp_path / "partner.json")]
    return tmp_path, held, base


def _run(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


class TestCommandLine:
    def test_chain_verifies_and_says_what_it_did_not_cover(self, files, capsys):
        tmp, held, base = files
        rc, out, _ = _run(base + ["--chain", str(held)], capsys)
        assert rc == 0, out
        assert "PASS  chain.head" in out and "VERIFIED" in out
        assert "previous_hash is not followed" not in out
        assert "governance and payload evidence apply to this Receipt only" in out

    def test_without_chain_the_limit_is_still_printed(self, files, capsys):
        tmp, held, base = files
        rc, out, _ = _run(base, capsys)
        assert rc == 0
        assert "previous_hash is not followed" in out

    def test_a_missing_link_exits_1(self, files, capsys):
        tmp, held, base = files
        (held / "head.json").unlink()
        rc, out, _ = _run(base + ["--chain", str(held)], capsys)
        assert rc == 1 and "NOT VERIFIED" in out

    def test_one_file_is_a_chain_of_one(self, files, capsys):
        tmp, held, base = files
        rc, out, _ = _run(base + ["--chain", str(held / "middle.json")], capsys)
        assert rc == 1  # the head is not held
        assert f"FAIL  chain.link[2 " in out

    def test_the_receipt_may_sit_in_its_own_chain_folder(self, files, capsys):
        tmp, held, base = files
        (held / "tip.json").write_text((tmp / "tip.json").read_text())
        base[1] = str(held / "tip.json")
        rc, out, _ = _run(base + ["--chain", str(held)], capsys)
        assert rc == 0, out

    def test_a_chain_path_that_is_not_there_is_a_usage_error(self, files, capsys):
        tmp, held, base = files
        rc, _, err = _run(base + ["--chain", str(tmp / "nowhere")], capsys)
        assert rc == 2 and "neither a directory nor a file" in err

    def test_an_unreadable_file_in_the_chain_folder_stops_the_run(self, files, capsys):
        tmp, held, base = files
        (held / "broken.json").write_text("{not json")
        with pytest.raises(SystemExit, match="not valid JSON"):
            cli.main(base + ["--chain", str(held)])


# --- #29: `init` writes the window a party's triggers are judged by --------------------


class TestInitWritesAWindow:
    def test_the_document_states_not_before_and_an_open_not_after(self, keys):
        from datetime import datetime, timedelta, timezone

        from sdcreceipt.party import key_document
        from sdcreceipt.verify import parse_instant

        entry = key_document(keys[VENDOR], VENDOR)["keys"][0]
        assert entry["not_after"] is None
        made = parse_instant(entry["not_before"])
        assert abs(datetime.now(timezone.utc) - made) < timedelta(minutes=1)
        assert load_key_set(key_document(keys[VENDOR], VENDOR)).window(VENDOR)["not_after"] is None

    def test_a_given_not_before_must_be_the_z_form(self, keys):
        from sdcreceipt.party import key_document

        assert key_document(keys[VENDOR], VENDOR, not_before="2026-01-01T00:00:00Z")["keys"][0][
            "not_before"] == "2026-01-01T00:00:00Z"
        with pytest.raises(ValueError):
            key_document(keys[VENDOR], VENDOR, not_before="2026-01-01")

    def test_the_cli_writes_it(self, tmp_path, capsys):
        rc = cli.main(["init", "--key-id", VENDOR, "--out", str(tmp_path / "vendor.pem")])
        assert rc == 0
        document = json.loads((tmp_path / "vendor-key-document.json").read_text())
        assert document["keys"][0]["not_before"].endswith("Z")
        assert document["keys"][0]["not_after"] is None

    def test_retiring_the_key_keeps_earlier_triggers_and_refuses_later_ones(self, keys, chain):
        """What a party does on rotation: set not_after; Receipts before it still verify."""
        from sdcreceipt.party import key_document

        document = key_document(keys[VENDOR], VENDOR, not_before="2026-09-01T00:00:00Z")
        document["keys"][0].update(status="retired", not_after="2026-10-02T00:00:00Z")
        party = KeySet()
        party.add_document(load_key_set(document), "vendor")
        party.add_document(load_key_set(_key_doc([_entry(keys[PARTNER], PARTNER)])), "partner")
        head, middle, tip = chain  # 10-01, 10-02, 10-03
        assert verify(head, issuer_keys=_issuer_keys(keys), party_keys=party).ok
        for later in (middle, tip):
            assert f"trigger[{VENDOR}]" in _failed(verify(later, issuer_keys=_issuer_keys(keys), party_keys=party))

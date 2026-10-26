#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
4.3.3: the fixes from Timothy Lee's release assurance review of 4.3.x
(October 2026), one test per finding (GHSA-gwhr-82j5-883w for F-01 and F-02).

F-01: the CLI pooled every --keys document and let the Receipt's own
`signatures` decide which keys were the issuer's, so a party that added a key
to its own published document could sign as the issuer and reach VERIFIED.
"""

import base64
import copy
import json
import pathlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from sdcreceipt import cli
from sdcreceipt.party import KeySet, PartyError, load_key_set, public_key_pem
from sdcreceipt.verify import canonical_content, receipt_digest, verify

KIT = pathlib.Path(__file__).parent / "conformance"


def _doc(group: dict) -> dict:
    return {"keys": [{"key_id": k, "public_key_pem": v, "status": "active"} for k, v in group.items()]}


@pytest.fixture
def kit(tmp_path):
    """The 1.0 settled vector, with the issuer's and the parties' documents as separate files."""
    keys = json.loads((KIT / "keys.json").read_text())
    issuer_doc, party_doc = _doc(keys["issuer_keys"]), _doc(keys["party_keys"])
    paths = {}
    for name, doc in (("issuer", issuer_doc), ("party", party_doc)):
        paths[name] = tmp_path / f"{name}.json"
        paths[name].write_text(json.dumps(doc))
    receipt = json.loads((KIT / "valid-settled.json").read_text())
    return receipt, issuer_doc, party_doc, paths, tmp_path


def _sign_as(receipt: dict, key, key_id: str) -> dict:
    """Re-hash the Receipt and sign it ES256 with `key`, as a forger would."""
    import hashlib

    forged = copy.deepcopy(receipt)
    forged["receipt_hash"] = hashlib.sha256(canonical_content(forged)).hexdigest()
    der = key.sign(receipt_digest(forged), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    sig = base64.urlsafe_b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).rstrip(b"=").decode()
    forged["signatures"] = [{"alg": "ES256", "key_id": key_id, "sig": sig}]
    return forged


def _run(args, capsys):
    rc = cli.main(args)
    out = capsys.readouterr()
    return rc, out.out, out.err


class TestF01RolesComeFromTheVerifier:
    def test_a_party_document_cannot_supply_an_issuer_key(self, kit, capsys):
        receipt, issuer_doc, party_doc, paths, tmp = kit
        attacker = ec.generate_private_key(ec.SECP256R1())
        forged = copy.deepcopy(receipt)
        forged["payload_hash"] = "0" * 64  # the altered claim; triggers still sign receipt_id + condition_hash
        forged = _sign_as(forged, attacker, "attacker-issuer-key")
        party_doc = copy.deepcopy(party_doc)
        party_doc["keys"].append({"key_id": "attacker-issuer-key", "public_key_pem": public_key_pem(attacker),
                                  "status": "active"})
        (tmp / "party-with-extra-key.json").write_text(json.dumps(party_doc))
        (tmp / "forged.json").write_text(json.dumps(forged))

        rc, out, _ = _run(["verify", str(tmp / "forged.json"), "--issuer-keys", str(paths["issuer"]),
                           "--party-keys", str(tmp / "party-with-extra-key.json")], capsys)
        assert rc == 1 and "NOT VERIFIED" in out
        assert "no key held for 'attacker-issuer-key'" in out

    def test_the_old_pooled_flag_is_refused_with_instructions(self, kit, capsys):
        receipt, _, _, paths, tmp = kit
        (tmp / "r.json").write_text(json.dumps(receipt))
        rc, out, err = _run(["verify", str(tmp / "r.json"), "--keys", str(paths["issuer"]),
                             "--keys", str(paths["party"])], capsys)
        assert rc == 2 and "VERIFIED" not in out
        assert "--issuer-keys" in err and "--party-keys" in err

    def test_the_genuine_receipt_still_verifies(self, kit, capsys):
        receipt, _, _, paths, tmp = kit
        (tmp / "r.json").write_text(json.dumps(receipt))
        rc, out, _ = _run(["verify", str(tmp / "r.json"), "--issuer-keys", str(paths["issuer"]),
                           "--party-keys", str(paths["party"])], capsys)
        assert rc == 0 and out.rstrip().endswith("VERIFIED") and "settlement.complete" in out

    def test_a_key_in_both_roles_is_refused(self, kit, capsys):
        receipt, issuer_doc, _, paths, tmp = kit
        (tmp / "r.json").write_text(json.dumps(receipt))
        with pytest.raises(SystemExit, match="both an issuer and a party document"):
            cli.main(["verify", str(tmp / "r.json"), "--issuer-keys", str(paths["issuer"]),
                      "--party-keys", str(paths["issuer"])])


class TestF02NoLastWins:
    def test_a_later_document_cannot_replace_an_earlier_key(self, kit):
        _, issuer_doc, _, _, _ = kit
        first = load_key_set(issuer_doc)
        replacement = copy.deepcopy(issuer_doc)
        replacement["keys"][0]["public_key_pem"] = public_key_pem(ec.generate_private_key(ec.SECP256R1()))
        with pytest.raises(PartyError, match="already supplied"):
            KeySet().add_document(first, "a").add_document(load_key_set(replacement), "b")

    def test_a_later_document_cannot_clear_a_revocation(self, kit):
        _, issuer_doc, _, _, _ = kit
        revoked = copy.deepcopy(issuer_doc)
        revoked["keys"][0]["status"] = "revoked"
        with pytest.raises(PartyError, match="already supplied"):
            KeySet().add_document(load_key_set(revoked), "a").add_document(load_key_set(issuer_doc), "b")

    def test_a_key_listed_twice_in_one_document_is_refused(self, kit):
        _, issuer_doc, _, _, _ = kit
        doubled = copy.deepcopy(issuer_doc)
        doubled["keys"].append(copy.deepcopy(doubled["keys"][0]))
        with pytest.raises(PartyError, match="more than once"):
            load_key_set(doubled)

    def test_the_cli_refuses_two_issuer_documents_claiming_one_key(self, kit):
        receipt, _, _, paths, tmp = kit
        (tmp / "r.json").write_text(json.dumps(receipt))
        with pytest.raises(SystemExit, match="already supplied"):
            cli.main(["verify", str(tmp / "r.json"), "--issuer-keys", str(paths["issuer"]),
                      "--issuer-keys", str(paths["issuer"])])


class TestLowFindings:
    def test_f04_only_the_canonical_spelling_of_an_es256_signature_is_accepted(self, kit):
        receipt, issuer_doc, party_doc, _, _ = kit
        sig = receipt["signatures"][0]["sig"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        twins = [sig[:-1] + c for c in alphabet if c != sig[-1]
                 and base64.urlsafe_b64decode(sig[:-1] + c + "==") == base64.urlsafe_b64decode(sig + "==")]
        assert twins, "the vector's last character should have unused bits"
        for twin in twins:
            r = copy.deepcopy(receipt)
            r["signatures"][0]["sig"] = twin
            result = verify(r, issuer_keys=load_key_set(issuer_doc), party_keys=load_key_set(party_doc))
            assert not result.ok and "canonical" in str(result)

    def test_f05_an_es256_signature_naming_a_non_ecdsa_key_is_a_fail_line(self, kit):
        from cryptography.hazmat.primitives.asymmetric import mldsa

        receipt, issuer_doc, party_doc, _, _ = kit
        key_id = receipt["signatures"][0]["key_id"]
        issuer = load_key_set(issuer_doc)
        issuer[key_id] = mldsa.MLDSA65PrivateKey.generate().public_key()
        result = verify(receipt, issuer_keys=issuer, party_keys=load_key_set(party_doc))
        assert not result.ok and "not an ECDSA P-256 key" in str(result)

    def test_f05_deep_nesting_is_an_error_not_a_traceback(self, tmp_path):
        deep = tmp_path / "deep.json"
        deep.write_text("[" * 200000 + "]" * 200000)
        with pytest.raises(SystemExit, match="nested too deeply"):
            cli.main(["verify", str(deep), "--issuer-keys", str(deep)])

    def test_f06_duplicate_object_keys_are_refused(self, kit):
        receipt, _, _, paths, tmp = kit
        text = json.dumps(receipt)
        doubled = text[:-1] + ', "receipt_id": "someone-else"}'
        (tmp / "dup.json").write_text(doubled)
        with pytest.raises(SystemExit, match="duplicate object key 'receipt_id'"):
            cli.main(["verify", str(tmp / "dup.json"), "--issuer-keys", str(paths["issuer"])])


class TestWhatVerifiedDoesNotCover:
    def test_the_limits_are_printed(self, kit, capsys):
        receipt, _, _, paths, tmp = kit
        (tmp / "r.json").write_text(json.dumps(receipt))
        rc, out, _ = _run(["verify", str(tmp / "r.json"), "--issuer-keys", str(paths["issuer"]),
                           "--party-keys", str(paths["party"])], capsys)
        assert rc == 0
        assert "trigger timestamps are not signed" in out
        assert "key validity windows" in out
        assert "payload_hash was not checked" in out

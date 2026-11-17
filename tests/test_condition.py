"""The Settlement Condition projection (sdcreceipt.condition): what is hashed, what is not, and what is refused."""
import hashlib
import json

import pytest

from sdcreceipt.canonical import canonicalize_bytes
from sdcreceipt.cli import main
from sdcreceipt.condition import PROJECTION, ConditionError, condition_hash, project

NS = "https://semanticdatacharter.com/ns/sdc4/"
M, G, C, T = "m" * 24, "g" * 24, "c" * 24, "t" * 24
ID, NONCE, KIND, AMT, LAPSE, ADP = "i" * 24, "n" * 24, "k" * 24, "q" * 24, "l" * 24, "a"


def adapter(ct, inner, p="sdc4"):
    return f"<{p}:ms-{ADP * 23}{ct[0]}><{p}:ms-{ct}><label>x</label><vtb>2026-01-01</vtb>{inner}</{p}:ms-{ct}></{p}:ms-{ADP * 23}{ct[0]}>"


def record(nonce="<xdstring-value>0123456789abcdef0123456789abcdef</xdstring-value>", amount="100.00", p="sdc4", extra=""):
    target = f"<{p}:ms-{T}><label>Settlement Target</label>{adapter(KIND, '<xdtoken-value>Cash Account</xdtoken-value>', p)}</{p}:ms-{T}>"
    cond = (f"<{p}:ms-{C}><label>Settlement Condition</label>"
            f"{adapter(ID, '<xdstring-value>SC-1</xdstring-value>', p)}{adapter(NONCE, nonce, p)}{target}"
            f"{adapter(AMT, f'<magnitude-status>_OPT_PH_</magnitude-status><xdquantity-value>{amount}</xdquantity-value><xdquantity-units><label>Currency</label><xdstring-value>USD</xdstring-value></xdquantity-units>', p)}"
            f"{adapter(LAPSE, '<xdtemporal-datetime>2026-12-31T00:00:00Z</xdtemporal-datetime>', p)}{extra}</{p}:ms-{C}>")
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n<{p}:dm-{M} xmlns:{p}="{NS}"><dm-label>Settlement Condition</dm-label>'
            f"<instance_id>abc</instance_id><{p}:ms-{G}><label>GR</label>{cond}"
            f"<{p}:ms-{'p' * 24}><label>Audit</label>{adapter('e' * 24, '<xdstring-value>changes every time</xdstring-value>', p)}</{p}:ms-{'p' * 24}>"
            f"</{p}:ms-{G}></{p}:dm-{M}>")


def test_the_projection_keeps_the_terms_and_drops_everything_else():
    got = project(record(), C)
    assert got == {
        "projection": PROJECTION, "model": M, "condition": C,
        "terms": {
            ID: "SC-1",
            NONCE: "0123456789abcdef0123456789abcdef",
            T: {KIND: "Cash Account"},
            AMT: {"value": "100.00", "units": "USD"},
            LAPSE: "2026-12-31T00:00:00Z",
        },
    }


def test_the_hash_is_sha256_over_rfc8785_of_the_projection():
    digest, canon = condition_hash(record(), C)
    assert canon == canonicalize_bytes(project(record(), C))
    assert digest == hashlib.sha256(canon).hexdigest()


def test_the_prefix_and_what_lies_outside_the_condition_do_not_change_the_hash():
    a = condition_hash(record(), C)[0]
    assert condition_hash(record(p="x"), C)[0] == a
    assert condition_hash(record().replace("changes every time", "something else"), C)[0] == a
    assert condition_hash(record().replace("<instance_id>abc", "<instance_id>xyz"), C)[0] == a


def test_values_are_lexical():
    """The parties hash the record they agreed; 100.00 and 100.0 are different records."""
    assert condition_hash(record(amount="100.0"), C)[0] != condition_hash(record(), C)[0]


def test_an_exceptional_value_is_projected_as_such_not_as_a_value():
    got = project(record(nonce="<sdc4:ASKU><ev-name>Asked but Unknown</ev-name></sdc4:ASKU>"), C)
    assert got["terms"][NONCE] == {"ev": "Asked but Unknown"}


@pytest.mark.parametrize("why,xml,cluster", [
    ("a DOCTYPE", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "y">]>' + record().split("?>", 1)[1], C),
    ("not an SDC4 model root", record().replace(f"dm-{M}", "notdm"), C),
    ("the cluster is absent", record(), "z" * 24),
    ("the cluster twice", record(extra=f"<sdc4:ms-{C}><label>again</label></sdc4:ms-{C}>"), C),
    ("a leaf with no value and no Exceptional Value", record(nonce=""), C),
    ("not a ct_id", record(), "../etc"),
])
def test_refused(why, xml, cluster):
    with pytest.raises(ConditionError):
        project(xml, cluster)


def test_cli(tmp_path, capsys):
    rec = tmp_path / "r.xml"
    rec.write_text(record())
    out = tmp_path / "projection.json"
    assert main(["condition", str(rec), "--cluster", C, "--out", str(out)]) == 0
    digest = capsys.readouterr().out.strip()
    assert digest == condition_hash(record(), C)[0]
    # settling with the projection as the condition: the issuer hashes RFC 8785 of it and gets the same value
    assert hashlib.sha256(canonicalize_bytes(json.loads(out.read_text()))).hexdigest() == digest
    assert main(["condition", str(rec), "--cluster", "z" * 24]) == 2


# ---------------------------------------------------------------- the vector: a real record of the published model
VECTOR = __import__("pathlib").Path(__file__).parent / "condition"


def test_the_vector_from_a_record_of_the_published_model():
    expected = json.loads((VECTOR / "settlement-condition-ledger-account.expected.json").read_text())
    digest, canon = condition_hash((VECTOR / "settlement-condition-ledger-account.xml").read_bytes(), expected["cluster"])
    assert canon.decode() == expected["canonical"]
    assert digest == expected["condition_hash"]


def test_two_escrows_two_hashes():
    """T1: a Receipt for escrow 42 carries a hash no holder of escrow 43 has pinned."""
    xml = (VECTOR / "settlement-condition-ledger-account.xml").read_text()
    a = condition_hash(xml, "eid1kx2nx04u3okbo18vqrks")[0]
    b = condition_hash(xml.replace("<xdstring-value>42</xdstring-value>", "<xdstring-value>43</xdstring-value>"), "eid1kx2nx04u3okbo18vqrks")[0]
    assert a != b


def test_the_mcp_tool_returns_the_same_hash_and_refuses_cleanly():
    from sdcreceipt.mcp_server import _handle_request

    xml = (VECTOR / "settlement-condition-ledger-account.xml").read_text()
    expected = json.loads((VECTOR / "settlement-condition-ledger-account.expected.json").read_text())
    r = _handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "condition_hash", "arguments": {"record": xml, "cluster": expected["cluster"]}}})
    assert json.loads(r["result"]["content"][0]["text"])["condition_hash"] == expected["condition_hash"]
    r = _handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "condition_hash", "arguments": {"record": xml, "cluster": "z" * 24}}})
    assert r["result"]["isError"] is True

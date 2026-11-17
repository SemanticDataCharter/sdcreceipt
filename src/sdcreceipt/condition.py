#
# Copyright (c) 2026, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
The Settlement Condition projection: from a governed record to the JSON whose
hash is ``condition_hash``.

A VSL Receipt commits to its release condition by hash, and every party's
trigger signs that hash. When the condition is a Settlement Condition record
(the Business Documents library), each party, the issuer and the holder must
derive the *same* JSON from the record, or the hashes differ and the holder
refuses a valid settlement. So the projection is pinned here, small enough to
reimplement from this docstring, with a conformance vector in the kit.

The projection, ``sdc-settlement-condition/1``:

1. The input is a Governed Data Record as XML. Its root is ``sdc4:dm-<model>``.
   A DOCTYPE is refused (no entities, no external fetches).
2. The projected element is the Settlement Condition cluster,
   ``sdc4:ms-<condition>``, found as a descendant of the root. Exactly one must
   be present.
3. A cluster projects to an object. Each child element in the SDC4 namespace
   is a member:

   - a member is an SDC4 element named ``ms-<ct_id>``;
   - an *adapter* (no child outside the namespace, exactly one member inside
     it) stands for the leaf it holds, keyed by the leaf's ct_id;
   - a member that holds members is a cluster, projected the same way;
   - a member that holds none is a leaf, projected to its value (a leaf with
     neither a value nor an Exceptional Value is refused).

   A key is the ct_id alone, the part after ``ms-``.
4. A leaf's value is the text of its value element, exactly as written, with
   no trimming or number normalisation: ``xdstring-value``, ``xdtoken-value``,
   ``xdcount-value``, ``xdquantity-value``, ``xdfloat-value``,
   ``xddouble-value``, ``xdboolean-true``/``xdboolean-false``, or the one
   ``xdtemporal-*`` element present. A quantity is ``{"value", "units"}``, the
   units being the text of ``xdquantity-units/xdstring-value``. A leaf with an
   Exceptional Value in place of its value is ``{"ev": <ev-name>}``; with one
   beside its value, ``{"ev": <ev-name>, "value": <value>}``, so the value is
   never dropped from the hash.
   Everything else a leaf carries (label, validity times, accuracy, the
   placeholder flags) is not part of the agreed terms and is left out.
5. The result is ``{"projection": "sdc-settlement-condition/1", "model":
   <model>, "condition": <condition>, "terms": <object>}``, canonicalised by
   RFC 8785 and hashed with SHA-256, as lowercase hex.

What this does not do: it does not validate the record. Hash only a record that
validates against its published model (``sdcvalidator``): the model's schema
is what requires the nonce, the lapse and the identifiers of the target's
kind, and refuses a target a holder could read two ways. Including the model's
ct_id in the projection binds the hash to that schema. Values are taken
lexically, so ``100.00`` and ``100.0`` hash differently: the parties hash the
record they agreed, not a re-serialisation of it.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Any

from .canonical import canonicalize_bytes

PROJECTION = "sdc-settlement-condition/1"
SDC4 = "https://semanticdatacharter.com/ns/sdc4/"
_VALUE = ("xdstring-value", "xdtoken-value", "xdcount-value", "xdquantity-value", "xdfloat-value", "xddouble-value",
          "xdboolean-true", "xdboolean-false")
_CT = re.compile(r"^[a-z0-9]{20,32}$")


class ConditionError(ValueError):
    """The record cannot be projected."""


def _split(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        ns, local = tag[1:].split("}", 1)
        return ns, local
    return "", tag


def _sdc(el) -> bool:
    return _split(el.tag)[0] == SDC4


def _member_id(el) -> str:
    local = _split(el.tag)[1]
    if not local.startswith("ms-") or not _CT.match(local[3:]):
        raise ConditionError(f"not a member element: {local}")
    return local[3:]


def _is_member(el) -> bool:
    return _sdc(el) and _split(el.tag)[1].startswith("ms-")


def _ev(el):
    """The Exceptional Value a leaf carries in place of its value: an SDC4 element with an ``ev-name``."""
    for c in el:
        if _sdc(c) and not _is_member(c) and c.find("ev-name") is not None:
            return c
    return None


def _value(el) -> Any:
    plain = {(_split(c.tag)[1]): c for c in el if not _sdc(c)}
    if "xdquantity-value" in plain:
        units = plain.get("xdquantity-units")
        u = units.find("xdstring-value") if units is not None else None
        return {"value": plain["xdquantity-value"].text or "", "units": (u.text or "") if u is not None else ""}
    for name in _VALUE:
        if name in plain:
            return plain[name].text or ""
    temporal = [n for n in plain if n.startswith("xdtemporal-")]
    if len(temporal) == 1:
        return plain[temporal[0]].text or ""
    return None


def _leaf_value(el) -> Any:
    """A leaf's value; ``{"ev": name}`` for an Exceptional Value in its place; both when it stands beside a value.

    The reference model allows an Exceptional Value beside a value as well as in place of one. Both are hashed: a
    projection that kept only the Exceptional Value would drop the value from the hash, so an escrow ID with an
    Exceptional Value beside it would hash the same for every escrow.
    """
    ev, value = _ev(el), _value(el)
    if ev is None:
        return value
    out = {"ev": ev.find("ev-name").text or ""}
    if value is not None:
        out["value"] = value
    return out


def _project(cluster) -> dict:
    out: dict[str, Any] = {}
    for child in cluster:
        if not _is_member(child):
            continue
        members = [c for c in child if _is_member(c)]
        plain = [c for c in child if not _sdc(c)]
        if not plain and len(members) == 1:        # an adapter: it stands for its leaf
            child = members[0]
            members = [c for c in child if _is_member(c)]
        key = _member_id(child)
        if members:                                  # a cluster
            value = _project(child)
        else:
            value = _leaf_value(child)
            if value is None:
                raise ConditionError(f"ms-{key} has no members, no value and no Exceptional Value")
        if key in out:
            raise ConditionError(f"member {key} appears twice")
        out[key] = value
    return out


def parse(xml: bytes | str):
    data = xml.encode() if isinstance(xml, str) else xml
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise ConditionError("a DOCTYPE or entity declaration is refused")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ConditionError(f"not well-formed XML: {e}") from e


def project(xml: bytes | str, condition: str) -> dict:
    """The projection of the Settlement Condition cluster ``ms-<condition>`` in a governed record."""
    if not _CT.match(condition):
        raise ConditionError(f"not a ct_id: {condition}")
    root = parse(xml)
    ns, local = _split(root.tag)
    if ns != SDC4 or not local.startswith("dm-"):
        raise ConditionError("the root is not an SDC4 data model element (sdc4:dm-<ct_id>)")
    found = [el for el in root.iter() if _sdc(el) and _split(el.tag)[1] == f"ms-{condition}"]
    if len(found) != 1:
        raise ConditionError(f"expected one ms-{condition}, found {len(found)}")
    return {"projection": PROJECTION, "model": local[3:], "condition": condition, "terms": _project(found[0])}


def condition_hash(xml: bytes | str, condition: str) -> tuple[str, bytes]:
    """``(condition_hash, canonical bytes)`` for the record: SHA-256 hex over RFC 8785 of the projection."""
    canon = canonicalize_bytes(project(xml, condition))
    return hashlib.sha256(canon).hexdigest(), canon

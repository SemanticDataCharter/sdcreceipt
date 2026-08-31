#
# Copyright (c) 2025, Axius SDC, Inc.
# Licensed under the Apache License, Version 2.0.
#
"""
Issuing a Receipt: the one thing here that needs an account.

Every other verb in this tool works with nothing from us. `verify` needs no
network at all. This one posts to a VSL issuer, which means an endpoint, a
token, and a balance, and it is worth being blunt about that rather than
blurring the line the rest of the package draws.

★ Why it belongs here anyway. Before this, getting a Receipt meant
hand-building a POST with five fields, two of which are not guessable:
`condition` is hashed and never stored, and `current_state`/`target_state` come
from a governance workflow defined in a schema that lives on the server. A tool
that handled everything *after* a Receipt existed and nothing about obtaining
one left the first step as the hardest.

The rejection path matters as much as the happy one. A VSL issuer answers a bad
transition with the states that would have worked, and `SettleRejected` carries
that through instead of flattening it to a status code.
"""

from __future__ import annotations

import json
from typing import Any

DEFAULT_ENDPOINT = "https://sdcstudio.axius-sdc.com/api/v1/vsl/settle"

#: Fields the issuer requires, in the order a person is asked for them.
REQUIRED = ("current_state", "target_state", "condition", "parties")


class SettleError(Exception):
    """Issuing failed for a reason that is not a governance rejection."""


class SettleRejected(SettleError):
    """
    The issuer refused the transition, and said what it would have accepted.

    Kept distinct from `SettleError` because it is the recoverable one: the
    caller asked for a transition that does not exist, and the answer contains
    the ones that do.
    """

    def __init__(self, body: dict[str, Any]):
        super().__init__(body.get("error", "The issuer rejected the transition."))
        self.body = body
        self.current_state = body.get("current_state", "")
        self.allowed = body.get("allowed_transitions") or []
        self.workflow = body.get("workflow") or []
        self.hint = body.get("hint", "")
        #: False when the model constrains no states at all, in which case the
        #: refusal came from a different governance dimension and telling
        #: someone to fix their state would send them the wrong way.
        self.defines_states = body.get("model_defines_workflow_states", True)

    def explain(self) -> str:
        """The rejection as a person should read it."""
        lines = [str(self)]
        if self.hint:
            lines += ["", self.hint]
        if self.allowed:
            targets = ", ".join(
                t.get("target_state", str(t)) if isinstance(t, dict) else str(t)
                for t in self.allowed
            )
            lines += ["", f"From {self.current_state!r} you can go to: {targets}"]
        if self.workflow:
            lines += ["", "This model's workflow:"]
            for path in self.workflow:
                states = " -> ".join(path.get("states", []))
                lines.append(f"  {path.get('path', '(unnamed)')}: {states}")
        return "\n".join(lines)


def settle(
    payload: str,
    *,
    endpoint: str,
    token: str,
    current_state: str,
    target_state: str,
    condition: dict[str, Any],
    parties: list[str],
    previous_receipt_id: str = "",
    timeout: int = 60,
) -> dict[str, Any]:
    """
    Ask a VSL issuer to validate, govern, attest and sign one exchange.

    Args:
        payload: The SDC4 XML instance, as text.
        endpoint: The issuer's settle URL.
        token: An API token for that issuer.
        current_state: The workflow state the payload is in.
        target_state: The state being transitioned to.
        condition: The release condition. Hashed by the issuer and never
            stored, so it may hold terms neither party wants published.
        parties: At least two `key_id` URIs, each controlled by its party.
        previous_receipt_id: Chain this settlement onto an earlier one.

    Raises:
        SettleRejected: The transition was refused, with what would work.
        SettleError: Anything else, including transport failures.
    """
    if len(set(parties)) < 2:
        # Caught here rather than after a round trip, and stated as the reason
        # rather than the rule: a settlement with one party is a signature.
        raise SettleError(
            f"A settlement needs at least two distinct parties; got {len(set(parties))}. "
            "Each is a key_id URI that party controls, which is what lets a "
            "verifier check their signature without asking us."
        )

    body = {
        "payload": payload,
        "current_state": current_state,
        "target_state": target_state,
        "condition": condition,
        "parties": parties,
    }
    if previous_receipt_id:
        body["previous_receipt_id"] = previous_receipt_id

    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Token {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raise SettleError(f"{exc.code} from {endpoint}: {raw[:400]}") from exc

        if exc.code == 422 and "allowed_transitions" in parsed:
            raise SettleRejected(parsed) from exc
        if exc.code == 401:
            raise SettleError(
                f"{endpoint} rejected the token. Issuing is the one verb here "
                "that needs an account; everything else works without one."
            ) from exc
        if exc.code == 402:
            raise SettleError(
                f"Insufficient balance at {endpoint}: {parsed.get('error', raw[:200])}"
            ) from exc
        raise SettleError(
            f"{exc.code} from {endpoint}: {parsed.get('error', raw[:400])}"
        ) from exc
    except urllib.error.URLError as exc:
        raise SettleError(f"Could not reach {endpoint}: {exc.reason}") from exc

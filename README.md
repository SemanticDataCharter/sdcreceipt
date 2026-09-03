# sdcreceipt

Verify and settle VSL Settlement Receipts.

**Verification needs no account, no network, and nothing from the issuer.**
That is the point of the tool: a claim that anyone can check a Receipt
independently is worth exactly as much as the ability to do it.

Apache-2.0.

```bash
pip install sdcreceipt
```

## Four verbs

```bash
# Check a Receipt you were sent. Offline.
sdcreceipt verify receipt.json --keys issuer-keys.json

# Set yourself up as a party: keypair + the document to publish.
sdcreceipt init --key-id https://vendor.example/.well-known/vsl-key.json

# Authorize a settlement you are a party to.
sdcreceipt trigger receipt.json --key vsl-party.pem \
    --key-id https://vendor.example/.well-known/vsl-key.json

# Ask an issuer for a Receipt. The one verb that needs an account.
sdcreceipt settle payload.xml \
    --party https://vendor.example/.well-known/vsl-key.json \
    --party did:web:partner.example
```

`settle` prompts for anything it needs and was not given. Two of its fields are
not guessable and never were: the release condition is hashed by the issuer and
never stored, and `current_state`/`target_state` come from a governance workflow
defined in a schema the issuer holds, not you.

If the issuer refuses the transition it answers with the ones it would have
accepted, and `settle` prints them:

```
Governance evaluation produced no Receipt. Decision was DENY

From 'draft' you can go to: review

This model's workflow:
  standard: draft -> review -> published
```

It exits 2 there, and 1 on a real failure, so a script can tell "ask again
differently" from "something is broken".

`verify` exits 0 only if every check passed, so it composes in a shell without
anyone parsing output.

That is the whole surface. This is a client, not a product, and its value is in
being small enough to read.

## Try it without reading anything

```bash
python examples/settle.py
```

One settlement end to end: two parties, two signatures, verified offline. No
account, no network, no API key. See [`examples/`](examples/).

## For an agent

The same two things over MCP, in the same package:

```bash
sdcreceipt-mcp --key vsl-party.pem \
    --key-id https://vendor.example/.well-known/vsl-key.json
```

Exposes `verify_receipt`, `sign_trigger` and `settle`. Each is advertised only
when the server has what it needs, so a tool is never offered whose every call
would fail.

Two deliberate omissions, and they are the security posture rather than an
oversight:

- **No key generation.** A private key generated inside an agent session has no
  clear custody story. `init` stays a human act at a terminal.
- **No submission.** `sign_trigger` returns a signed trigger for you to submit.
  Submitting takes a destination from the caller, and a signed trigger plus an
  arbitrary host is the combination worth refusing.

`settle` is available when the server is started with `--endpoint` and a token,
and it is the only tool that reaches the network. The endpoint is fixed at
start-up exactly like the key, so a caller can never redirect where a payload
goes. **No tool takes a URL**, and that is the invariant to keep if this ever
grows another one.

The signing key is given at start-up, never in a tool call, so it does not
travel through the conversation.

---

## If you were sent a Receipt

You do not need an account with anyone.

```bash
pip install sdcreceipt
curl -O https://sdcstudio.axius-sdc.com/.well-known/sdcstudio-signing-keys.json
sdcreceipt verify receipt.json --keys sdcstudio-signing-keys.json
```

Every check is reported, not just the first failure:

```
PASS  schema: conforms
PASS  receipt_hash: matches the canonical content
PASS  signature[sdcstudio-signing-key-v1]: verifies over receipt_hash
PASS  trigger[https://vendor.example/.well-known/vsl-key.json]: verifies
PASS  settlement.complete: every listed party has triggered

VERIFIED
```

A Receipt carries **hash commitments, never the payload**. So verification
tells you a conformant, authorized, dual-triggered exchange occurred, without
anyone having to disclose what was exchanged. If you also hold the payload or
the governance Receipt, pass them and those get checked too:

```bash
sdcreceipt verify receipt.json --keys keys.json \
    --payload manifest.xml --governance governance-receipt.json
```

## If you need to become a party

A settlement identifies each party by a `key_id` that **you** control. That is
deliberate: it means verifying your signature does not route through the
issuer, so nobody has to stay alive for your old signatures to keep meaning
something.

```bash
sdcreceipt init --key-id https://vendor.example/.well-known/vsl-key.json
```

That writes a private key (mode `0600`) and a key document, and tells you the
exact URL the document must be reachable at. Publishing one JSON file is the
whole onboarding requirement.

Then, when you are sent a Receipt to authorize:

```bash
sdcreceipt trigger receipt.json --key vsl-party.pem --key-id <your key_id>
```

It prints a signed trigger and stops. **Signing is inert; submitting is a side
effect**, so you send it yourself, or add `--submit <url>`.

---

## ★ Never take the verification key from the document

> The set of keys you will accept is decided **before** you read the document,
> and the document cannot change it.

`ds:RetrievalMethod` in XML-Signature, `jku` and `x5u` in JOSE, and their
equivalents elsewhere all say *"here is where my key lives."* That pointer was
written by whoever produced the document, so following it asks the document to
nominate the key that will judge it. A forged document nominates the forger's
key and verification "succeeds."

The failure is quiet. A pointer can name a domain that was correct when the
document was signed and has since lapsed; anyone who registers it can serve a
key at that path, and nothing about the document looks wrong — because nothing
about it *is* wrong. The verifier was asked where to look and did as it was
told.

This tool cannot make that mistake: `verify` takes keys as arguments and has
no code path that fetches one. That is a security property, not an
inconvenience.

The same applies to party keys, with a corollary rather than an exemption.
Those `key_id`s *are* URIs the counterparty controls, deliberately. Resolve
them over HTTPS only, only for identifiers already recorded in a Receipt you
trust, and keep a copy — a party who later loses a domain must not be able to
change what their old signatures mean.

Supply them, too. Party keys are optional in the sense that the issuer
signature and the payload hash can be checked without them, and **not** in the
sense that a settled Receipt means anything without them. Whether every party
triggered is a claim about authorization, so with no key to check a signature
against, `settlement.complete` is recorded as unestablished rather than passed
and the Receipt does not verify. Before 4.2.1 it passed on a comparison of
`key_id` strings alone, which reported VERIFIED over fabricated triggers.

---

## Conformance

`tests/conformance/` ships the issuer's published vectors, and the suite runs
this implementation against them.

Eleven vectors. **Every invalid one encodes a defect that was actually made**,
not a hypothetical: a DER signature where ES256 requires P1363, a signature
over the hex text of `receipt_hash` rather than its raw bytes, a governance
binding that does not match the evidence held, a trigger replayed from another
Receipt sharing the same release condition, and so on. Failing one for the
wrong reason does not count — the manifest names the check that must break.

```bash
pytest
```

**On independence, honestly.** Passing these vectors shows this tool agrees
with the issuer's published expectations, and that it never drifted from them.
It is *not* an independent re-derivation: this implementation and the issuer's
share design and history. The vectors are most valuable to someone writing a
verifier from the specification alone, which is what they are published for.

**The canonicalization underneath them is a different case, and it has been
checked against an independent implementation.** Every hash in a Receipt is
taken over RFC 8785 canonical bytes, so agreement on canonicalization is what
the rest of the verification rests on. In September 2026 that agreement was
tested in both directions with the MTCP project (Ahmad Abby), which implements
RFC 8785 using Trail of Bits `rfc8785` rather than `sdcgovernance`:

- MTCP's published vectors were run against `sdcgovernance.jcs`. Byte-for-byte
  agreement, with self-consistent SHA-256 values.
- The 21 vectors in `sdcgovernance/test-vectors/rfc8785-canonicalization.json`
  were run against MTCP's implementation. Zero disagreements, including the
  edge set: negative zero, subnormals, the 1e21 fixed-to-exponential boundary,
  C0 controls as lowercase `\u00xx`, unescaped solidus, an astral-plane
  character, and key ordering across a UTF-16 surrogate pair.

Those 21 were cross-checked against Node.js before publication and MTCP's run
on Python, so the two implementations agree **in two languages**. That is not
a claim either project could make about itself, and it is the reason to prefer
it over a second opinion from the same lineage.

It does not make the Receipt vectors above independent. It means that when
they disagree with your implementation, the disagreement is about the Receipt
rules and not about the bytes underneath them.

## Building your own

You do not have to use this tool, and the specification does not depend on it.
If you are writing a verifier:

**Do not write a second canonicalizer.** Use `sdcgovernance` or another
conformant RFC 8785 implementation. A second implementation can disagree with
the first, and the disagreement is silent: the bytes differ, so the hash
differs, and the artifact reads as tampered with rather than misencoded. This
tool re-exports `sdcgovernance.jcs` for exactly that reason and adds nothing.

**Refuse rather than guess.** Integers beyond ±(2⁵³−1) cannot round-trip
through an IEEE 754 double, and `NaN`/`Infinity` have no JSON representation.
Emitting something for those produces a hash that looks fine and fails only in
someone else's verifier.

**Report every check.** Stopping at the first failure hides the case that
matters most: a Receipt whose signature verifies but whose governance binding
does not.

**Check the curve.** A signature verified against a key on an unexpected curve
proves nothing about the party you believe signed.

## Versioning

MAJOR tracks the **SDC reference model**, so a `4.x.x` release targets SDC4.
It starts at 4 rather than 0 because of that convention, not because there
were three earlier versions. MINOR is features, PATCH is fixes. An SDC5
reference model would make this `5.x.x`.

The same scheme is used by `sdcvalidator`, `sdcgovernance` and the rest of the
family, so a version number tells you which reference model an artifact
targets without looking anything up.

Note that the **Receipt format version is separate** and independent: a
Receipt says `"version": "1.0"`, which is the frozen wire format, not this
package.

## Dependencies

`sdcgovernance` for canonicalization and `cryptography` for ECDSA, both
Apache-2.0-compatible libraries. `jsonschema` is optional and only needed for
`--schema`.

These are **library** dependencies. Nothing here calls a service, and
`verify` makes no network request at all.

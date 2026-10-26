# VSL conformance kit (1.1)

*The issuer builds this kit and copies it here, unchanged, so anyone can check a verifier against it without an
account. `sdcreceipt`'s own suite runs every vector and every key-document case (`tests/test_conformance.py`).*

Everything needed to build a Settlement Receipt verifier **and prove it is
correct**, without asking us and without trusting us.

This document is ordered deliberately: **how to check an implementation comes
before how to write one.** A verifier that is subtly wrong does not fail
loudly, it accepts bad receipts, and that is worse than having no verifier
because it manufactures confidence. Run the vectors first.

---

## 1. Start here: prove your implementation is correct

`manifest.json` lists every vector, what it should do, and why.

```
for each vector in manifest.json:
    evidence = keys.json + governance-receipt.json + payload.xml
    schema   = the schema the vector's own `version` names (1.0 or 1.1)
    for each name in vector.withhold:   # usually absent
        drop that piece of evidence

    result = your_verifier(<file>, evidence)

    if vector.expect == "valid":    result must PASS
    if vector.expect == "invalid":  result must FAIL, on vector.breaks
```

**`withhold` matters.** A vector that names it must be run *without* the
evidence it lists. The runner used to supply every key to every vector, so the
one arrangement that broke the verifier, a settled Receipt checked without
party keys, could not be expressed, and the defect shipped (see the last row
below).

**Failing an `invalid` vector for the wrong reason does not count.** That is
the difference between "my code rejected it" and "my code rejected it for the
reason that matters," and only the second means the bug is caught.

You are conformant when all 17 vectors and all 5 key-document cases (below) behave as documented. Our own kit build refuses
to write a vector that does not, so the file you have has been held to the
same standard.

### What each vector is for

Every `invalid` vector is **a mistake that was actually made building VSL**,
not a hypothetical. That is what makes this a regression suite rather than a
demonstration.

| Vector | Expect | What it catches |
|---|---|---|
| `valid-settled` | valid | The happy path: signed, bound, fully triggered. |
| `valid-canonicalization-integral-float` | **valid** | ★ Your canonicalization. Contains a number RFC 8785 renders as `1`, not `1.0`. **If this is the only vector you fail, that is your bug.** |
| `signature-der-not-p1363` | invalid | A DER signature where ES256 requires P1363 `r‖s`. The exact defect found in our XMLDSig signer. |
| `signature-over-hex-string` | invalid | Signed over the *hex text* of `receipt_hash` rather than the 32 raw bytes. Both readings are plausible; one is correct. |
| `governance-binding-does-not-match` | invalid | Signature and hash both fine, but the Receipt commits to different governance evidence than the one held. A signed, unsupported verdict. |
| `trigger-replayed-from-another-receipt` | invalid | ★ A trigger lifted from another Receipt sharing this release condition. |
| `tampered-payload-hash` | invalid | `payload_hash` edited after signing. Must be caught without holding the payload. |
| `duplicate-trigger-from-one-party` | invalid | One party triggering twice with different timestamps. Count *distinct parties*, not signatures. |
| `missing-canonicalization-field` | invalid | Nothing states which rules produced the hash. |
| `unsupported-alg` | invalid | `alg` is not `ES256`, so nothing pins the curve or the encoding. |
| `valid-settled-1.1` | valid | **Receipt 1.1.** The same content signed twice: an `ES256` and an `ML-DSA-65` signature over the same 32-byte digest, both of which must verify. Pure ML-DSA signs the digest bytes as its message; the signature is the raw FIPS 204 byte string, 4412 base64url characters. Checked against `settlement-receipt-1.1.schema.json`. |
| `missing-mldsa-signature-1.1` | invalid | A Receipt that says 1.1 with only its `ES256` signature. 1.1 is the promise that both are there. The 1.1 schema catches it first; without schema validation you must still fail at `signatures.algorithms`. |
| `mldsa-signature-over-hex-string-1.1` | invalid | The `ML-DSA-65` signature is over the hex text of `receipt_hash` while the `ES256` one is correct. One signature verifying must not carry the other. |
| `mldsa-signature-wrong-length-1.1` | invalid | A 64-byte `ML-DSA-65` signature. The `alg` fixes the length (3309 bytes); the schema catches it first, the decode must catch it without. |
| `mldsa-signature-unknown-key-1.1` | invalid | The `ML-DSA-65` signature names a `key_id` the key document does not hold. A signature that cannot be checked is a failure, not a skip. |
| `issuer-signature-by-a-party-key` | invalid | ★ The issuer signature is genuine, made with a second key the vendor publishes in **its own** key document, and the content is untouched. The only reason to refuse is the role: a key you hold as a party's is never an issuer key, whatever the Receipt's `signatures` name. Run with every key in `keys.json`, the vendor's second key included, and you must still fail at that signature. This was the `sdcreceipt` command-line defect GHSA-gwhr-82j5-883w (found by Timothy Lee, October 2026). |
| `triggers-forged-no-party-keys` | invalid, **`withhold: party_keys`** | ★ Every trigger signature is well formed and wrong, and you are run **without party keys**. Party and trigger `key_id` sets still match, so a verifier that decides completeness by comparing strings says VERIFIED over fabricated authorization. `settlement.complete` must be recorded as unestablished. This shipped in `sdcreceipt` 4.2.0 and in our own reference verifier. |

### Key-document cases: assembling the keys before reading a Receipt

A verifier holds several published key documents: the issuer's, and one per party. How it puts them together
decides what a Receipt can get away with, so the kit tests that too. `manifest.json` lists the cases under
`key_documents`; the documents are in `key-documents/`.

```
for each case in manifest.key_documents:
    documents = [(entry.role, key-documents/<entry.file>) for entry in case.documents]
    outcome   = your_key_assembly(documents)       # "accepted" or "refused"
    outcome must equal case.expect
```

Roles come from **you**, never from a Receipt. The rules the cases hold you to:

| Case | Expect | Why |
|---|---|---|
| `issuer-and-two-parties` | accepted | The ordinary arrangement. The vendor's document publishes a second key; that is allowed, and it is a party key. With these keys `valid-settled` verifies and `issuer-signature-by-a-party-key` does not. |
| `same-key-id-in-two-documents` | refused | The vendor's document publishes a different key under the issuer's key_id. Merging documents last-wins would replace the issuer's key. A key_id comes from exactly one document. |
| `revocation-cleared-by-a-later-document` | refused | A later document lists a revoked key as active. Last-wins would clear the revocation. |
| `key-id-listed-twice-in-one-document` | refused | Which of two entries a parser keeps depends on the parser. Refuse the document. |
| `one-document-in-both-roles` | refused | The issuer's document given as a party document too. One key has one role. |

These come from Timothy Lee's release assurance review of `sdcreceipt` 4.3.x (findings F-01 and F-02), where the
verifier's command line pooled every document it was given. `sdcreceipt` 4.3.3 and later pass them.

### The two that catch the most implementations

**Canonicalization.** RFC 8785 requires ECMAScript `Number::toString`. Python's
`json.dumps` emits `1.0` where the standard requires `1`, `1e+16` where it
requires `10000000000000000`, and `1e-07` where it requires `1e-7`. A single
float anywhere is enough to compute a different `receipt_hash`, and the
failure looks exactly like tampering. Conformance vectors for canonicalization
alone are published separately in
[`sdcgovernance/test-vectors/`](https://github.com/SemanticDataCharter/sdcgovernance).

**Trigger replay.** A trigger signs `{condition_hash, receipt_id}`, never the
condition alone. Repeat trading relationships reuse the same release
condition, so a verifier checking only the condition accepts last month's
signature for this month's shipment. This is not exotic; it is the normal case.

**The check that was never run.** Party keys are optional in the sense that
the issuer signature and `receipt_hash` can be checked without them, and
**not** in the sense that a settled Receipt means anything without them.
Whether every party triggered is a claim about authorization. With no key to
check a signature against, `settlement.complete` must read as unestablished
and the Receipt must not verify. A verifier that quietly omits a requested
check and still says VERIFIED is worse than one that stops, because the
operator believes the check ran.

---

## 2. What is in the kit

| File | |
|---|---|
| `settlement-receipt-1.0.schema.json` | The frozen format. Normative. |
| `settlement-receipt-1.1.schema.json` | The 1.1 revision: the same content with two required signatures, `ES256` and `ML-DSA-65`. Normative for a Receipt that says `1.1`. |
| `manifest.json` | Every vector, its expectation, and why it exists. |
| `keys.json` | Public keys for the vectors. Vectors only, used nowhere else. `party_keys` includes the vendor's second key (`#k2`). |
| `key-documents/` | Published-shape key documents for the key-document cases. |
| `governance-receipt.json` | The governance Receipt the vectors bind to. |
| `payload.xml` | The payload the vectors commit to, for the optional payload check. |


---

## 3. The verification procedure

In order:

1. **Resolve the issuer key** by `key_id`, from
   `/.well-known/sdcstudio-signing-keys.json` **or a copy retained earlier**.
   Verification must work from a cached key; if your verifier needs the
   network, it has a dependency the format does not. **Never resolve the key
   from a location carried inside the Receipt** (see §4).
2. **Recompute `receipt_hash`** over the RFC 8785 canonical form of the
   Receipt with `receipt_hash`, `signatures` and `settlement.triggers`
   removed.
3. **Verify each signature** in `signatures` as ECDSA P-256 over **the raw 32
   bytes** of `receipt_hash`: the same digest, not its hex text.
4. **Verify each trigger** over the canonical form of
   `{condition_hash, receipt_id}`, confirm every `key_id` is a listed party,
   and confirm no party appears twice. **If you hold no party keys and the
   Receipt carries triggers, record `settlement.complete` as unestablished**;
   do not decide it by comparing `key_id` strings.
5. **If the governance Receipt is held**, confirm its own `receipt_hash`
   equals `governance.receipt_hash` and its decision matches.
6. **If the payload is held**, recompute `payload_hash` and re-run the
   recorded validator version.
7. **If a chain is held**, verify `previous_hash` linkage across the sequence.

Steps 5 to 7 are conditional by design. Holding only the Receipt, steps 2 to 4
still establish that a conformant, authorized, dual-triggered exchange
occurred. That is the audit-without-the-payload property.

### Why triggers are outside `receipt_hash`

They arrive after the Receipt is hashed and signed, sometimes days later. If
the hash covered them, appending one would invalidate the issuer signature and
the parties could not sign independently. Each trigger carries its own
signature and is bound to the Receipt through `receipt_id`.

---

## 4. Implementation notes

**Do not write a second canonicalizer.** Use an existing RFC 8785 library, or
[`sdcgovernance`](https://pypi.org/project/sdcgovernance/), which is
Apache-2.0 and differential-tested against a real ECMAScript engine. A second
implementation can disagree with the first, and the disagreement is silent.

**Refuse rather than guess.** Integers beyond ±(2⁵³−1) cannot round-trip
through an IEEE 754 double, and `NaN`/`Infinity` have no JSON representation.
Emitting something for these yields a hash that looks fine and fails only in
someone else's verifier.

**Report every check, not just the first failure.** An implementer running
these vectors learns one thing per run otherwise, and the case that matters
most (a Receipt whose signature verifies but whose governance binding does
not) is invisible if you stop early.

**Check the curve.** A signature verified against a key on an unexpected curve
proves nothing about the party you believe signed.

### ★ Never take the key from the document you are verifying

Resolve `key_id` against the published key set, or against a copy you retained
earlier. **Do not follow a key location carried inside the artifact.**

XML-Signature has `ds:RetrievalMethod`, JOSE has `jku` and `x5u`, and other
formats have equivalents. They all say the same thing: *here is where my key
lives.* But that pointer was written by whoever produced the document, so
resolving it asks the document to nominate the key that will be used to judge
it. A forged document simply nominates the forger's key, and verification
"succeeds."

This is not theoretical, and the failure is quiet. A pointer can name a domain
that was correct when the document was signed and has since been allowed to
lapse; anyone who then registers it can serve a key at that path and every
verifier that follows the pointer will trust documents they signed. Nothing
about the document looks wrong, because nothing about it *is* wrong: the
verifier was simply asked where to look and did as it was told.

The rule that avoids all of it:

> The set of keys you will accept is decided **before** you read the document,
> and the document cannot change it.

Concretely, for a Settlement Receipt: `key_id` is a **lookup key, not a
location**. Look it up in a key set you fetched independently, or one you
already hold. If `key_id` is absent from that set, the correct outcome is
"cannot verify", never "fetch it from wherever the Receipt says."

The same applies to party keys in `settlement.triggers`. Those `key_id`s are
URIs the counterparty controls, which is deliberate: it keeps verification
independent of the issuer. But *deliberate* is not *unconditional*. Resolve
them over HTTPS only, from an identifier recorded in a Receipt you already
trust, and cache the result: a party who later loses control of a domain must
not be able to retroactively change what their old signatures mean.

---

## 5. Where the kit comes from

The issuer generates the kit and copies it here unchanged. Keys are regenerated on every build, so a new kit version
changes every vector file. The build **refuses to write a vector or a key-document case that does not behave as
documented**, which is the property that makes the kit worth trusting. To check a copy, run `sdcreceipt`'s suite
(`pytest tests/test_conformance.py`), or your own implementation against `manifest.json`.

---

*Apache-2.0. Part of the Verifiable Settlement Layer; `sdcreceipt` (this repository) is the open party tool that
implements this procedure.*

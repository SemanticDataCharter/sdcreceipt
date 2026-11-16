# Design note: `verify` follows the chain and checks key windows

*Status: **approved 2026-11-16; #26 to #30 implemented on `dev`.** Check names and chain rules aligned on
2026-11-16 with SDCStudio's conformance kit 1.2 (SDCStudio#985; the issuer side is released and deployed), whose README sections
"Chains" and "Key windows" are normative where this note and the kit differ. Target: `sdcreceipt` 4.4.0 (new
behaviour, no format change). Closes two of the limits `verify` prints today under "Not covered by this result",
from Timothy Lee's 4.3.x review, recorded together as F-03 and F-11 to F-13.*

## 1. The two limits

`_print_not_checked` in `src/sdcreceipt/cli.py` tells every reader of a VERIFIED result that:

1. **`previous_hash` is not followed.** A Receipt that names an earlier Receipt is judged alone. Whether the earlier
   one exists, verifies, and is the one this Receipt committed to is never checked.
2. **Key validity windows are not compared with the Receipt's `timestamp`.** The issuer's key document publishes
   `not_before` and `not_after` for every key version it has used (`retired` after a rotation, never removed).
   `verify` reads `status` and fails a `revoked` key (`verify.py`, `_revoked`), but drops the window when it loads the
   document (`party.py`, `load_key_set`), so a signature made by a key outside its window still verifies.

Anyone who verifies Receipts for someone else has to build both of these before VERIFIED can stand for a sequence of
settlements rather than one. Closing them in the open verifier means each of them stops writing their own.

## 2. What does not change

- **The Receipt format.** Both checks read fields that already exist and are already signed: `previous_hash` and
  `timestamp` are inside `receipt_hash` in 1.0 and 1.1. No field is added, removed or reinterpreted, the schemas in
  `tests/conformance/` are untouched, and SDCStudio issues exactly what it issues today.
- **The key-document format.** `not_before` and `not_after` are already published by the issuer
  (`SigningKey.as_published` in SDCStudio). The verifier starts reading them; nobody has to publish anything new.
- **Keys are parameters.** Earlier Receipts are parameters too. `verify` never fetches an earlier Receipt, from the
  issuer's `/receipt/{id}` or anywhere else, for the same reason it never fetches a key: a document must not nominate
  the evidence it is judged by.
- **`verify()` keeps its signature.** Chain walking is a new function; existing library callers see no change except
  the window check (section 4.4).

## 3. Chain: `--chain DIR`

### 3.1 The flag

```
sdcreceipt verify receipt.json --issuer-keys issuer.json --party-keys a.json --party-keys b.json --chain receipts/
```

`--chain DIR` names a directory of Receipts the verifier holds. Every `*.json` file in it is read (bare Receipt or
the issuer's envelope, as `_load_receipt` already accepts). Starting from the Receipt being verified, the verifier
follows `previous_hash` back through DIR until it reaches a Receipt whose `previous_hash` is `null`, the head.

**Why a directory and not repeated `--previous FILE`.** A chain is held as a set of files, and the order is already
fixed by the hashes; asking the operator to supply the order adds a way to get it wrong and nothing to check. A
directory also lets one folder serve every Receipt in it. A single file is the same case as a directory of one, so
there is one flag, not two.

**Opt-in.** Without `--chain`, behaviour is as today and the NOTE about `previous_hash` stays. With it, the NOTE goes.

### 3.2 How the walk works

1. **Index DIR by recomputed hash, never by the recorded one.** Each file's `receipt_hash` is recomputed from its
   canonical content. A file cannot claim a place in the chain by writing a hash it does not have, and a cycle
   cannot be built from forged `receipt_hash` values. A file whose recorded and recomputed hashes differ is still
   indexed (by the recomputed value) and fails its own `receipt_hash` check if it is reached.
2. **Two different documents with one hash is a refusal.** They can differ only outside the hash, in `signatures` or
   `settlement.triggers` (for example, a copy saved before the second party triggered and one saved after). The
   verifier does not pick one: the link fails, naming both files. Byte-identical copies are fine.
3. **Walk back.** For the current Receipt with `previous_hash = H`, the earlier link is the one document in DIR whose
   recomputed hash is `H`. None found: the link fails on the bare prefix `chain.link[n H8…]`, or on `chain.link[n H8…] previous_hash` when
   other held Receipts are left over (the operator was given an earlier Receipt and this one names a different one).
   A left-over Receipt that *records* `H` without hashing to it is examined anyway, so the output says which link
   was edited: it fails its own `receipt_hash` and the join. `--chain` with nothing held still runs as a chain and
   fails on the bare prefix (kit vector `chain-link-not-held`, `"chain": []`). The walk stops
   at the first `null`, at the first failure it cannot walk past, or at a ceiling of 10,000 links (a verifier's input
   is chosen by whoever wants it to fail badly).
4. **Verify every link fully.** Each earlier Receipt runs the whole `verify()` procedure with the same
   `--issuer-keys`, `--party-keys` and `--schema`. Governance and payload checks apply to the Receipt named on the
   command line only, because those are held for that Receipt; the output says so for the earlier links.
5. **Check each join.** For each pair, two checks: `previous_hash` of the later equals the recomputed hash of the
   earlier (true by construction of the index, recorded so the output shows it), and the earlier `timestamp` is not
   after the later one. Both timestamps are signed, so the order check costs nothing and catches a Receipt spliced
   onto a chain it postdates.

### 3.3 Output

The flat `Result` stays flat. Checks from earlier links are recorded with the kit's prefix: `chain.link[`, the link number,
a space, the first 8 characters of the `previous_hash` that named it, `…` (U+2026) and `]`. The existing printer and
the `failures` list work unchanged:

```
PASS  receipt_hash: matches the canonical content
...
PASS  chain.link[1 2e41e3d3…] previous_hash: names a held Receipt
PASS  chain.link[1 2e41e3d3…] timestamp: 2026-09-30T14:26:10Z is not after 2026-09-30T14:26:18Z
PASS  chain.link[1 2e41e3d3…] signature[sdcstudio-signing-key-v1]: verifies over receipt_hash (ES256)
...
PASS  chain.head: reached after 3 earlier Receipts
```

A Receipt that is itself a head, verified with `--chain`, records `chain.head: this Receipt is the head` and passes.

### 3.4 Library and MCP

- **Library:** `verify_chain(receipt, *, held, issuer_keys, party_keys=None, schema=None, governance_receipt=None,
  payload=None) -> Result` in `verify.py`. `held` is an iterable of Receipt dicts. No I/O; the CLI reads DIR. A caller
  who already has the Receipts in memory never touches the filesystem.
- **MCP `verify_receipt`:** gains an optional `chain` argument, an array of Receipt objects (bare or enveloped),
  capped at the same 10,000, and an optional `party_keys` array alongside today's single object, since links in one
  chain can have different parties. It calls `verify_chain` when `chain` is present, so the tool and the CLI cannot
  disagree. The result gains `"chain_checked": true|false`, named the way `trigger_signatures_checked` is, so an
  agent cannot mistake an unrun chain check for a passed one. Same release as the CLI: every public surface ships
  together.

## 4. Key validity windows

### 4.1 What the key document says

Each key entry the issuer publishes carries `not_before` (when the key material was generated; no Receipt can
predate it) and `not_after` (when its successor took over or it was revoked; `null` while active). The rotation
runbook already tells holders to keep a copy of the key document with each Receipt, because this is what a verifier
compares the Receipt's `timestamp` against.

`load_key_set` keeps the window next to `status` in `KeySet` (a new `window: dict[key_id, (not_before, not_after)]`).
A value that is present but not the RFC 3339 UTC `Z` form the Receipt itself uses is refused when the document is
loaded, the same way a key listed twice is refused: two verifiers must not read one window two ways. A key with no
window stated has no window to check.

### 4.2 Issuer signatures

The Receipt's `timestamp` is when the issuer built and signed it, and it is inside `receipt_hash`. For every issuer
signature, the key's window must contain it, as a half-open interval:

```
not_before <= timestamp < not_after        (not_after null: no upper bound)
```

Half-open because the runbook sets a retired key's `not_after` equal to its successor's `not_before`; at that
instant the successor signs, not both. Failure is recorded on the signature itself, as revocation is:
`signature[key_id]: timestamp 2026-12-02T09:00:00Z is after the key's not_after 2026-11-30T00:00:00Z`.

**`retired` is not a failure.** A retired key inside its window verifies; that is what lets every Receipt signed
before a rotation keep verifying. **`revoked` stays a failure regardless of window**, as today. A revoked key is
presumed compromised, and a compromised key can write any `timestamp` it likes, so a window cannot rescue it.

### 4.3 Party triggers

Trigger timestamps are not signed, so a party key's window cannot be compared with when the trigger was made. One
bound is still sound: a trigger signs `{condition_hash, receipt_id}`, and the `receipt_id` did not exist before the
Receipt was built, so no trigger predates the Receipt's signed `timestamp`. Therefore:

- **`not_after <= timestamp` fails** the trigger: the key was retired before this Receipt existed, so it cannot have
  triggered it legitimately.
- **`not_before` is not judged**, because nothing signed bounds how late the trigger came. The NOTE says so.

Party documents written by `sdcreceipt init` today carry no window, and DID documents carry none, so for most parties
this check will have nothing to read until `init` starts writing `not_before` (issue 5).

### 4.4 On by default

The window check needs no new input: the key documents are already given. Revocation is enforced without a flag,
and a window is the same kind of statement by the same publisher, so it is enforced the same way. A Receipt that
verified under 4.3.x and fails under 4.4.0 on this check was signed by a key outside the window its own issuer
published; that is a finding, not a regression. There is no flag to turn it off: a verifier that quietly omits a
check and still says VERIFIED is worse than one that stops.

This is the one choice in the note that changes an existing result, so it is the first decision for Tim (section 7).

## 5. Exit codes

Unchanged in meaning; the new checks feed the existing ones.

| Exit | When |
|---|---|
| **0** | Every check passed: the Receipt, and with `--chain`, every earlier link, every join, and a head reached. |
| **1** | Any check failed, including a chain that cannot be established (a missing link, two documents with one hash, the ceiling reached before a head). Asked for and not established is a failure, as `settlement.complete` is without party keys. Files that cannot be read as JSON end the run as today (`error: … is not valid JSON`, status 1). |
| **2** | Usage: `--chain` names something that is not a directory or file, plus the existing `--keys` and missing `--issuer-keys` cases. |

The NOTE lines change to match: the window NOTE becomes "party key `not_before` is not judged: trigger timestamps are
not signed", and the `previous_hash` NOTE appears only when `--chain` was not given.

## 6. Conformance vectors

The kit is built by the issuer (`SDCStudio/design_docs/vsl/conformance/build_kit.py`) and copied here unchanged, and
the build refuses to write a vector that its own verifier (`vsl/services/verify.py`) does not judge as documented.
So every vector below is built in SDCStudio first, and the issuer's verifier gains the same two checks, before the
kit is copied into `tests/conformance/`. Two manifest extensions, both additive (older runners ignore unknown keys,
and a runner that does not implement them must report the vectors as not run, never as passed):

- a vector may carry `"chain": [files]`, the held earlier Receipts, run as `--chain`;
- a vector may carry `"key_documents": {"issuer": file, "party": [files]}` naming published-shape documents in
  `key-documents/` to use instead of `keys.json`, because `keys.json` is a flat PEM map with no status or window.

| Vector | Expect | Breaks | What it catches |
|---|---|---|---|
| `valid-chain-of-three` | valid | | Head, middle, tip; each fully settled; run from the tip with the other two held. |
| `chain-broken-link` | invalid | `chain.link[1 …] previous_hash` | The middle Receipt is held, but the tip's `previous_hash` names a different one. The tip alone verifies; only following the chain catches it. |
| `chain-earlier-link-tampered` | invalid | `chain.link[1 …] receipt_hash` | The middle Receipt's `payload_hash` was edited after signing. The tip is untouched and verifies alone. |
| `chain-link-not-held` | invalid | `chain.link[1 …]` | `--chain` given without the earlier Receipt. Asked for and not established. |
| `chain-out-of-order` | invalid | `chain.link[1 …] timestamp` | A validly signed Receipt names an earlier link whose signed `timestamp` is later than its own. |
| `chain-two-documents-one-hash` | invalid | `chain.link[1 …]` | Two copies of the middle Receipt with different trigger sets. The verifier must not choose. |
| `issuer-key-expired-before-timestamp` | invalid | `signature[sdcstudio-signing-key-v1]` | A retired key whose `not_after` precedes the Receipt's `timestamp`. Signature and hash are both correct; only the window says no. |
| `issuer-key-not-yet-valid` | invalid | `signature[sdcstudio-signing-key-v1]` | `timestamp` before the key's `not_before`. |
| `retired-key-inside-window` | **valid** | | The same retired key, `timestamp` inside its window. Rotation must not break earlier Receipts. |
| `party-key-retired-before-receipt` | invalid | `trigger[…]` | A party key whose `not_after` precedes the Receipt's `timestamp`. |

The kit README gains a section per extension, ordered like the rest: how to check an implementation first.

**As built (kit 1.2, 27 vectors):** the kit puts held Receipts under `vectors/chain/` and window documents under
`vectors/key-documents/`; #30 decides how those land in this repo's flat `tests/conformance/`. The issuer's verifier
drops a revoked key when assembling keys, where `sdcreceipt` keeps it and fails it with a reason. Both fail on
`signature[<key_id>]`, so the check names agree.

## 7. Decisions for Tim

*Kit 1.2 already takes the recommended option on 1 and 2: windows are always on, and an earlier link that was never
fully triggered fails the chain. If Tim decides otherwise for `sdcreceipt`, the kit changes first, or `sdcreceipt`
stops being conformant.*

1. **Window check on by default** (section 4.4), or behind a flag for one minor release. Recommended: on by default.
2. **Earlier links must be fully settled.** As proposed, every link runs the whole procedure, so an earlier Receipt
   with a missing trigger fails the chain. SDCStudio chains from any PERMIT Receipt, settled or not, so a chain whose
   middle exchange was never triggered would fail. Recommended: fail it; VERIFIED over a chain means every exchange
   in it settled. The alternative is a per-link `settlement.complete` that reports without failing.
3. **A trusted anchor.** A later option, not in this proposal: `--chain-anchor HASH`, to stop the walk at a Receipt
   the operator already verified and retained, for long chains. Not needed for 4.4.0.

## 8. What this does not close

- Trigger timestamps stay unsigned and advisory. Unchanged.
- A **retired** key whose private material later leaks can sign a Receipt backdated into its window. The window
  check does not catch that; revocation does, which is why revoked keys fail regardless of window.
- **HalvorsenDemo has no chain to walk today.** All ten of its Receipts in `settlement/receipts/` are heads
  (`previous_hash` null): the order-to-payment sequence is linked in the business documents, not in the Receipts.
  Covering it as one ReceiptChain needs the demo to settle each step with `previous_receipt_id` (issue 7), which
  reissues its Receipts.

## 9. Issues (filed 2026-11-16)

In `SemanticDataCharter/sdcreceipt` unless noted. Each lands on `dev`; no release until all of 1–6 are in.

1. **[sdcreceipt#26](https://github.com/SemanticDataCharter/sdcreceipt/issues/26) `verify --chain DIR`: follow `previous_hash` and verify every link.** `verify_chain()` in the library,
   the flag in the CLI, the walk in section 3.2, prefixed checks, exit codes in section 5, README and CHANGELOG.
2. **[sdcreceipt#27](https://github.com/SemanticDataCharter/sdcreceipt/issues/27) `verify`: compare key windows with the Receipt's `timestamp`.** `KeySet` keeps `not_before`/`not_after`;
   malformed windows refused at load; issuer rule in 4.2, party rule in 4.3; retired-in-window passes; revoked
   unchanged.
3. **[sdcreceipt#28](https://github.com/SemanticDataCharter/sdcreceipt/issues/28) MCP `verify_receipt`: `chain` argument, `party_keys` as an array, `chain_checked` in the result.** Same
   function as the CLI; tests in `tests/test_mcp_server.py`.
4. **[SDCStudio#985](https://github.com/Axius-SDC/SDCStudio/issues/985) SDCStudio: kit vectors for chain and key windows** (`SemanticDataCharter/SDCStudio`). The ten vectors in
   section 6, the two manifest extensions, the README sections, and the same two checks in `vsl/services/verify.py`
   so the build can hold them to their expectations. Blocks 6.
5. **[sdcreceipt#29](https://github.com/SemanticDataCharter/sdcreceipt/issues/29) `sdcreceipt init` writes `not_before` into the party key document.** Additive to the key document; makes the
   party rule in 4.3 apply to keys made with this tool. Rotation guidance for parties in the README.
6. **[sdcreceipt#30](https://github.com/SemanticDataCharter/sdcreceipt/issues/30) Copy kit 1.2 into `tests/conformance/` and run the new vectors through the real command line**
   (`tests/test_conformance.py`). After 4.
7. **[HalvorsenDemo#18](https://github.com/SemanticDataCharter/HalvorsenDemo/issues/18) HalvorsenDemo: settle the order-to-payment steps as one ReceiptChain** (`HalvorsenDemo`). Pass
   `previous_receipt_id` at each step, keep the folder of Receipts with the issuer's key document, and run
   `verify --chain` in `verify_all.py`. Reissues the demo's Receipts, so it is a demo release.

Found while reading, separate from this proposal:

8. **[HalvorsenDemo#19](https://github.com/SemanticDataCharter/HalvorsenDemo/issues/19) HalvorsenDemo `settlement/verify_all.py` lets the Receipt assign key roles** (`HalvorsenDemo`). `split_keys`
   treats whichever key ids the Receipt's own `signatures` name as the issuer's, after merging every document with
   last-wins `merge`. That is the arrangement `sdcreceipt` 4.3.3 removed from its CLI (F-01, F-02,
   GHSA-gwhr-82j5-883w). It should load `issuer-keys.json` as the issuer role and `keys/*-key.json` as the party
   role with `add_document`.

# Changelog

All notable changes to `sdcreceipt` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); MAJOR tracks the SDC
reference model (see README, Versioning).

## [Unreleased]

## [4.2.4] - 2026-10-03

One `verify` defect found while writing the instructions a reader follows on
the day the Verifiable Settlement Layer is announced. No wire-format change;
Receipt 1.0 is unchanged.

### Fixed

- **`verify` and `trigger` read the Receipt out of an issuer's response.** The
  issuer's `/receipt/{id}` endpoint answers with a status envelope (`receipt`,
  `status`, `decision`, `parties`, `triggered`, `awaiting`), and `settle`
  answers with another. A reader who downloaded either and ran `verify` on it
  was told `Receipt version None`. Both verbs now take the bare Receipt or
  either envelope, say on stderr when they unwrapped one, and verify the signed
  document inside. The MCP `verify_receipt` tool does the same.

## [4.2.3] - 2026-09-28

Two `settle` defects found on the first settlement with an outside party. Both
were in the client; the issuer, the Receipt and the verifier were correct. No
wire-format change; Receipt 1.0 is unchanged.

### Fixed

- **`settle --out` writes the Receipt, not the issuer's response.** An issuer
  answers with an envelope (`receipt`, `governance`, `verification`,
  `wallet`). The CLI wrote the whole envelope, so `verify` and `trigger`
  refused the file (`Receipt version None`) and the receipt id printed blank.
  The earlier tests mocked the issuer as if it answered with a bare Receipt,
  which is why none of them caught it. `--out` and stdout now carry the Receipt;
  the new `--response FILE` keeps the whole envelope for the record.
- **A DENY is said plainly.** The decision is printed to stderr, and a DENY
  says the Receipt records a refusal and accepts no triggers, with the model's
  workflow paths, so nobody triggers or forwards it by mistake.
- **`--current-state` defaults to the payload's `<current-state>`.** The issuer
  treats the instance's value as authoritative, but an omitted flag was a blind
  prompt whose natural answer (Enter) sent an empty state. A flag that differs
  from the payload is honored with a warning. Read with a pattern, not an XML
  parser, so the convenience adds no parser to the verb.
- **The MCP `settle` tool returns the Receipt itself** under `receipt` (the
  same envelope defect), plus `decision`, `settleable` and `wallet`; on a DENY,
  `hint`, `allowed_transitions` and `workflow`. A bare-Receipt response from an
  issuer still works in both places (`split_response`).

## [4.2.2] - 2026-09-16

The hardening pass from Timothy Lee's independent review of 4.2.0 (findings
F-02, F-03, F-05, F-06, F-07, F-09, F-10, F-11, F-15, F-16) plus two checks
from the VSL rollout inventory. No wire-format change; Receipt 1.0 is unchanged.

### Fixed

- **Key type and curve are checked when a key document is loaded (F-02).** An
  RSA or non-P-256 key previously reached `cryptography` and raised a
  `TypeError`; it is now refused with the offending `key_id` named.
- **A malformed Receipt is reported, never raised (F-03).** Every place the
  procedure indexes into the document is shape-checked first; the result
  carries a single `shape` failure. Over MCP the answer is a sentence about the
  input, and an unexpected exception is reported by class name without its
  text, which could carry paths.
- **The private key file is owner-only from its first byte (F-05).** Created
  with `O_EXCL` and mode 0600 rather than written and then chmod'ed.
- **The API token is read without echo (F-06)**, through `getpass`.
- **Nothing sensitive goes over plaintext (F-07).** `--endpoint`, `--submit`
  and the MCP server's `--endpoint` must be `https://`; loopback `http://` is
  the one exception, for a local issuer.
- **Signatures are decoded strictly (F-09):** exactly 86 unpadded base64url
  characters. Lenient decoding dropped characters outside the alphabet.
- **`load_private_key` now does what its docstring said (F-10):** it warns when
  the file is readable by other accounts.
- **The signing key's path stays out of MCP error text (F-11).**
- **A key marked `revoked` in its key document fails the signature it is named
  on,** for issuer and party keys alike. `load_key_set` returns a `KeySet` that
  keeps each key's published `status`; a plain `{key_id: key}` dict still works.
- **An unsupported Receipt `version` is refused** before any 1.0 rule is
  applied.

### Added

- `sdcreceipt verify --keys` may be repeated, one file per key document, so
  the issuer's and each party's documents no longer have to be merged by hand.
- `server.json` and a `publish-mcp` release job: `sdcreceipt-mcp` is published
  to the MCP registry beside `sdcvalidator` and `sdcgovernance`.
- `SECURITY.md` and this changelog.

### Changed

- `sdcgovernance` is pinned `>=4.2.0,<5` (F-16).
- README: the MCP section says three tools; the walkthrough shows the party
  key documents a settled Receipt needs to verify; the dependency section
  states the Python range, the pin and that a clean install resolves the
  transitive set (F-15).

## [4.2.1] - 2026-09-01

- A verifier that skipped the trigger check because no party keys were
  supplied still said VERIFIED (F-01). `settlement.complete` is now recorded as
  unestablished in that case and the Receipt does not verify.
- `sign_trigger` over MCP no longer accepts a caller-chosen `key_id` (F-04).
- The conformance kit ships in the sdist (F-08).
- Conformance vector 11, `triggers-forged-no-party-keys`.

## [4.2.0] - 2026-08-30

- `settle` verb, in the CLI and over MCP.

## [4.1.0]

- MCP stdio server: `verify_receipt`, `sign_trigger`.

## [4.0.0] - [4.0.1]

- First release: `verify`, `init`, `trigger`; ten published conformance
  vectors.

# Security

Report a vulnerability privately to security@axius-sdc.com, or through GitHub's
private vulnerability reporting on this repository. The organization policy is
at https://github.com/SemanticDataCharter/.github/blob/main/SECURITY.md. Expect an
acknowledgement within three business days.

## Supported versions

| version | supported |
|---|---|
| 4.2.x | yes |
| earlier | no; 4.2.0 and earlier reported VERIFIED on Receipts whose trigger signatures were never checked |

## What this tool protects, and what it does not

**Verification is offline and key-anchored.** `verify` takes keys as arguments
and has no code path that fetches one, so a Receipt cannot nominate the key that
judges it. Every check is reported; a check that could not run is recorded as a
failure, never skipped.

**The MCP server** (`sdcreceipt-mcp`) is stdio only. No tool takes a URL, a key
path or an identity: the signing key, its `key_id` and the issuer endpoint are
fixed when the operator starts the server. Tool arguments are attacker-reachable
and are shape-checked before use; a malformed Receipt is reported as malformed.
Error text never carries the key path.

**Out of scope.** This tool does not decide whether a party's published key
document is authentic: resolve `key_id`s over HTTPS, only for identifiers already
recorded in a Receipt you trust, and keep a copy. It does not establish temporal
validity: a key marked `revoked` fails, but the Receipt format carries no
validity window, so "valid at the time of settlement" is the verifier's own
policy. `settle` sends an API token to the configured issuer over HTTPS only.

# A settlement, end to end

```bash
pip install sdcreceipt
python examples/settle.py
```

No account, no network, no API key. It prints `VERIFIED` or it fails loudly.

Everything it writes lands in `examples/out/`, which is gitignored: the point is
that you generate these yourself rather than trusting ours.

## What it shows

| step | what happens |
|---|---|
| 1 | The issuer settles and hands each party a Receipt. |
| 2 | Each party generates a keypair and publishes a key document. |
| 3 | Each party signs a trigger, alone and in any order. |
| 4 | Anyone verifies, offline. |

Three properties are worth watching for, because they are the ones people
assume are impossible:

**The `key_id` is a URI the party controls.** Not one we issue. That is what
makes verification independent of us: a verifier fetches the key from the party's
own domain, and we are not in the path.

**The parties sign independently and out of order.** The example signs partner
first, which is not the order they appear in `parties`, to make the point. Both
sign `{condition_hash, receipt_id}`, which is fixed before either starts, so
neither has to wait for the other and neither signature can be replayed into a
different settlement.

**Verification touches no network.** Given the Receipt and the keys, everything
is local arithmetic. Step 4 makes no request of any kind.

## Doing it for real

Step 1 is the only part that changes. Instead of reading a fixture, the issuing
side calls `POST /api/v1/vsl/settle` and gets back a signed Receipt. Everything
after that is what the script does, using the same functions.

At a terminal:

```bash
sdcreceipt init    --key-id https://you.example/.well-known/vsl-key.json
sdcreceipt verify  receipt.json --issuer-keys issuer-keys.json
sdcreceipt trigger receipt.json --key party.pem --key-id https://you.example/...
```

Or, for an agent, over MCP:

```bash
sdcreceipt-mcp --key party.pem --key-id https://you.example/.well-known/vsl-key.json
```

The MCP server exposes `verify_receipt` and `sign_trigger` and nothing else. It
does not generate keys, and it never reaches the network: a signed trigger comes
back for you to submit. Started without `--key` it runs verify-only and does not
advertise signing at all.

# Lithos mining integration

The Rust node can serve as the Ergo backend for the Lithos client. Lithos keeps
Stratum, collateral selection, Non-Interactive Share Proofs (NISPs), rollups and
order batching in its own process. The node constructs and validates ordinary
Ergo blocks using client-supplied transactions and reward keys.

## Node configuration

Use a fully synced **UTXO archive node** with the extra-index enabled and caught
up. The default bundled node configuration already uses archive UTXO state and
indexing. Select the same network in the node and Lithos configurations.

```toml
[indexer]
enabled = true

[mining]
enabled = true
# Optional operator reward key for solo fallback. When omitted, the node
# resolves the initialized wallet's first EIP-3 address key.
# miner_public_key_hex = "<66 hex characters>"

[api.security]
api_key_hash = "<Blake2b-256 hash of your API secret>"
# Current Lithos clients omit api_key on solo candidate/solution/reward calls.
allow_unauthenticated_legacy_mining = true
```

Pass the unhashed secret as Lithos's `node.key`, and point `node.url` at the node's
REST address with a trailing slash. Check `/blockchain/indexedHeight`: its
`indexedHeight` should reach `fullHeight` and the indexer's status should be
`caughtUp` before starting the client. Successful HTTP alone does not prove
index readiness. Keep the node API on loopback when the client runs locally.

Authentication remains enabled by default. The explicit compatibility setting
opens only `/mining/candidate`, `/mining/solution`, `/mining/rewardAddress` and
`/mining/rewardPublicKey`. Both transaction-insertion endpoints and all v1
operator routes still require `api_key`. Clients which authenticate every mining
call can leave the compatibility setting false.

## Wallet files

Lithos's JVM client loads and signs with a local encrypted keystore. Newly
created Rust wallets use Appkit-compatible PBKDF2-HMAC-SHA256, 128000 iterations,
and Scala's AES-GCM field layout. Rust also reads historical SHA512 and trailing
GCM-tag wallet files without rewriting them.

For an existing Rust wallet, export an independently encrypted compatible copy:

```bash
cargo build --release -p ergo-wallet
./target/release/ergo-wallet export-keystore \
  --keystore /path/to/existing-wallet.json \
  --output-dir /path/to/lithos-keystore
```

The command prompts for the existing password without echoing it. For automation,
`--password-file /path/to/password-file` or `--password-file -` reads it without
placing the password in command-line arguments. The output directory must be
empty or absent. The source file remains unchanged; the copy uses fresh salt and
IV, preserves the seed and derivation mode, and uses the same password. Unix
output files are created with mode `0600`.

Set Lithos's `node.storagePath` to the emitted JSON file and `node.pass` to its
password. An existing wallet does not need a new mnemonic or new addresses.

## Candidate requests

- `POST /mining/candidateWithTxs`: a signed transaction JSON array using the
  operator's reward key.
- `POST /mining/candidateWithTxsAndPk`: `{"txs": [...], "pk": "<compressed key>"}`,
  using that key for candidate validation, emission and fee rewards, and the
  solved block's miner identity.
- `POST /api/v1/mining/candidate-with-txs`: accepts either shape under the normal
  v1 operator authentication policy.

Transactions retain their signed context extensions and request order. Valid
zero-fee and dependent transactions can enter this private block package without
public mempool admission. Normal consensus, cost and size limits still apply;
invalid, conflicting, unresolved or nonfitting members are omitted. Check the
returned proofs rather than assuming the whole request was included.

The work response retains `msg`, `b`, `h` and `pk`, adding `proof.msgPreimage`
(the serialized header without PoW) and `proof.txProofs` for included requested
transactions. Each proof has `leaf` (transaction ID) and `levels` (hexadecimal
side-byte followed by sibling digest). The proofs use the final block's
transaction/witness tree, so they bind the package to the work being mined.

Requested and ordinary jobs have independent bounded retention. Refreshing
ordinary mempool contents cannot evict a retained Lithos job; solo candidate
reads use the operator's key even after a lender request. Submit `pk` from the
work response with the nonce for an explicit-key job. Nonce-only submission
uses the operator's key. A tip change invalidates old jobs.

## Validation

The checked-in Scala 6.0.6 fixture contains genuinely signed, miner-key-sensitive
zero-fee transactions and a dependent child, rejection verdicts, original JSON,
and upcoming-transaction proofs. The node HTTP test submits that package,
verifies proof/preimage binding, mines and applies it, checks solo fallback and
stale rejection, and repeats with the AVL base cache enabled. Appkit 6.0.1,
matching the cloned Lithos client, independently unlocks Rust-generated and
exported keystores. Reproduction tools are in
[`scripts/jvm_mining_request_oracle`](../scripts/jvm_mining_request_oracle/README.md)
and [`scripts/jvm_keystore_oracle`](../scripts/jvm_keystore_oracle/README.md).

This establishes node API, block construction and keystore interoperability.
A full Lithos pool lifecycle with mining hardware is not exercised by these
repository tests.

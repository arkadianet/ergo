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
invalid, conflicting, unresolved or nonfitting members refuse the entire request
with HTTP 400. Accepted packages include every requested member, and their
returned proofs bind that inclusion to the offered work.

The work response retains `msg`, `b`, `h` and `pk`, adding `proof.msgPreimage`
(the serialized header without PoW) and `proof.txProofs` for included requested
transactions. Each proof has `leaf` (transaction ID) and `levels` (hexadecimal
side-byte followed by sibling digest). The proofs use the final block's
transaction/witness tree, so they bind the package to the work being mined.

Identical ordered packages on the live parent reuse their offered work for
60 seconds, including the message and template sequence. Cache hits do not
consume build permits. Requested jobs retain up to 16 templates per miner key
and share a 64 MiB accounted-byte budget (four times encoded transactions,
resolved system inputs, AVL proofs, extensions and membership proofs, at least
64 KiB per job). Budget pressure evicts stale or withdrawn jobs first. Ordinary
jobs retain their own 16-slot history. Refreshing
ordinary mempool contents cannot evict a retained Lithos job; solo candidate
reads use the operator's key even after a lender request. Submit `pk` from the
work response with the nonce for an explicit-key job. Nonce-only submission
matches templates marked as operator-owned when they were built; it does not
read the wallet again when a solution arrives. A tip change invalidates old jobs.

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

## Operator policy and private work

Requested packages form an atomic prefix after emission and before storage rent.
The node validates members in the supplied dependency order using the same
selection path and consensus budgets as ordinary candidates. Invalid members,
conflicts, or a package that cannot fit with the final fee transaction refuse
the request with HTTP 400; no partial package is offered. Operator exclusions
win, and the error names the excluded transaction. Included request members
satisfy matching operator requirements; remaining requirements retain their
ordinary priority and never withhold work. Requested members take budget before remaining policy requirements and the
private reservation. Rent limits, token preservation, and reservations still
apply to the remaining budget.

The node skips its storage-rent sweep for another miner key. This keeps the
operator's rent proceeds and recovered tokens out of lender rewards; requested
transactions may still claim rent themselves under consensus rules. Jobs owned
by the operator retain the normal sweep.

A request for another miner key never selects the operator's private queue.
Explicitly requesting a pending private member with another key is refused.
Requests for the operator key may include private work as ordinary full builds
do. Cancellation and expiry withdraw every retained template containing the
private member, including requested templates, and reject older in-flight
builds. Unrelated retained jobs survive ordinary refreshes and selective queue
withdrawals. Policy changes and global operator invalidation retire all retained jobs,
including lender jobs: every build obeys the operator policy, so retaining an
older job could allow an excluded transaction to be mined after a policy edit.
Clients must request fresh work after these administrative changes. Selective
private cancellation and expiry continue to preserve unrelated lender work.

`candidate-details` accepts the requested work's `template_seq` and message.
It records `build_reason: "Requested"`, categories for requested and private
members, and their frozen policy revision and operator generation. A requested
job may show `superseded` because it is separate from the current solo template;
that status still permits solving offered work. History includes both classes,
with up to 16 ordinary and 1024 requested templates, and journals requested outcomes
with their frozen miner identity. Lender jobs have no operator earnings
accounting and never become the public current-work freshness view.

Requested bytes are parsed on the serial mining worker using the committed
tip's activated script version, as mempool admission does, and trailing bytes
are rejected. Selection also parses under the frozen candidate context. Before
AVL proof generation or publication, every assembled transaction section is
round-tripped through the node's incoming block parser with the candidate's
block version, including ordinary candidates.

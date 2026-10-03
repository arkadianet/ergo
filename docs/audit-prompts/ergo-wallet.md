# `ergo-wallet` reference-quality audit prompt

Audit `ergo-wallet` as the custody, key derivation, transaction construction, and
proof-production component of a prospective reference Rust Ergo node. Follow
`docs/audit-prompts/COMMON.md` first, then `CONTRIBUTING.md`,
`docs/compatibility.md`, and `docs/codemap/ergo-wallet.md`. Apply the common
review-only workflow, complete file ledger, evidence requirements, and report
format. Establish behavior from this checkout and pinned primary authorities;
codemaps, comments, and names are claims to verify. Do not claim perfection.

## Mission and boundaries

Trace mnemonic/password input → seed → modern or legacy master key → derived
scalar/public key/address → encrypted storage → selection/build → signed bytes.
Also trace external secrets and untrusted multisignature hints independently of
the unlocked-wallet path. The consequential failures include lost funds,
unspendable outputs, nonce reuse, secret disclosure, incompatible restoration,
invalid signatures, and safe-looking partial state after an I/O failure.

Separate responsibilities owned here from the node bridge: this crate builds
and proves; the production bridge supplies coherent chain context, wallet
ownership checks, and final transaction validation. Verify both sides of every
assumption without silently granting correctness to the downstream verifier.

## Source landmarks and associated material

- Read `ergo-wallet/Cargo.toml`, `src/lib.rs`, and every module and inline test.
- Key path: `src/mnemonic.rs`, `derivation.rs`, `extended_key.rs`, `secret.rs`,
  `address.rs`, `encryption.rs`, `storage.rs`, `state.rs`, and `error.rs`.
- Build path: `src/tx_builder.rs`, `tx_context.rs`, and all `src/box_selector/`.
- Proof path: every file in `src/proving/` and `src/proving/sigma/`, including
  `randomness.rs`, `external.rs`, `secrets.rs`, `commitments.rs`, and `extract.rs`.
- Scan path: `src/scan/{predicate,registry,mod}.rs`; CLI:
  `src/bin/ergo-wallet.rs`, including each platform and input-source branch.
- Inventory `tests/it/main.rs` and each included test module; separately include
  `tests/proving_internal_consistency.rs` and `tests/multi_sig_inline.rs`.
- Resolve all fixture reads and `include_*` references. Examine
  `test-vectors/scala/proving/README.md` and `scala_signing_spec.json`, wallet
  fixture expectations, and the extraction/provenance paths named by tests.
- Read relevant consumers in `ergo-node/src/node/wallet_bridge/`,
  `ergo-node/src/wallet_boot.rs`, `ergo-state/src/wallet/`, and `ergo-api/src/wallet/`.

## Key derivation, addresses, and secret lifetime

1. Verify every mnemonic strength, entropy/checksum rule, import normalization,
   Unicode/passphrase treatment, and BIP39 seed length against independent
   vectors. Follow every allocation and copy of phrase, password, seed, scalar,
   HMAC output, decrypted plaintext, and private commitment randomness.
2. Check modern BIP32 scalar-range handling, big-endian serialization, hardened
   encoding, leading-zero preservation, invalid-child retry, index exhaustion,
   and retry behavior at hardened/non-hardened boundaries.
3. Verify the pre-1627 variable-length secret behavior and pre-EIP-3 paths against
   the correct reference era. Compatibility quirks must be narrowly explained;
   do not modernize away historical wallet recovery behavior.
4. Review path parser ambiguity, numeric overflow, malformed components,
   display/parse agreement, network-prefix handling, and SEC1 point validation.
   Confirm P2PK encoding uses the proper nonsegregated script representation.
5. Check redaction of `Debug`, `Display`, errors, assertions, CLI help, traces,
   DTO serialization, and nested containers. Identify residual unzeroized
   copies, including stack scalars and temporary buffers; distinguish evidence
   of erasure from an unsupported promise that all memory is scrubbed.
6. Verify that `test-utils` exposes deterministic randomness only for intended
   tests and cannot accidentally become the production signing backend through
   feature unification. Trace entropy failures and cryptographic RNG contracts.

## Encrypted storage and wallet state

7. Verify Scala-compatible PBKDF2-HMAC-SHA512 parameters, AES-GCM nonce/tag/key
   lengths, authenticated failure behavior, ciphertext seed format, and Java
   name-UUID filename derivation. MD5 here is a compatibility filename operation;
   assess its actual security role rather than flagging the name alone.
8. Reject unsupported cipher metadata before expensive or secret-bearing work.
   Review zero/extreme iteration counts, oversized JSON/hex/salt/ciphertext,
   malformed authenticated payload lengths, wrong passwords, tampering, and
   missing `usePre1627KeyDerivation` semantics.
9. Draw the uninitialized/locked/unlocked transition table for `open`, `init`,
   `restore`, `unlock`, `lock`, metadata loading, and seed checking. Verify each
   failed operation preserves the previous valid state and clears partial keys.
10. Inspect file creation/replacement, permissions from creation, directory
    permissions, symlinks, existing-file races, multiple secret files, truncated
    writes, close/flush/fsync semantics, cached metadata, and Windows behavior.
    Determine what is actually atomic and durable; prove restart behavior at
    each partial-write boundary without assuming encryption makes corruption safe.
11. Verify tracked-key deduplication, path/public-key consistency, visible/change
    address ownership, hydration ordering, legacy-key flags, locked-state reads,
    and recovery from persisted wallet-state corruption or schema drift.
12. Inspect scan predicate recursion/size bounds, register and token matching,
    wire tags, scan-name limits, reserved IDs, monotonic allocation/exhaustion,
    deregistration, wallet interactions, and restart consistency at the node seam.

## Selection, construction, and proving

13. Prove selection preserves ERG/token accounting with checked arithmetic,
    deterministic ties, duplicate candidate IDs, insufficient funds/tokens,
    zero or extreme targets, dust/minimum-value change, token-bearing change,
    and selected-input/transaction limits. Check what the replacement selector
    actually implements and whether its documentation promises more.
14. Verify builder fees, change, token mint/burn constraints, creation heights,
    register/script provenance, recipient/network validation, duplicate input
    rejection, ordered data inputs, and exact `bytes_to_sign` construction.
15. Match each supplied box to its input ID and each data box to its declared
    data-input ID. Review transaction count/order checks and the owned-to-borrowed
    reduction context for SELF, inputs, outputs, extensions, headers, and parameters.
16. Verify the supported-script gate and miner-reward maturity rules against the
    real chain validation context. Audit both standalone `Prover` behavior and
    the bridge's final cost/validity gate; report unsupported script families
    precisely, rather than treating a self-verifying proof as a valid transaction.
17. Verify DLog/DHT equations, scalar sampling, Fiat-Shamir domain separation,
    challenge lengths, AND/OR/threshold traversal, simulated branches,
    GF(2^192) interpolation, proof serialization order, and strict proof parsing.
18. Review multisignature commitment/hint indexing, node-position parsing,
    threshold boundary cases, repeated leaves, secret/hint conflicts, forged
    own commitments, secret-key/public-key mismatches, partial-proof extraction,
    nonce reuse across messages/rounds, and all clone/drop paths for secret hints.
19. Check external-secret decoding and locked-wallet signing cannot weaken script
    gates, substitute the message/context, leak secrets, or silently select a
    conflicting secret. Self-verification must have an explicit authority and cost.

## Required evidence and seam checks

- Derivation/address vectors must cover modern and legacy leading-zero cases,
  invalid-child boundaries, malformed paths, and every supported network/address
  mode. The CLI has mainnet/testnet choices; node devnet currently shares the
  testnet address prefix through `ergo-chain-spec` network parameters. Revalidate
  both the CLI and node mapping rather than assuming a third address prefix.
- Storage evidence must distinguish synthetic encryption consistency from
  Scala → Rust and Rust → Scala interoperability. Inspect ignored storage tests;
  missing extraction prerequisites are uncovered evidence, not passing parity.
- Reproduce wrong-password/tamper/unsupported-metadata failures and storage
  interruption/reopen cases in disposable directories; preserve actual wallets.
- Proof evidence must include independent Scala signatures/verifications, DHT,
  AND/OR/threshold and partial rounds, wrong message/context, damaged hints/proofs,
  and a rejected unsupported or immature script. Check fixture provenance pins.
- Compare selected/build/signed outputs with downstream semantic validation and
  the API/node wallet send tests. Include token conservation and fee/change cases
  that would remain invisible to a proof-only verifier.
- Inspect `tests/it/cli_smoke.rs`: secret stdin/file/argument handling, prompts,
  terminal/nonterminal errors, output precision, and documented command behavior.

## Scoped verification and completion

Use the common checks plus `cargo test --locked -p ergo-wallet` and
`cargo test --locked -p ergo-wallet --features test-utils`; both feature-gated
integration targets must be accounted for. Inspect ignored tests before selecting any run;
do not supply real secrets or call a live wallet merely to complete a checklist.

Complete only when the ledger covers all source, tests, comments, CLI branches,
fixtures, and associated tooling; the key/storage/build/proof/scan contracts are
mapped to evidence; production bridge assumptions are checked; and unsupported
behavior, missing oracle coverage, and residual custody risks are explicit in the
common report. Separate implementation defects from enhancement requests.

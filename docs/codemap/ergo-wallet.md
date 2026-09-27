# ergo-wallet

**Purpose:** HD wallet cryptography and secret storage. Owns BIP39
mnemonics, post-/pre-1627 BIP32 derivation, P2PK address rendering, encrypted
Scala-compatible secret files, sigma-proof production (single- and multi-sig
hint bags), and the wallet CLI. Wallet orchestration, persistence, scans, box
selection, and transaction construction now live in `ergo-wallet-service`;
wire DTOs live in `ergo-wallet-protocol`.

**Depends on (workspace):** `ergo-primitives`, `ergo-ser`, `ergo-sigma`,
`ergo-validation`
**Normal workspace boundary:** this crate has no normal dependency on
`ergo-state`, `ergo-wallet-service`, `ergo-wallet-protocol`, `ergo-api`, or
`ergo-node`, and it does not bring in `redb`, `tokio`, or `axum`.
**Depended on by:** `ergo-wallet-service`, `ergo-state` (miner-reward
classification and chain integration), `ergo-node`
**Approx LOC:** ~7.0K (`src/**/*.rs`)

## Start here
- `src/lib.rs` — crate root, module tree, convenience re-exports, and
  `miner_pubkey_for_seed`; orchestration is explicitly delegated to
  `ergo-wallet-service`.
- `src/extended_key.rs:20` — the BIP32 derivation engine and the post-/pre-1627
  split.
- `src/storage.rs:148` — encrypted secret-file format plus the
  `SecretStorage` lock/unlock state machine.
- `src/proving/prover.rs:39` — the single entry point that signs transaction
  inputs.
- `src/proving/sigma/mod.rs:67` — compound sigma-proof composition and
  self-verification.
- `src/proving/miner_reward.rs:22` — canonical reward-wrapper recognition used
  by the service/state apply integration.

## Modules
- `src/mnemonic.rs` — BIP39 newtype, generation/import, and seed derivation.
- `src/derivation.rs` — `DerivationPath` and Ergo/EIP-3 constants.
- `src/extended_key.rs` — modern and legacy BIP32 derivation over `k256` and
  HMAC-SHA512.
- `src/secret.rs`, `src/encryption.rs` — secret types, PBKDF2 key derivation,
  and AES-256-GCM buffers.
- `src/storage.rs` — Scala-compatible encrypted secret files, lock state, and
  unlocked key material.
- `src/address.rs` — curve-validated P2PK address encoding.
- `src/proving/` — sigma proving, secrets, external secrets, hints, and
  multi-sig commitment/extraction helpers.
- `src/proving/miner_reward.rs` — canonical mainnet miner-reward script shape
  detection; it is an integration helper, not a persistence layer.
- `src/tx_context.rs` — per-input chain context used by `Prover`.
- `src/bin/ergo-wallet.rs` — CLI for generation, import, derivation, pubkeys,
  and addresses.

## Key types, traits & functions
- `Mnemonic` — BIP39 phrase newtype with `generate`/`import`/`to_seed`.
- `DerivationPath` — parsed BIP32/BIP44 path and EIP-3 helpers.
- `ExtendedSecretKey`, `ExtendedSecretKeyLegacy`, `ExtendedPublicKey` — HD key
  derivation and compressed public-key output.
- `SecretStorage`, `EncryptedSecret`, `CipherParams` — secret-file persistence
  and lock/unlock lifecycle.
- `Prover`, `prove_sigma`, `SecretRegistry` — transaction signing and
  compound-proof composition.
- `extract_miner_reward_pubkey` — canonical reward-script classification hook.
- `BlockchainStateContext`, `BlockchainParameters` — chain context supplied by
  an embedding runtime.
- `WalletError` — crypto/storage/derivation error taxonomy.
- `miner_pubkey_for_seed` — EIP-3 first-address public-key convenience helper.

## Invariants & contracts
- **Secret-file format parity.** The `<uuid>.json` file uses
  PBKDF2-HMAC-SHA512 and AES-256-GCM with the Scala-compatible defaults; the
  ciphertext is the BIP39 seed, and the filename is Java
  `UUID.nameUUIDFromBytes` output.
- **Pre-1627 derivation fidelity.** Legacy child secrets retain the historical
  unsigned-byte representation because it is load-bearing for descendant HMAC
  inputs; modern derivation is fixed-width and zero-padded.
- **P2PK address safety.** Addresses use the curve-validated P2PK encoder,
  not a segregated-constants ErgoTree that could produce an unspendable
  address.
- **Proof self-verification.** `prove_sigma` builds, hashes, serializes, and
  verifies proofs before returning them; the produced bytes are compatible
  with the workspace verifier.
- **Secret hygiene.** Master keys, leaf scalars, derived encryption keys, and
  commitment randomness are zeroized, debug output is redacted, and errors do
  not embed secret material.
- **Split boundary.** This crate owns cryptography and secret-file types, not
  wallet tables, scan state, rescan orchestration, or transport DTOs. The
  service consumes those types; the state/node layers integrate them.
- **No `sigma-rust` runtime dependency.** Proving uses the native `k256`,
  HMAC, and `gf2_192` implementation; `sigma-rust` is a test/oracle concern.

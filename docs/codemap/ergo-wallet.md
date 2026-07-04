# ergo-wallet

**Purpose:** Ergo HD wallet. BIP39 mnemonics, post-/pre-1627 BIP32 HD
derivation, P2PK address rendering, AES-GCM/PBKDF2 encrypted secret-file
storage, sigma-proof production for transaction signing (single- and
multi-sig hint bags), unsigned-tx building, and box selection. Ships its
own `ergo-wallet` CLI binary. Proving is implemented natively over `k256`
and `gf2_192` — sigma-rust is never a runtime dependency.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-sigma,
ergo-validation, ergo-state, gf2_192
**Depended on by:** (see codemap index)
**Approx LOC:** ~8,900 (src/**/*.rs)

## Start here
- `src/lib.rs` — module tree + crate-root re-exports (`Mnemonic`,
  `ExtendedSecretKey`, `DerivationPath`, `SecretKey`, `WalletState`,
  `SecretStorage`, `WalletError`) and `miner_pubkey_for_seed`.
- `extended_key::ExtendedSecretKey` (`src/extended_key.rs:20`) — the BIP32
  derivation engine; read this and `ExtendedSecretKeyLegacy` to understand
  the post-/pre-1627 split.
- `storage::SecretStorage` (`src/storage.rs:148`) — the lock/unlock state
  machine + Scala-compatible encrypted-secret-file format.
- `proving::prover::Prover::sign` (`src/proving/prover.rs:67`) — the single
  entry point that signs every input of a transaction.
- `proving::sigma::prove_sigma` (`src/proving/sigma/mod.rs:67`) — compound
  AND/OR/threshold sigma-proof composition (the proving core).

## Modules
- `src/lib.rs` — crate root: module tree, re-exports, `miner_pubkey_for_seed`.
- `src/mnemonic.rs` — BIP39 mnemonic newtype (`Mnemonic`,
  `MnemonicStrength`); generate/import/`to_seed`. Wraps the `bip39` crate;
  `Debug`/`Display` deliberately hide the words.
- `src/derivation.rs` — `DerivationPath` parse/display + Ergo constants
  (`HARDENED_OFFSET`, `ERGO_COIN_TYPE = 429`, EIP-3 / pre-EIP-3 paths).
- `src/extended_key.rs` — BIP32 CKD-priv over `k256` + `hmac-sha512`;
  modern (`ExtendedSecretKey`) and legacy (`ExtendedSecretKeyLegacy`)
  variants; `ExtendedPublicKey`.
- `src/secret.rs` — `SecretKey` enum (only `Dlog` implemented today).
- `src/address.rs` — `pubkey_to_p2pk_address`: curve-validated P2PK
  encoding via `ergo_ser::address::encode_p2pk_from_pubkey`.
- `src/encryption.rs` — `derive_key_pbkdf2` (PBKDF2-HMAC-SHA512) +
  AES-256-GCM `encrypt`/`decrypt`; all buffers `Zeroizing`.
- `src/storage.rs` — encrypted-secret-file format (`EncryptedSecret`,
  `CipherParams`, `uuid_from_ciphertext`), `SecretStorage` lock/unlock
  state machine, `UnlockedMaster`/`UnlockedSecret`.
- `src/state.rs` — `WalletState`: in-memory caches (tracked pubkeys, P2PK
  trees, visible addresses, change address) + redb rehydration. Read by
  the `ergo-state` apply hook through a reader trait.
- `src/scan/` — `/scan/*` wallet subsystem (Scala scanning API).
- `src/scan/mod.rs` — module root; re-exports `ScanRegister`,
  `ScanningPredicate` (from `predicate`) and `Scan`, `ScanRegistry`,
  `ScanRequest`, `WalletInteraction`, `MAX_SCAN_NAME_LENGTH`,
  `MINING_SCAN_ID`, `PAYMENTS_SCAN_ID` (from `registry`).
- `src/scan/predicate.rs` — `ScanningPredicate` tracking-rule language:
  `Contains`, `Equals`, `ContainsAsset`, `And`, `Or` variants; Scala
  `ScanningPredicateJsonCodecs` wire format; box-matcher (`matches`).
- `src/scan/registry.rs` — `ScanRegistry` + `Scan`/`ScanRequest`/
  `WalletInteraction`; Scala scanId allocation (ids 1-10 reserved,
  user scans from 11; monotonic counter, ids never reused);
  `MAX_SCAN_NAME_LENGTH = 255`, `MINING_SCAN_ID = 9`,
  `PAYMENTS_SCAN_ID = 10`.
- `src/tx_builder.rs` — `UnsignedTxBuilder` + `PaymentRequest`: payment
  requests → `UnsignedTransaction` (pure; no chain access).
- `src/tx_context.rs` — `BlockchainStateContext`, `BlockchainParameters`,
  `ReductionContextOwned`: per-input evaluation context for `Prover::sign`.
- `src/box_selector/` — `BoxSelector` trait + `SelectionTarget`/`BoxSummary`/
  `SelectionResult` (`mod.rs`); `DefaultBoxSelector` (greedy value-DESC,
  `default.rs`); `ReplaceCompactCollectBoxSelector` (delegates today,
  `replace_compact.rs`).
- `src/proving/` — sigma proving subsystem (see below).
- `src/proving/sigma/` — compound-proof composition: `build` (phase 1 tree
  walk), `finalize` (challenge propagation + GF(2^192) threshold), `serialize`
  (verifier-order proof bytes), `fiat_shamir`, `crypto`, `tree`, `hints`.
- `src/bin/ergo-wallet.rs` — CLI: `generate`/`import`/`derive`/`pubkey`/
  `address`.

### `src/proving/` submodules
- `prover.rs` — `Prover::sign` tx-level orchestrator + script gate.
- `secrets.rs` — `SecretRegistry`: `ProveDlog(pk) → Scalar` / DHT lookup;
  zeroized storage.
- `external.rs` — `ProverExternalSecret`: decoded external secret for the
  locked-wallet signing path.
- `hints.rs` — `Hint`/`HintsBag`/`TransactionHintsBag`, `FirstProverMessage`
  (multi-sig commitment/proof exchange types).
- `node_position.rs` — `NodePosition`: depth-first tree addressing for hints.
- `randomness.rs` — `ProvingRng` abstraction (OsRng + deterministic test RNG).
- `schnorr.rs` — `prove_schnorr` (ProveDlog leaf proof).
- `dht.rs` — `prove_dht` (ProveDHTuple leaf proof).
- `commitments.rs` — `generate_commitments_for` (multi-sig commitment round).
- `extract.rs` — `bag_for_multisig` (hint extraction from a partial proof).

## Key types, traits & functions
- `Mnemonic` (struct) — BIP39 phrase newtype; `generate`/`import`/`to_seed` — `src/mnemonic.rs:41`
- `DerivationPath` (struct) — parsed BIP32/BIP44 path; `eip3_first_address`/`pre_eip3_first_address` — `src/derivation.rs:22`
- `ExtendedSecretKey` (struct) — modern BIP32 xsk; `derive_master_key`/`derive_child`/`derive_at_path`/`public_key` — `src/extended_key.rs:20`
- `ExtendedSecretKeyLegacy` (struct) — pre-1627 xsk (variable-length secret bytes) — `src/extended_key.rs:238`
- `ExtendedPublicKey` (struct) — compressed-SEC1 xpub; `compressed_bytes` — `src/extended_key.rs:182`
- `SecretStorage` (struct) — secret-file dir owner + lock/unlock; `open`/`init`/`restore`/`unlock`/`lock`/`load_metadata`/`check_seed` — `src/storage.rs:148`
- `LockState` (enum) — `Uninitialized`/`Locked`/`Unlocked` — `src/storage.rs:133`
- `UnlockedMaster` (enum) — `Modern`/`Legacy` in-memory master key; `derive_pubkey_at_path`/`derive_scalar_at_path` — `src/storage.rs:169`
- `EncryptedSecret` / `CipherParams` (struct) — on-disk JSON wire shape (Scala-compatible) — `src/storage.rs:56` / `:19`
- `uuid_from_ciphertext` (fn) — Java `UUID.nameUUIDFromBytes` filename derivation — `src/storage.rs:98`
- `WalletState` (struct) — in-memory wallet caches; `hydrate_from_reader`/`insert_tracked_pubkey`/`is_tracked_tree`/`visible_addresses` — `src/state.rs:26`
- `pubkey_to_p2pk_address` (fn) — curve-checked P2PK base58 encoding — `src/address.rs:20`
- `UnsignedTxBuilder` / `PaymentRequest` (struct) — requests → `UnsignedTransaction` — `src/tx_builder.rs:40` / `:17`
- `BoxSelector` (trait) — UTXO selection; `select` — `src/box_selector/mod.rs:50`
- `DefaultBoxSelector` (struct) — greedy value-DESC selector — `src/box_selector/default.rs:13`
- `Prover` (struct) — tx-level signer; `Prover::sign` — `src/proving/prover.rs:39` / `:67`
- `prove_sigma` (fn) — compound sigma-proof composition + self-verify — `src/proving/sigma/mod.rs:67`
- `SecretRegistry` (struct) — pubkey→scalar lookup; `from_master_key`/`merge_external_secrets`/`dlog_secret` — `src/proving/secrets.rs:44`
- `HintsBag` / `TransactionHintsBag` (struct) — multi-sig hint bags — `src/proving/hints.rs:129` / `:166`
- `bag_for_multisig` (fn) — extract hints from a partial proof — `src/proving/extract.rs:30`
- `WalletError` (enum) — one variant per failure class — `src/error.rs:10`

## Invariants & contracts
- **Secret-file format parity.** The `<uuid>.json` encrypted-secret file is
  byte-compatible with Scala `JsonSecretStorage`: PBKDF2-HMAC-SHA512 (default
  128,000 iters) → AES-256-GCM; ciphertext is the 64-byte BIP39 *seed* (not
  the phrase); `cipherParams` are enforced exactly on unlock
  (`src/storage.rs:394-417`). Filename = Java `UUID.nameUUIDFromBytes(cipherText)`
  (raw MD5 + version/variant patch), `src/storage.rs:98`.
- **Pre-1627 derivation bug fidelity.** `ExtendedSecretKeyLegacy` stores the
  child secret as *variable-length* unsigned bytes (leading zeros stripped,
  matching Java `BigIntegers.asUnsignedByteArray`); this leading-zero
  stripping is load-bearing for descendant HMAC inputs and is intentionally
  reproduced for parity (`src/extended_key.rs:313-386`). Modern derivation
  left-pads to 32 bytes.
- **`usePre1627KeyDerivation` defaults to `true` when missing.** Legacy
  Scala secret files predate the field; defaulting to `true` is the only safe
  restore path (`src/storage.rs:74-84`).
- **BIP32 retry is class-preserving (post-1627).** On `I_L >= n` or child
  scalar 0, derivation advances within the same hardened/non-hardened class
  so the HMAC input shape never silently flips (`next_index_same_class`,
  `src/extended_key.rs:157`). Legacy path advances raw `idx + 1` to match the
  pre-fix Scala behavior.
- **P2PK address shape.** Addresses go through `encode_p2pk_from_pubkey`, NOT
  `build_prove_dlog_ergo_tree` (which emits a segregated-constants tree that
  would silently encode as unspendable P2S); pubkeys are validated as on-curve
  SEC1 points first (`src/address.rs:8-35`).
- **Sigma-proof wire parity.** `prove_sigma` builds, Fiat-Shamir-hashes, and
  serializes the proof in the exact depth-first order
  `ergo_sigma::verify::verify_sigma_proof` reads, and self-verifies before
  returning (`SelfVerifyFailed` otherwise) — a produced proof must survive the
  verifier unmodified (`src/proving/sigma/mod.rs`). Threshold challenges use
  Lagrange interpolation over GF(2^192).
- **Script gate at signing.** `Prover::sign` rejects any input whose ErgoTree
  is not bare ProveDlog/ProveDHTuple or a matured miner-reward wrapper, because
  context-sensitive scripts could self-verify against the synthetic pre-header
  yet fail the chain's real context (`src/proving/prover.rs:90-106`). Cost
  enforcement is NOT done here — the bridge self-verify is authoritative.
- **Secret-material hygiene.** Master keys, leaf scalars, derived AES keys,
  and commitment randomness `r` are `Zeroize`/`ZeroizeOnDrop`; `Debug` impls
  on `ExtendedSecretKey*`, `UnlockedSecret`, and `OwnCommitment` redact the
  bytes so secrets never reach a log line. `WalletError` never embeds key
  material.
- **No `sigma-rust` at runtime.** Crypto is `k256` + `hmac-sha512` + `bip39`
  + `gf2_192`; sigma-rust is dev/test oracle only.

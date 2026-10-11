# ergo-wallet

**Purpose:** Portable wallet cryptography, pure box selection and transaction
construction. Owns mnemonics, HD keys, P2PK addresses, sigma proving and hint bags.
Filesystem keystore support and the CLI are opt-in features. Orchestration,
persistence and scans live in `ergo-wallet-service`; wire DTOs live in
`ergo-wallet-protocol`.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-sigma,
ergo-chain-spec, gf2_192. No validation/state/node/runtime dependency.
**Depended on by:** (see codemap index)

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
  AES-256-GCM `encrypt`/`decrypt`; owned keys and decrypted plaintext use
  `Zeroizing` (ciphertext and caller-owned inputs do not).
- `src/storage.rs` — encrypted-secret-file format (`EncryptedSecret`,
  `CipherParams`, `uuid_from_ciphertext`), `SecretStorage` lock/unlock
  state machine (requires `keystore`).
- `src/master.rs` — portable zeroized `UnlockedMaster`/`UnlockedSecret`,
  available without filesystem support. Storage compatibility reexports retain
  the existing import paths when `keystore` is enabled.
- `src/tx_context.rs` — `BlockchainStateContext`, `BlockchainParameters`,
  `ReductionContextOwned`: per-input evaluation context for `Prover::sign`.
  Candidate pre-header types come from `ergo-ser` without a validation dependency.
- `src/box_selector/`, `src/tx_builder.rs` — pure selection/building, including
  explicit mint/burn requests and the shared EIP-27 obligation arithmetic.
- `src/proving/` — sigma proving subsystem (see below).
- `src/proving/sigma/` — compound-proof composition: `build` (phase 1 tree
  walk), `finalize` (challenge propagation + GF(2^192) threshold), `serialize`
  (verifier-order proof bytes), `fiat_shamir`, `crypto`, `tree`, `hints`.
- `src/bin/ergo-wallet.rs` — CLI: `generate`/`import`/`derive`/`pubkey`/
  `address`.

### `src/proving/` submodules
- `prover.rs` — `Prover::sign` tx-level orchestrator and script gate;
  `sign_bound` consumes native transaction-bound commitment hints.
- `secrets.rs` — `SecretRegistry`: `ProveDlog(pk) → Scalar` / DHT lookup;
  zeroized storage.
- `external.rs` — `ProverExternalSecret`: decoded external secret for the
  locked-wallet signing path.
- `hints.rs` — `Hint`/`HintsBag`/`TransactionHintsBag`, `FirstProverMessage`
  (multi-sig commitment/proof exchange types), and `BoundTransactionHints`
  for a consumed, transaction-bound native commitment round.
- `node_position.rs` — `NodePosition`: depth-first tree addressing for hints.
- `randomness.rs` — `ProvingRng` abstraction (OsRng + deterministic test RNG).
- `schnorr.rs` — `prove_schnorr` (ProveDlog leaf proof).
- `dht.rs` — `prove_dht` (ProveDHTuple leaf proof).
- `commitments.rs` — `generate_commitments_for` (multi-sig commitment round).
- `extract.rs` — `bag_for_multisig` (hint extraction from a partial proof).

The orchestration and persistence module map is in
[`ergo-wallet-service`](./ergo-wallet-service.md).

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
- **Secret-file format parity.** The `<uuid>.json` encrypted-secret file is
  interoperable with Scala `JsonSecretStorage`: PBKDF2-HMAC-SHA512 (default
  128,000 iters) → AES-256-GCM over the 64-byte BIP39 seed. Scala names the
  first 16 bytes of the encrypted stream `authTag` and the rest `cipherText`;
  these names do not describe the cryptographic GCM components. Imports also
  authenticate the conventional field layout written by earlier Rust versions.
  Filename = Java `UUID.nameUUIDFromBytes(cipherText)` (raw MD5 plus
  version/variant patch). Fresh Scala 6.0.6 fixtures and the reverse JVM unlock
  gate are documented in [the fixture provenance](../../test-vectors/wallet/README.md).
- **Secret-file publication.** Creation writes a same-directory temporary file
  (owner-only on Unix), synchronizes it, publishes without replacing an existing
  wallet, synchronizes the published file and (on Unix) the directory, then
  updates cached metadata. Newly created directories and their parent entries
  also receive Unix sync barriers; new directories are owner-only. An
  interrupted write cannot expose a partial final
  file. Pending files are ignored on discovery. A directory-sync failure can
  leave a complete published file; reopening recovers it. Windows has no
  portable directory-sync step, so sudden-power-loss durability of the name
  is not promised there.
- **Pre-1627 derivation bug fidelity.** `ExtendedSecretKeyLegacy` stores the
  child secret as *variable-length* unsigned bytes (leading zeros stripped,
  matching Java `BigIntegers.asUnsignedByteArray`); this leading-zero
  stripping is load-bearing for descendant HMAC inputs and is intentionally
  reproduced for parity (`src/extended_key.rs:313-386`). Modern derivation
  left-pads to 32 bytes.
- **`usePre1627KeyDerivation` defaults to `true` when missing or null.** Legacy
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
- **Script gate at signing.** `Prover::sign` retains its existing support for
  bare ProveDlog/ProveDHTuple and canonical matured miner-reward wrappers.
  Context-sensitive scripts remain gated because the candidate pre-header can
  be synthetic. The prover records reduction costs; the service's self-verify
  applies authoritative chain cost limits before returning signed bytes.
  Full contract signing and reduced transaction interchange are deferred to
  [#612](https://github.com/arkadianet/ergo/issues/612), after Phase 3 merges.
- **Portable capability boundary.** Defaults enable no host features. `keystore`
  adds file storage and md5/uuid/tempfile; `cli` adds keystore plus clap/rpassword.
  Existing node, state, service and daemon consumers opt into keystore explicitly.
  `scripts/check-wallet-portable.py` checks the normal dependency graph; CI checks
  core libraries on aarch64/x86_64 Android without an NDK link.
- **Change-address ownership.** The persisted change address must be owned by
  the active master key: both the unlock-time boot check and the node's
  update path re-derive the recorded path and reject a mismatch
  (`ChangeAddressUntracked`), so the wallet never signs for an address it
  cannot prove possession of (`ergo-wallet-service/src/engine/admin.rs`,
  `ergo-wallet-service/src/engine/keys.rs`).
- **Secret-material ownership.** The BIP39 mnemonic, generated entropy and
  seed, master keys, registry secrets, owned real proof-tree scalars/nonces,
  AES-derived keys, decrypted plaintext and owned commitment randomness have
  drop-time zeroization. Secret type `Debug` implementations redact bytes.
  This is a guarantee about those owned buffers, not all copies: library
  internals, temporary scalar values, registers, swap and process dumps are
  outside it. Exported phrases and compatibility JSON hint DTOs are plain
  caller-owned strings/bytes; the caller must protect and erase them.
- **Commitment nonce ownership.** Native callers can use
  `generate_bound_commitments_for_tx` with `Prover::sign_bound`: secret hints
  are private, the wrapper cannot be cloned, signing consumes it and rejects
  a different canonical signing message. Public commitments are shareable.
  The Scala-compatible low-level hint bags and JSON interface remain reusable
  by design; callers must never reuse a private commitment nonce for another
  message. Zeroization alone does not enforce that protocol rule.
- **No `sigma-rust` at runtime.** Crypto is `k256` + `hmac-sha512` + `bip39`
  + `gf2_192`; sigma-rust is dev/test oracle only.

Modern master construction is `ExtendedSecretKey::derive_master_key(seed)`;
legacy construction is `ExtendedSecretKeyLegacy::derive_master_key(seed)`.
Master bytes stay32wide in both modes, while legacy children remain variable
length. Unlock binds the master to the persisted keys
(`SecretStorage::bind_tracked_keys`): a legacy wallet whose keys all come from
the earlier Rust trimmed master keeps that derivation, and any other mismatch
refuses the unlock. See `test-vectors/wallet/leading-zero-master/README.md` for
independent Scala vectors and recovery of earlier Rust master trimming.

# ergo-crypto

**Purpose:** Chain-aware cryptographic consensus primitives one layer above
`ergo-primitives`/`ergo-ser`: Autolykos v1/v2 proof-of-work verification,
difficulty-adjustment math (pre-EIP-37, EIP-37, v2-activation), and
Blake2b256 Merkle trees matching the scorex layout. No script interpreter,
no AVL+ state, no wire codecs — those live elsewhere.

**Depends on (workspace):** ergo-primitives, ergo-ser, ergo-chain-spec
**Depended on by:** (see codemap index) — ergo-sigma, ergo-validation, ergo-state, ergo-sync, ergo-mining, ergo-node
**Approx LOC:** ~1,950 (src) + ~1,150 (tests)

## Start here
- `src/pow.rs` — the public façade; `verify_pow_solution` and `verify_header_difficulty` are the two header-verification entry points the rest of the node calls.
- `src/autolykos/common.rs` — shared PoW machinery: the `M_BYTES` table, `calc_n` (height-dependent table size), `gen_indexes`/`gen_indexes_k`, and the local `blake2b256` helper.
- `src/difficulty.rs` — retarget math; `next_n_bits` (mining-side) and `verify_nbits` (verify-side) both wrap `required_difficulty_checked`.
- `src/merkle/mod.rs` — `merkle_tree_root`, `transactions_root`, `extension_root`, plus per-leaf and batch inclusion proofs.

## Modules
- `src/lib.rs` — crate root; declares the four public modules (`autolykos`, `difficulty`, `merkle`, `pow`) with the module map in doc comments.
- `src/pow.rs` — header-level PoW + difficulty verification entry points; owns `PowError` and `DifficultyError`. Dispatches v1/v2 by solution variant.
- `src/autolykos/mod.rs` — namespace for the two PoW versions and their shared helpers.
- `src/autolykos/common.rs` — version-shared pieces: `M_BYTES`, `AUTOLYKOS_*` constants, `calc_n`, `gen_indexes`/`gen_indexes_k`, `to_big_int`, `biguint_to_32bytes`, `blake2b256`.
- `src/autolykos/v1.rs` — Autolykos v1: secp256k1 EC equation `w^f == g^d * pk`, the `hashModQ` rejection-sampling hash, and the secp256k1 group order.
- `src/autolykos/v2.rs` — Autolykos v2: memory-hard Blake2b-only hit computation (`hit_for_v2`, general `hit_for_v2_pow`) and the `check_pow_v2` target comparison.
- `src/difficulty.rs` — chain-aware retarget: epoch-length selection, predictive linear interpolation (`calculate`), EIP-37 predictive∪classic with ±50% cap (`eip37_calculate`), v2-activation special case, `get_target`, `next_n_bits`, `verify_nbits`. Re-exports `DifficultyParams` from `ergo-chain-spec`.
- `src/merkle/mod.rs` — scorex-layout Blake2b256 Merkle trees: roots, single-leaf proofs (`MerkleProofRaw`), batch multiproofs (`merkle_proof_by_indices` → `IndexedBatchProof`), and verification.
- `tests/` — mainnet/sigmastate oracle parity: `pow_mainnet.rs` (~9k-header corpus), `difficulty_mainnet.rs`, `merkle_mainnet.rs`, `merkle_proof_for_tx_oracle.rs`.

## Key types, traits & functions
- `verify_pow_solution` (fn) — verify Autolykos solution against the header's own nBits target; dispatches v1/v2 by `header.solution` variant — `src/pow.rs:41`
- `verify_header_difficulty` (fn) — verify a header's nBits matches the value derived from ancestor epoch headers — `src/pow.rs:108`
- `PowError` (enum) — `InvalidSolution` / `HeaderEncode`; the PoW-equation failure surface — `src/pow.rs:13`
- `DifficultyError` (enum) — `NbitsMismatch` / `HeightMismatch` / `MissingEpochHeaders` — `src/pow.rs:71`
- `calc_n` (fn) — height+version → Autolykos table size N (v1 = NBase; v2 grows 5% per period from height 614,400, capped at 4,198,400) — `src/autolykos/common.rs:49`
- `gen_indexes` / `gen_indexes_k` (fn) — k indices in `[0, N)` from a seed via the 35-byte extended hash and a sliding 4-byte window — `src/autolykos/common.rs:80` / `:92`
- `M_BYTES` (const) — 8192-byte `(0..1024)` big-endian table; const-evaluated — `src/autolykos/common.rs:27`
- `check_pow_v1` (fn) — full v1 EC-equation check (`d < target`, valid non-identity points, `w^f == g^d·pk`) — `src/autolykos/v1.rs:92`
- `secp256k1_order` / `hash_mod_q` (fn) — group order q and the rejection-sampling mod-q hash — `src/autolykos/v1.rs:12` / `:24`
- `hit_for_v2` / `hit_for_v2_pow` (fn) — v2 memory-hard hit; the general form backs `SGlobal.powHit` in ergo-sigma — `src/autolykos/v2.rs:12` / `:30`
- `check_pow_v2` (fn) — `hit < target` after `calc_n` — `src/autolykos/v2.rs:97`
- `DifficultyParams` (struct, re-export) — network difficulty config (epoch lengths, EIP-37/v2 activation, initial difficulty, interval) — re-exported `src/difficulty.rs:8`
- `get_target` (fn) — `b = q / decode_compact_bits(nBits)` — `src/difficulty.rs:21`
- `next_n_bits` (fn) — encoded nBits a candidate at `child_height` must use (mining side) — `src/difficulty.rs:328`
- `required_difficulty_checked` (fn, pub(crate)) — the retarget core: branches non-recalc / pre-EIP-37 / EIP-37 / v2-activation; enforces height + window preconditions — `src/difficulty.rs:258`
- `is_recalculation_height` / `epoch_length_for_height` (fn) — epoch-boundary + EIP-37 epoch-length selection (uses the child's regime) — `src/difficulty.rs:47` / `:34`
- `merkle_tree_root` (fn) — scorex root: leaf prefix `0x00`, internal `0x01`, odd nodes paired with `EmptyNode = []`; empty input → `Blake2b256([])` — `src/merkle/mod.rs:36`
- `transactions_root` (fn) — block transactionsRoot: tx IDs only (v1) or tx IDs ++ witness IDs (v2+) — `src/merkle/mod.rs:105`
- `extension_root` (fn) — extension KV root with leaf `[key.len() as u8] ++ key ++ value` — `src/merkle/mod.rs:348`
- `MerkleProofRaw` (struct) + `merkle_proof_by_index` / `merkle_proof_verify` (fn) — single-leaf inclusion proof, build + verify — `src/merkle/mod.rs:125` / `:154` / `:328`
- `BatchProofEntry` / `IndexedBatchProof` (struct/type alias) + `merkle_proof_by_indices` (fn) — compact multi-leaf proof, in-memory form pairing with `ergo_ser::batch_merkle_proof::BatchMerkleProof` — `src/merkle/mod.rs:212` / `:231` / `:255`

## Invariants & contracts
- **PoW equation parity is byte-exact with Scala.** v1 EC equation and v2 hit pipeline match `AutolykosPowScheme`; pinned by the mainnet corpus (`tests/pow_mainnet.rs`) and the sigmastate v6.0.2 `powHit` KAT (`src/autolykos/v2.rs` tests).
- **No version-by-height enforcement in `verify_pow_solution`.** Dispatch is purely on the solution variant (coupled to `header.version` at parse time), mirroring Scala which has no version-vs-height check — rejecting more would be the chain-split direction (`src/pow.rs:36-40`, oracle test at `src/pow.rs:173`).
- **Autolykos N growth is Scala-faithful integer math.** `calc_n` uses `n = n / 100 * 105` per period (not `n * 105 / 100`); v1 always returns NBase (`src/autolykos/common.rs:49-64`).
- **`gen_indexes_k` is the k-prefix of k=32 `gen_indexes`** for all `2 <= k <= 32` (shared 35-byte extended hash + sliding window); the 32-index path anchors the smaller-k powHit path.
- **secp256k1 order q is pinned** to the SEC2/Bitcoin-Core constant; guards BigUint construction drift (`src/autolykos/v1.rs:162` test).
- **Difficulty retarget matches Scala `DifficultyAdjustment`**: USE_LAST_EPOCHS=8, PRECISION=1e9, signed-BigInt least-squares interpolation; EIP-37 = average(classic, ±50%-capped predictive), capped again at ±50%.
- **v2-activation special case returns fixed initial difficulty** when parent IS or precedes the v2-activation block; networks with no v1→v2 hardfork carry `v2_activation = None` and skip it (`src/difficulty.rs:280-284`).
- **Difficulty math returns structured errors, never panics on caller misuse.** Empty/undersized epoch windows and height mismatches surface as `DifficultyError` (the EIP-37 ≥2-header precondition is intercepted before the inner `debug_assert!`).
- **Merkle layout matches scorex**: leaf = `Blake2b256(0x00 ++ data)`, internal = `Blake2b256(0x01 ++ left ++ right)`, odd-trailing node paired with `EmptyNode` (hash `[]`), empty tree = `Blake2b256([])` (the `Algos.emptyMerkleTreeRoot` special case, not a prefixed empty leaf).
- **Proofs and roots come from one reduction.** `merkle_proof_by_index` and `merkle_tree_root` share `build_levels`; empty siblings are synthesized at proof time from out-of-range lookups, never materialized as phantom nodes — every honest leaf is provable (proptest at `src/merkle/mod.rs:548`).

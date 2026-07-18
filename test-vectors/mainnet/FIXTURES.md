# Curated mainnet fixtures — what each is for

The committed `test-vectors/mainnet/` set is **curated for key uses**: each fixture
covers a distinct *type* (tx/script shape) or *transition* (EIP, epoch, version
bump), NOT long runs of near-identical contiguous blocks. Deep contiguous
validation (cumulative state-root correctness over a long real chain) lives in the
**streamed replay driver** (`ergo-difftest --bin replay`, §Replay below), not in
committed CI fixtures.

Before committing a new large fixture, add a row here + justify it against this
principle; before deleting one, check it here.

## Design principle (2026-07-03)
Committed fixtures were essential for *initial* Scala-parity bring-up. For a mature
node, per-commit CI needs **representative** coverage — one exemplar per tx/script
type + one per transition — which is small and hermetic. The bulk contiguous
ranges tested cumulative state accumulation; that unique coverage now runs against
the **live chain** via the replay driver (pinned by hash in `replay-pins.json`),
reproducibly and far deeper (to tip), as a scheduled/pre-release job.

## Retired ranges → now covered by the replay driver
| retired file(s) | size | old CI test | now covered by |
|-----------------|------|-------------|----------------|
| `transactions_1_10000` + `headers_1_10000` + `utxo_digests_1_10000` | 27 MB | `chain_validate_1_10000` (deleted) | `replay --from 1 --to 10000` (cumulative state root per height); short-seed sanity stays in `chain_validate_1_1000` |
| `transactions_1761000_1762000` + `input_boxes_…` + `headers_…` | 51 MB | `recent_block_validation` (deleted) | `replay` over the modern range; EIP-27 kept hermetic via `ergo-validation reemission.rs` (20 tests); EIP-37 boundary kept via the curated file below |

The 6 bulk files were extracted into the fuzz seed corpus first; the two deep tests
were removed (superseded by the replay driver + the retained short seed +
dedicated hermetic rule tests). Ignored diagnostics (`m7_mainnet_corpus`) now
skip-if-missing and re-run after re-extraction. Committed mainnet: 101 MB → 20 MB.

## Retired earlier — genuine dead weight, zero consumers
`input_boxes_205000_205200.json` (2.1 MB), `ergotrees_700000_700200.json` (0.6 MB),
`boxes_recent_range.json` (0.9 MB) — zero consumers anywhere.

## Curated transition fixtures (small, committed, CI-run)
| file | backs | transition covered |
|------|-------|--------------------|
| `headers_1761792_1761795_eip37_curated.json` (4 headers) | `difficulty.rs`, `header_validation.rs`, `header_sync_integration.rs` EIP-37 undersized-window tests + `decode_scala_header` v2+ roundtrip (`.take(3)`) | **EIP-37** difficulty recalculation boundary (h1761792 = 13764×128) |
| `blocks_844665_844680.json` (1.7 MB, parked `#[ignore]`) | `merkle_mainnet`, `full_block_validation` EIP-37-activation tests (need gitignored headers) | **EIP-37 activation** |
| `headers_eip37_curated.json`, `headers_v1v2_parity_curated.json`, `headers_v2_curated.json` | header decode/parity tests | v1→v2→v3 header **version bumps** |
| `block_836113.json` | `diagnose_block_836113` | a specific gnarly block |
| `blocks_1_5.json`, `blocks_700000_700010.json` | merkle-root, full-block, auction, multi-tx-ordering | genesis-era + 700k-era block shapes |
| `voted_params_softfork_blobs.json` | voting/softfork param decode | **soft-fork** param transitions |

## Curated type fixtures (script/proof/tx shapes) — count-pinned CI corpora
| file | backs | type covered |
|------|-------|--------------|
| `mining_reward_proofs_700000.json` | `mining_reward_all_352_verified` (+neg) | mining-reward script proofs |
| `emission_contract_700000.json` | `emission_contract_all_895_verified`, `traced_untraced_parity` | emission contract eval |
| `dex_oracle_proofs_700000.json` | `dex_oracle_all_134_verified` | DEX/oracle scripts |
| `treasury_contract_700000.json` | `treasury_contract_all_201_verified` | treasury script |
| `schnorr_proofs_700000.json` | schnorr/spending/sigma-composition | P2PK + sigma proofs |
| `transactions_205000_205200.json`, `transactions_1_200.json` | `api_bridge` byte-parity, scala-parity, indexer backfill | mid-era + genesis tx shapes |
| `boxes_recent.json`, `genesis_boxes.json`, `fee_proposition.hex` | box decode, genesis, storage-rent fee prop | box/register shapes |
| `storage_rent_reemission_deadlock.json` | `storage_rent_reemission_oracle` (ergo-mining) | storage-rent × EIP-27 deadlock: real rent-eligible reward box w/ re-emission tokens; both claim shapes + live-Scala `/transactions/check` rejection verdicts |

## Retained contiguous seeds (short, hermetic CI cumulative-state sanity)
`transactions_1_1000` + `utxo_digests_1_1000` + `headers_1_2000` (`chain_validate_1_1000`,
`digest_chain_1_1000`); `transactions_1_200` + `utxo_digests_1_200` + `headers_1_500`
(`digest_chain_1_200`, backfill, header contiguity). These give per-commit CI a
short real-chain cumulative-state check without a live node.

## Replay driver — the deep-coverage mechanism
`ergo-difftest --bin replay --from 1 --to <N> --node <url>` pulls blocks from a live
Scala node, applies each in-process, and diffs `root_digest()` vs the committed
`stateRoot`, verifying covered heights by hash against `ergo-difftest/replay-pins.json`.
It reproduces (and deepens, to tip) the retired contiguous coverage. It needs a
live `:9053` node so it runs as a **scheduled / pre-release / `workflow_dispatch`**
job (`.github/workflows/fuzz.yml` → `replay` job, gated on a `NODE_URL` secret),
NOT per-commit CI.

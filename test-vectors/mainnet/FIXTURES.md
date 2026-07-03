# Curated mainnet fixtures — what each is for

This is the **curated keep-list**: every committed `test-vectors/mainnet/` fixture
mapped to the CI-run test that needs it and why it can't be smaller. It exists so
(a) contributors know what each fixture backs, and (b) dead weight can't silently
re-accumulate. Before committing a new large fixture, add a row here; before
deleting one, check it here.

**Finding that shaped this list:** the committed ranges are NOT redundant bloat.
Each large file backs a *distinct* CI-run key test with **exact count assertions**,
so they can't share a smaller sibling without losing unique coverage. The streamed
replay driver (`ergo-difftest --bin replay`, pinned by hash in `replay-pins.json`)
*adds* reproducible deep coverage but **cannot run in CI** (needs a live `:9053`
node), so these committed fixtures ARE the CI hermetic coverage — retiring them is
a real coverage loss, not free cleanup.

## Retired (2026-07-03) — genuine dead weight, zero consumers

| file | size | why retired |
|------|------|-------------|
| `input_boxes_205000_205200.json` | 2.1 MB | zero consumers in any `.rs`/`.toml`/`.sh`/`.md` |
| `ergotrees_700000_700200.json` | 0.6 MB | zero consumers anywhere |
| `boxes_recent_range.json` | 0.9 MB | zero consumers (distinct from `boxes_recent.json`, which IS used) |

Total: ~3.6 MB removed with zero coverage loss (101 MB → 97 MB committed mainnet).

## Keep-list — each backs a CI-run key test (cannot shrink without losing coverage)

### Long-range state-root parity (the 10k trio)
| file | size | key test | why full size |
|------|------|----------|---------------|
| `transactions_1_10000.json` | 15 MB | `ergo-state chain_validate_1_10000` | exact assertion `validated_txs == 10_404`; first multi-tx block is at **height 3355** — a 1-1000 sibling has ZERO multi-tx blocks, so this coverage is unique |
| `headers_1_10000.json` | 10 MB | same | PoW + difficulty + parent-linkage + tx-root at every one of 10000 heights; 9 epoch boundaries |
| `utxo_digests_1_10000.json` | 1.1 MB | same | per-height expected AVL state root |

### Modern-era (post-EIP-37) block validation (the 1761k trio)
| file | size | key test | why full size |
|------|------|----------|---------------|
| `transactions_1761000_1762000.json` | 29 MB | `ergo-validation recent_block_validation` | script eval + EIP-27 re-emission over 7178 modern txs; assertion `multi_tx_blocks >= 500` (reached only at ~height 1761641) |
| `input_boxes_1761000_1762000.json` | 22 MB | same | all spent input boxes preloaded for the window |
| `headers_1761000_1762000.json` | 0.9 MB | same + 3 EIP-37 unit tests (`difficulty.rs`, `header_validation.rs`, `header_sync_integration.rs` use heights 1761792/1761793) + `decode_scala_header` v2 roundtrip (`.take(3)`) | height→miner_pk map for the full window |

### Sigma proof / contract corpora (700k era) — count-pinned
| file | size | key test | assertion |
|------|------|----------|-----------|
| `mining_reward_proofs_700000.json` | 4.1 MB | `ergo-sigma mining_reward_all_352_verified` | `len >= 352` |
| `emission_contract_700000.json` | 1.2 MB | `emission_contract_all_895_verified` + `traced_untraced_parity` | `len >= 895` |
| `dex_oracle_proofs_700000.json` | 0.7 MB | `dex_oracle_all_134_verified` | `len >= 134` |
| `treasury_contract_700000.json` | 0.6 MB | `treasury_contract_all_201_verified` | `len >= 201` |
| `schnorr_proofs_700000.json` | 0.5 MB | `schnorr_verify_mainnet_proofs`, `spending_proof_*`, `sigma_composition` | `len >= 50` (56 vectors) |

### Early-chain small siblings (used directly by CI tests — keep)
| file | key tests |
|------|-----------|
| `headers_1_2000.json` (2.1 MB) | `chain_validate_1_1000`, `digest_chain_1_1000`, `header_sync` epoch-boundary (h1025), 8+ merkle/popow/pow/difficulty unit tests (heights 1-5, 100, 105, 200, 1024) |
| `headers_1_500.json` | `header_validation contiguous_validation_1_500` (`len >= 500`), `backfill_corpus`, `bridge_type_invariants` |
| `transactions_1_1000.json`, `utxo_digests_1_1000.json` | `chain_validate_1_1000`, `digest_chain_1_1000` (`999 txs` exact) |
| `transactions_1_200.json`, `utxo_digests_1_200.json` | `digest_chain_1_200`, `backfill_corpus`, `api_bridge` byte-parity (min 300), `blockchain_scala_parity`, `mempool_overlay_oracle` (genesis tx) |
| `transactions_205000_205200.json` (1.5 MB) | `api_bridge b4_byte_parity` (combined ≥300 JSON↔bytes) |
| `transactions_1_10.json`, `headers_1_10.json`, `transactions_700000.json` | tiny CI roundtrip/decode fixtures |
| `blocks_1_5.json`, `blocks_700000_700010.json` | merkle-root, full-block, auction-divergence, multi-tx-ordering |
| `boxes_recent.json`, `genesis_boxes.json`, `fee_proposition.hex`, `block_836113.json`, curated headers (`eip37`/`v1v2`/`v2`), `voted_params_softfork_blobs.json`, `nipopow_proof_capture.bin`, `scala_*` | targeted single-purpose consensus vectors |

### Parked (kept) — real key use, currently `#[ignore]`'d on missing gitignored headers
| file | size | why kept |
|------|------|----------|
| `blocks_844665_844680.json` | 1.7 MB | backs the **EIP-37 difficulty-hardfork activation** tests (`merkle_mainnet extension_root_*`, `full_block_validation validate_full_block_eip37_activation`); ignored only because it needs gitignored `headers_843000_*`/`headers_844673_*` — a genuine consensus-event vector, not dead weight |

## Optional further downsizing (NOT done — requires test changes + a coverage trade)
These recover more MB but cost real CI coverage and need code edits + fixture
regeneration; left for an explicit decision rather than taken silently:
- **`mining_reward_proofs_700000.json`** 4.1 MB → ~0.6 MB by truncating to 50
  vectors + relaxing `>= 352` to `>= 50` (loses 302 real mainnet proof checks).
- **1761k trio** 51 MB → ~33 MB by slicing to the first ~650 blocks + relaxing
  `multi_tx_blocks >= 500` to `>= 250` (loses ~350 modern blocks of eval coverage).

Recommendation: keep both at full size — the proof/eval coverage is worth more
than the megabytes, and the streamed replay driver already provides the deep
end of the coverage spectrum reproducibly.

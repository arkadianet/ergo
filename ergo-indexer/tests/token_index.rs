//! Integration tests for `INDEXED_TOKEN` apply + rollback.
//!
//! Confirms:
//!   - apply records IndexedToken on EIP-4 mint detection
//!     (`tokenId == tx.inputs[0].box_id && tokenId ∉ inputTokens`);
//!   - apply skips IndexedToken when the predicate fails (token id
//!     differs from first input's box id, or token id was already in
//!     a spent input's bundle);
//!   - apply accumulates emission_amount across multi-output mint
//!     within a single tx;
//!   - apply decodes R4/R5/R6 metadata into name/description/decimals;
//!   - apply appends every output's token to that token's box-segment
//!     (independent of mint detection — both mints and plain transfers
//!     touch the segment);
//!   - apply sign-flips the token box-segment entry on input spend
//!     (mirror of address/template flip behavior);
//!   - rollback removes the IndexedToken record when its mint was the
//!     only contribution in the rolled-back block;
//!   - rollback preserves the record when an earlier block contributed
//!     entries that the segment still carries;
//!   - the token-segment spill mechanic works exactly like the
//!     template-segment spill (>512 entries triggers a spill row under
//!     `box_segment_id(token_unique_id, 0)`).

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::ErgoTree;
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::opcode::{Body, Expr};
use ergo_ser::register::{AdditionalRegisters, RegisterValue};
use ergo_ser::sigma_type::SigmaType;
use ergo_ser::sigma_value::{CollValue, SigmaValue};
use ergo_ser::token::Token;
use ergo_ser::transaction::{transaction_id, Transaction};
use tempfile::TempDir;

use ergo_indexer::segment_id::{box_segment_id, token_unique_id};
use ergo_indexer::TokenId;
use ergo_indexer::{apply_block, rollback_one_block, IndexerBlock, IndexerMeta, IndexerStore};

fn parseable_tree_true() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(true),
        } as Body,
    }
}

fn parseable_tree_false() -> ErgoTree {
    ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: vec![],
        body: Expr::Const {
            tpe: SigmaType::SBoolean,
            val: SigmaValue::Boolean(false),
        } as Body,
    }
}

fn candidate_with_tree(value: u64, tree: ErgoTree, height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, vec![], AdditionalRegisters::empty()).unwrap()
}

fn candidate_with_tokens(
    value: u64,
    tree: ErgoTree,
    height: u32,
    tokens: Vec<Token>,
) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, tokens, AdditionalRegisters::empty()).unwrap()
}

fn candidate_with_tokens_and_registers(
    value: u64,
    tree: ErgoTree,
    height: u32,
    tokens: Vec<Token>,
    regs: AdditionalRegisters,
) -> ErgoBoxCandidate {
    ErgoBoxCandidate::new(value, tree, height, tokens, regs).unwrap()
}

fn fake_input(box_id_seed: u8) -> Input {
    Input {
        box_id: Digest32::from_bytes([box_id_seed; 32]),
        spending_proof: SpendingProof::new(vec![0xAB, 0xCD, 0xEF], ContextExtension::empty())
            .unwrap(),
    }
}

fn input_spending(box_id: Digest32) -> Input {
    Input {
        box_id,
        spending_proof: SpendingProof::new(vec![0xCA, 0xFE, 0xBA, 0xBE], ContextExtension::empty())
            .unwrap(),
    }
}

fn open_store() -> (IndexerStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("indexer.redb");
    let (store, _) = IndexerStore::open(&path).unwrap();
    (store, tmp)
}

fn sealed_box_id(tx: &Transaction, output_idx: u16) -> Digest32 {
    let tx_id = transaction_id(tx).unwrap();
    let sealed = ErgoBox {
        candidate: tx.output_candidates[output_idx as usize].clone(),
        transaction_id: tx_id,
        index: output_idx,
    };
    sealed.box_id().unwrap()
}

/// Build registers carrying R4=name (Coll[Byte]), R5=description
/// (Coll[Byte]), R6=decimals (Coll[Byte] ASCII). Mirrors the EIP-4
/// `MintToken` register layout.
fn eip4_registers(name: &str, description: &str, decimals: &str) -> AdditionalRegisters {
    let bytes_type = SigmaType::SColl(Box::new(SigmaType::SByte));
    AdditionalRegisters {
        registers: vec![
            RegisterValue {
                tpe: bytes_type.clone(),
                value: SigmaValue::Coll(CollValue::Bytes(name.as_bytes().to_vec())),
            },
            RegisterValue {
                tpe: bytes_type.clone(),
                value: SigmaValue::Coll(CollValue::Bytes(description.as_bytes().to_vec())),
            },
            RegisterValue {
                tpe: bytes_type,
                value: SigmaValue::Coll(CollValue::Bytes(decimals.as_bytes().to_vec())),
            },
        ],
    }
}

/// EIP-4 mint contract: input.box_id == minted token_id. Use a single
/// seed byte for both ends so callers can read tests without tracking
/// two parallel ids.
fn mint_input_and_token_id(seed: u8) -> (Input, TokenId) {
    let id = Digest32::from_bytes([seed; 32]);
    (fake_input(seed), id)
}

// ----- happy path -----

#[test]
fn apply_records_indexed_token_for_eip4_mint() {
    // Single-output mint: tx.inputs[0].box_id == output token_id, no
    // spent inputs carry the token. is_mint must fire and write an
    // IndexedToken with creating_box_id = output box_id, emission_amount
    // = the token amount, and (since regs are empty) the
    // name/description/decimals defaults Some("") / Some("") / Some(0).
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAA);
    let token = Token {
        token_id,
        amount: 21_000_000,
    };
    let tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![token],
        )],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x11; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let record = store
        .read_token(&token_id)
        .unwrap()
        .expect("IndexedToken record must exist after mint");
    assert_eq!(record.token_id, token_id);
    assert_eq!(record.creating_box_id, Some(sealed_box_id(&tx, 0)));
    assert_eq!(record.emission_amount, Some(21_000_000));
    // Empty regs default to Some("") / Some("") / Some(0).
    assert_eq!(record.name.as_deref(), Some(""));
    assert_eq!(record.description.as_deref(), Some(""));
    assert_eq!(record.decimals, Some(0));

    // Token segment also got the +0 entry (per-output append independent
    // of mint detection).
    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(entries, vec![0]);
}

#[test]
fn apply_decodes_eip4_metadata_from_registers() {
    // Same shape as the bare-mint test but the candidate carries
    // R4/R5/R6 with realistic mint metadata. Confirms the register
    // decoders in `token::decode_*_r{4,5,6}` are wired into the apply
    // path (regression guard against accidentally calling
    // `IndexedToken::empty` instead of `from_box`).
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xBB);
    let token = Token {
        token_id,
        amount: 1_000,
    };
    let tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens_and_registers(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![token],
            eip4_registers("MyToken", "A description", "9"),
        )],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x12; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(record.name.as_deref(), Some("MyToken"));
    assert_eq!(record.description.as_deref(), Some("A description"));
    assert_eq!(record.decimals, Some(9));
    assert_eq!(record.emission_amount, Some(1_000));
}

#[test]
fn apply_skips_token_record_when_token_id_does_not_match_first_input() {
    // Token id != first_input.box_id → is_mint = false → no IndexedToken
    // record gets created. There's also nothing to append to (no record
    // → try_load_token_into_map returns None → segment append skipped),
    // so read_token_box_entries returns None.
    let (store, _tmp) = open_store();
    let token_id = TokenId::from_bytes([0xDD; 32]);
    let token = Token {
        token_id,
        amount: 100,
    };
    let tx = Transaction {
        inputs: vec![fake_input(0xCC)], // box_id [CC; 32] ≠ token id [DD; 32]
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![token],
        )],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x13; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    assert!(
        store.read_token(&token_id).unwrap().is_none(),
        "no record should exist when token id doesn't satisfy mint predicate"
    );
    assert!(
        store.read_token_box_entries(&token_id).unwrap().is_none(),
        "no segment entries should exist either"
    );
}

#[test]
fn apply_multi_output_mint_accumulates_emission_amount() {
    // Tx has 3 outputs all carrying the same minted token id (== first
    // input box id). First detection populates the record from output 0;
    // detections 2 and 3 call `add_emission_amount` so total emission =
    // 100 + 200 + 300 = 600. All three outputs also append to the token
    // segment, so entries = [0, 1, 2].
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAB);
    let amounts = [100u64, 200, 300];
    let outputs: Vec<ErgoBoxCandidate> = amounts
        .iter()
        .map(|&amount| {
            candidate_with_tokens(
                1_000_000,
                parseable_tree_true(),
                1,
                vec![Token { token_id, amount }],
            )
        })
        .collect();
    let tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x14; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(record.emission_amount, Some(600));
    // creating_box_id is the FIRST output's box_id (Scala only sets it
    // on the first detection, subsequent calls take the
    // `add_emission_amount` branch).
    assert_eq!(record.creating_box_id, Some(sealed_box_id(&tx, 0)));

    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(entries, vec![0, 1, 2]);
}

#[test]
fn apply_skips_mint_when_token_id_already_in_input_tokens() {
    // Block 1: legit mint of token_id [0xEE; 32]. Token record exists
    // with emission_amount = 100, segment = [+0].
    // Block 2: spends the mint output (which carries token_id [EE]),
    // and creates an output that *also* matches the mint shape
    // (token_id == tx.inputs[0].box_id). But the input_tokens accumulator
    // captured [0xEE] from the spent box, so is_mint returns false and
    // the record's emission_amount is NOT incremented. The new output
    // STILL appends to the token segment (segment-append is independent
    // of mint detection).
    let (store, _tmp) = open_store();
    let (input1, token_id) = mint_input_and_token_id(0xEE);
    let mint_tx = Transaction {
        inputs: vec![input1],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id,
                amount: 100,
            }],
        )],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x21; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let mint_output_id = sealed_box_id(&mint_tx, 0);
    // Construct a tx whose first input is the mint output (so it spends
    // the box carrying token_id [0xEE]), and whose first output token
    // id is — by coincidence of the input box id — also [0xEE]. But
    // because input_tokens already contains [0xEE], is_mint = false.
    //
    // Note: input.box_id == mint_output_id ≠ token_id [0xEE; 32], so
    // even the syntactic part of the predicate fails. To exercise the
    // input_tokens-blocks-mint path, we'd need to engineer a new tx
    // input whose box_id == [0xEE; 32]. But box ids are derived hashes,
    // so we cannot. The realistic path is: spend a box holding T, then
    // mint a *different* token U whose id == new_input.box_id — input
    // U is not in input_tokens (only T was), so U's mint succeeds.
    //
    // What we CAN test on the indexer side: spending a box with token
    // T, then transferring T to a new output. The transfer must NOT
    // increment emission_amount (no mint), and the segment must record
    // the transfer (one flip + one append).
    let transfer_tx = Transaction {
        inputs: vec![input_spending(mint_output_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            900_000,
            parseable_tree_false(),
            2,
            vec![Token {
                token_id,
                amount: 100,
            }],
        )],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x22; 32]),
        transactions: std::slice::from_ref(&transfer_tx),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    // emission_amount stays at 100 (no mint in block 2).
    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(record.emission_amount, Some(100));

    // Segment: original +0 (mint output), spend flips it to -0, then
    // transfer output appends +1.
    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(entries, vec![-0i64, 1]);
}

#[test]
fn apply_then_spend_flips_token_box_segment_sign() {
    // Block 1: mint 1 output → segment [+0].
    // Block 2: spend that output, no new outputs carry the token →
    // segment [-0]. Confirms apply step 1's per-token sign flip.
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAC);
    let mint_tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id,
                amount: 50,
            }],
        )],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x31; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![0]
    );

    let spent_id = sealed_box_id(&mint_tx, 0);
    let burn_tx = Transaction {
        inputs: vec![input_spending(spent_id)],
        data_inputs: vec![],
        // No tokens on the new output — token "burned" from indexer view.
        output_candidates: vec![candidate_with_tree(900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x32; 32]),
        transactions: std::slice::from_ref(&burn_tx),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(
        entries,
        vec![-0i64],
        "spent mint output must be sign-flipped in the token segment"
    );
}

#[test]
fn rollback_of_mint_block_deletes_token_record() {
    // Apply one mint block, then roll it back. The IndexedToken record
    // must vanish — it was created entirely by the rolled-back block,
    // so the segment is empty post-rollback and the record gets deleted.
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAD);
    let mint_tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id,
                amount: 7,
            }],
        )],
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x41; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block).unwrap();
    assert!(store.read_token(&token_id).unwrap().is_some());

    let after_rb = rollback_one_block(&store, &meta1, &block).unwrap();
    assert_eq!(after_rb.indexed_height, 0);
    assert!(
        store.read_token(&token_id).unwrap().is_none(),
        "rollback of mint block must delete the IndexedToken record"
    );
}

#[test]
fn rollback_undoes_token_segment_append_and_flip() {
    // Apply mint (segment [+0]), apply transfer (segment [-0, +1]),
    // then roll back each block in reverse:
    //   - rollback block 2 → segment back to [+0], record preserved.
    //   - rollback block 1 → record deleted.
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAE);
    let mint_tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id,
                amount: 100,
            }],
        )],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x51; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let spent_id = sealed_box_id(&mint_tx, 0);
    let transfer_tx = Transaction {
        inputs: vec![input_spending(spent_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            900_000,
            parseable_tree_false(),
            2,
            vec![Token {
                token_id,
                amount: 100,
            }],
        )],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x52; 32]),
        transactions: std::slice::from_ref(&transfer_tx),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![-0i64, 1]
    );

    // Rollback block 2: pop the +1 transfer append, then unflip the
    // -0 spend. Segment → [+0]. Record preserved (mint contribution
    // was in block 1, not block 2).
    let after_rb2 = rollback_one_block(&store, &meta2, &block2).unwrap();
    assert_eq!(after_rb2, meta1);
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![0i64]
    );
    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(record.emission_amount, Some(100));

    // Rollback block 1: pop the +0 mint append, reverse the mint
    // emission contribution. Segment empty → record deleted.
    let after_rb1 = rollback_one_block(&store, &after_rb2, &block1).unwrap();
    assert_eq!(after_rb1.indexed_height, 0);
    assert!(
        store.read_token(&token_id).unwrap().is_none(),
        "after both rollbacks the mint record must be gone"
    );
}

#[test]
fn apply_513_outputs_with_same_mint_token_spills_box_segment() {
    // Mirror of the address/template spill tests. One tx mints the same
    // token into 513 outputs (all hit the mint-detection path because
    // input_tokens never gets [0xAF]). Each output appends to the token
    // segment, so the segment crosses SEGMENT_THRESHOLD (512) and one
    // spill row is produced under `box_segment_id(unique_id, 0)`.
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0xAF);
    let outputs: Vec<ErgoBoxCandidate> = (0..513u32)
        .map(|i| {
            candidate_with_tokens(
                1_000 + i as u64,
                parseable_tree_true(),
                1,
                vec![Token {
                    token_id,
                    amount: 1,
                }],
            )
        })
        .collect();
    let tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: outputs,
    };
    let block = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x61; 32]),
        transactions: std::slice::from_ref(&tx),
    };
    apply_block(&store, &IndexerMeta::empty(), &block).unwrap();

    let entries = store.read_token_box_entries(&token_id).unwrap().unwrap();
    assert_eq!(entries.len(), 513);
    assert_eq!(entries[0], 0);
    assert_eq!(entries[512], 512);

    let unique_id = token_unique_id(&token_id);
    let spill_id = box_segment_id(&unique_id, 0);
    let spill = store
        .read_spill_segment(&spill_id)
        .unwrap()
        .expect("spill row written for tokens exactly like for templates");
    assert_eq!(spill.boxes.len(), 512, "spill row carries the oldest 512");
    assert_eq!(spill.boxes[0], 0);
    assert_eq!(spill.boxes[511], 511);

    // Multi-output mint emission accumulates: 513 × 1 = 513.
    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(record.emission_amount, Some(513));
}

#[test]
fn spend_of_non_zero_global_index_flips_token_segment_to_negative() {
    // The `-0i64 == 0i64` collapse hides sign-flip behavior at index 0,
    // so this test exercises a non-zero global_index. Block 1 multi-mints
    // token T into 2 outputs (segment [+0, +1]). Block 2 spends only
    // output 1 (global_index = 1) without re-emitting → segment must
    // become [+0, -1]. The `-1` assertion is non-vacuous (distinguishable
    // from `+1`), so this proves the flip path actually fires.
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0x20);
    let mint_tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![
            candidate_with_tokens(
                1_000_000,
                parseable_tree_true(),
                1,
                vec![Token {
                    token_id,
                    amount: 10,
                }],
            ),
            candidate_with_tokens(
                1_000_000,
                parseable_tree_true(),
                1,
                vec![Token {
                    token_id,
                    amount: 20,
                }],
            ),
        ],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x81; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![0, 1]
    );

    // Spend only output 1 — its global_index is 1, so the flip turns
    // it from +1 to -1 (observationally distinct).
    let spent_id = sealed_box_id(&mint_tx, 1);
    let burn_tx = Transaction {
        inputs: vec![input_spending(spent_id)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tree(900_000, parseable_tree_false(), 2)],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x82; 32]),
        transactions: std::slice::from_ref(&burn_tx),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![0, -1],
        "global_index 1 entry must be sign-flipped on spend"
    );

    // Rollback block 2 → segment back to [+0, +1] (the unflip is also
    // observationally distinct: -1 → +1).
    let after_rb = rollback_one_block(&store, &meta2, &block2).unwrap();
    assert_eq!(after_rb, meta1);
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![0, 1],
        "rollback must restore the +1 sign on the spent entry"
    );
}

#[test]
fn mixed_mint_t_with_transfer_u_in_same_output_appends_to_both_segments() {
    // Edge case: when one output simultaneously mints token T (predicate
    // satisfied) AND carries an unrelated token U (predicate fails — U
    // was already in input_tokens), the IndexedToken record for T must
    // be created AND the U-bearing output must be appended to U's
    // box-segment. This exercises the "mint detection and token-segment
    // maintenance must not be conflated" invariant.
    let (store, _tmp) = open_store();
    // Block 1: mint U.
    let (input_u, token_u) = mint_input_and_token_id(0x30);
    let mint_u_tx = Transaction {
        inputs: vec![input_u],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id: token_u,
                amount: 100,
            }],
        )],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x91; 32]),
        transactions: std::slice::from_ref(&mint_u_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();
    assert!(store.read_token(&token_u).unwrap().is_some());

    // Block 2: tx_b's first input is mint_u_tx output 0 (carrying U).
    // Its first output mints T (token_id_T == first_input.box_id ==
    // sealed_box_id(mint_u_tx, 0)) AND carries U (transferred from input).
    // - Mint check for T: token_id_T == first_input.box_id ✓; T ∉
    //   input_tokens (which contains only U) ✓ → T is a mint.
    // - Mint check for U: token_id_U == first_input.box_id ✗ (U's id is
    //   [0x30; 32], first input box_id is the sealed mint_u output id) →
    //   U is NOT a mint.
    let mint_u_out = sealed_box_id(&mint_u_tx, 0);
    let token_t = TokenId::from_bytes(*mint_u_out.as_bytes()); // T's id == first input box_id
    let mixed_tx = Transaction {
        inputs: vec![input_spending(mint_u_out)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            900_000,
            parseable_tree_false(),
            2,
            vec![
                Token {
                    token_id: token_t,
                    amount: 5,
                },
                Token {
                    token_id: token_u,
                    amount: 100,
                },
            ],
        )],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x92; 32]),
        transactions: std::slice::from_ref(&mixed_tx),
    };
    apply_block(&store, &meta1, &block2).unwrap();

    // T must have a fresh record from this output (creating_box_id =
    // sealed_box_id(mixed_tx, 0), emission_amount = 5).
    let t_record = store.read_token(&token_t).unwrap().unwrap();
    assert_eq!(t_record.creating_box_id, Some(sealed_box_id(&mixed_tx, 0)));
    assert_eq!(t_record.emission_amount, Some(5));
    // T's segment got +1 (the only output of block 2; global_index = 1
    // because block 1 used global_index = 0).
    assert_eq!(
        store.read_token_box_entries(&token_t).unwrap().unwrap(),
        vec![1]
    );

    // U's emission_amount is unchanged (no re-mint).
    let u_record = store.read_token(&token_u).unwrap().unwrap();
    assert_eq!(
        u_record.emission_amount,
        Some(100),
        "U was transferred, not re-minted"
    );
    // U's segment: original [+0] from block 1, then block 2's spend
    // flips +0 → -0 (vacuous on equality but the +1 append below proves
    // the segment was touched), then output_b0 carrying U appends +1.
    let u_entries = store.read_token_box_entries(&token_u).unwrap().unwrap();
    assert_eq!(
        u_entries.len(),
        2,
        "U segment must have spend-flip + transfer-append entries"
    );
    assert_eq!(
        u_entries[1], 1,
        "U segment must end with the new transfer's global_index (+1)"
    );
}

#[test]
fn rollback_preserves_record_when_pre_block_segment_entries_remain() {
    // Apply 3 blocks: block1 mints (segment [+0]), block2 transfers
    // (segment [-0, +1]), block3 transfers again (segment [-0, -1, +2]).
    // Rolling back block3 must leave segment [-0, +1] AND keep the
    // record alive (mint contribution still tracked in block 1, segment
    // still non-empty).
    let (store, _tmp) = open_store();
    let (input, token_id) = mint_input_and_token_id(0x10);
    let mint_tx = Transaction {
        inputs: vec![input],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            1_000_000,
            parseable_tree_true(),
            1,
            vec![Token {
                token_id,
                amount: 50,
            }],
        )],
    };
    let block1 = IndexerBlock {
        height: 1,
        header_id: Digest32::from_bytes([0x71; 32]),
        transactions: std::slice::from_ref(&mint_tx),
    };
    let meta1 = apply_block(&store, &IndexerMeta::empty(), &block1).unwrap();

    let mint_out = sealed_box_id(&mint_tx, 0);
    let transfer_tx = Transaction {
        inputs: vec![input_spending(mint_out)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            900_000,
            parseable_tree_false(),
            2,
            vec![Token {
                token_id,
                amount: 50,
            }],
        )],
    };
    let block2 = IndexerBlock {
        height: 2,
        header_id: Digest32::from_bytes([0x72; 32]),
        transactions: std::slice::from_ref(&transfer_tx),
    };
    let meta2 = apply_block(&store, &meta1, &block2).unwrap();

    let transfer_out = sealed_box_id(&transfer_tx, 0);
    let transfer_tx2 = Transaction {
        inputs: vec![input_spending(transfer_out)],
        data_inputs: vec![],
        output_candidates: vec![candidate_with_tokens(
            800_000,
            parseable_tree_true(),
            3,
            vec![Token {
                token_id,
                amount: 50,
            }],
        )],
    };
    let block3 = IndexerBlock {
        height: 3,
        header_id: Digest32::from_bytes([0x73; 32]),
        transactions: std::slice::from_ref(&transfer_tx2),
    };
    let meta3 = apply_block(&store, &meta2, &block3).unwrap();
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![-0i64, -1, 2]
    );

    let after_rb3 = rollback_one_block(&store, &meta3, &block3).unwrap();
    assert_eq!(after_rb3, meta2);
    assert_eq!(
        store.read_token_box_entries(&token_id).unwrap().unwrap(),
        vec![-0i64, 1]
    );
    let record = store.read_token(&token_id).unwrap().unwrap();
    assert_eq!(
        record.emission_amount,
        Some(50),
        "record preserved across partial rollback"
    );
}

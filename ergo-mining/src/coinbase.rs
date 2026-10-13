//! Coinbase transaction assembly: pre-EIP-27 emission tx and fee tx.
//!
//! Port of `CandidateGenerator.collectRewards` from
//! `src/main/scala/org/ergoplatform/mining/CandidateGenerator.scala:713-820`,
//! pre-EIP-27 path only. The EIP-27 activation + post-activation paths
//! live in `crate::reemission`.
//!
//! Two transactions, in this order in the block:
//!
//! 1. **Emission tx**: consumes the current emission box, emits an
//!    updated emission box (value reduced by `miners_reward_at_height`)
//!    plus a single miner reward box. One input (the emission box,
//!    empty proof), two outputs.
//!
//! 2. **Fee tx** (optional, skipped when total fees == 0): consumes
//!    all fee-locked outputs from selected user transactions (boxes
//!    whose `ergo_tree_bytes == MAINNET_FEE_PROPOSITION_BYTES` and
//!    that aren't spent within the block), aggregates their values
//!    and tokens into a single miner reward box, collecting only the
//!    fee boxes that keep that box within the output limits.

#[cfg(test)]
use ergo_primitives::digest::Digest32;
use ergo_primitives::digest::{blake2b256, ModifierId};
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::token::Token;
use ergo_ser::transaction::{bytes_to_sign, Transaction};
use ergo_validation::tx::structural::serialized_box_size;
use ergo_validation::ProtocolParams;

use crate::emission_rules::{miners_reward_at_height, MonetarySettings};
use crate::error::MiningError;
use crate::reward_script::reward_output_script;

/// Mainnet fee-output proposition bytes, mirrored from
/// `ergo-mempool/src/validator.rs:35-43` so this crate can detect
/// fee boxes without depending on `ergo-mempool`. Identity is
/// `Scala::MonetarySettings.feePropositionBytes` =
/// `ErgoTreePredef.feeProposition(720).bytes`.
const MAINNET_FEE_PROPOSITION_BYTES: &[u8] = &[
    0x10, 0x05, 0x04, 0x00, 0x04, 0x00, 0x0e, 0x36, 0x10, 0x02, 0x04, 0xa0, 0x0b, 0x08, 0xcd, 0x02,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0xea, 0x02, 0xd1, 0x92, 0xa3, 0x9a, 0x8c, 0xc7, 0xa7, 0x01, 0x73, 0x00, 0x73, 0x01, 0x10, 0x01,
    0x02, 0x04, 0x02, 0xd1, 0x96, 0x83, 0x03, 0x01, 0x93, 0xa3, 0x8c, 0xc7, 0xb2, 0xa5, 0x73, 0x00,
    0x00, 0x01, 0x93, 0xc2, 0xb2, 0xa5, 0x73, 0x01, 0x00, 0x74, 0x73, 0x02, 0x73, 0x03, 0x83, 0x01,
    0x08, 0xcd, 0xee, 0xac, 0x93, 0xb1, 0xa5, 0x73, 0x04,
];

/// Build the pre-EIP-27 emission transaction for a candidate at
/// `next_height`. Mirrors the pre-activation branch of
/// `CandidateGenerator.collectRewards` (`CandidateGenerator.scala:736-800`).
///
/// `input_emission_box` is the current emission box in state.
/// `miner_pk` is the 33-byte compressed secp256k1 reward pubkey.
///
/// The emission box's `value` decreases by
/// `miners_reward_at_height(next_height, &mainnet)`; its tokens are
/// preserved verbatim (pre-EIP-27 the emission box has no tokens on
/// mainnet, but tests / testnet may differ). The miner reward box
/// carries `miners_reward_at_height` nanoERG, no tokens, no registers,
/// and uses the `reward_output_script(miner_pk)` lock.
pub fn build_pre_eip27_emission_tx(
    input_emission_box: &ErgoBox,
    miner_pk: &[u8; 33],
    next_height: u32,
    settings: &MonetarySettings,
) -> Result<Transaction, MiningError> {
    let emission_amount = miners_reward_at_height(next_height, settings);
    let input_value = input_emission_box.candidate.value;
    if emission_amount > input_value {
        return Err(MiningError::EmissionInvariant {
            op: "build_pre_eip27_emission_tx",
            reason: format!(
                "emission box value {input_value} < per-block emission {emission_amount} \
                 at h={next_height}: emission curve is exhausted or input is wrong",
            ),
        });
    }

    // Updated emission box: same script, same tokens (pre-EIP-27),
    // value reduced, height bumped.
    let new_emission_box = ErgoBoxCandidate::from_trusted_raw_parts(
        input_value - emission_amount,
        input_emission_box.candidate.ergo_tree().clone(),
        input_emission_box.candidate.ergo_tree_bytes().to_vec(),
        next_height,
        input_emission_box.candidate.tokens.clone(),
        AdditionalRegisters::empty(),
        Vec::new(), // empty registers serialize to a single `0x00` count byte; we let new() re-serialize below
    );
    // Re-derive register bytes through new() to be safe (we used trusted_raw_parts above for the tree bytes).
    let new_emission_box = ErgoBoxCandidate::new(
        new_emission_box.value,
        new_emission_box.ergo_tree().clone(),
        next_height,
        new_emission_box.tokens.clone(),
        AdditionalRegisters::empty(),
    )
    .map_err(|e| MiningError::IdComputation {
        op: "new_emission_box",
        reason: format!("{e:?}"),
    })?;

    // Miner reward box: 54-byte reward script, no tokens, no registers.
    let reward_script_bytes = reward_output_script(miner_pk).to_vec();
    let reward_tree = parse_ergo_tree(&reward_script_bytes)?;
    let miner_box = ErgoBoxCandidate::from_trusted_raw_parts(
        emission_amount,
        reward_tree,
        reward_script_bytes,
        next_height,
        Vec::new(),
        AdditionalRegisters::empty(),
        vec![0x00], // empty-register block serializes as a single 0x00 count byte
    );

    let input = Input {
        box_id: input_emission_box
            .box_id()
            .map_err(|e| MiningError::IdComputation {
                op: "emission_box_id",
                reason: format!("{e:?}"),
            })?,
        spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).map_err(|e| {
            MiningError::IdComputation {
                op: "empty_spending_proof",
                reason: format!("{e:?}"),
            }
        })?,
    };

    Ok(Transaction {
        inputs: vec![input],
        data_inputs: Vec::new(),
        output_candidates: vec![new_emission_box, miner_box],
    })
}

/// Build the fee transaction. Returns `None` when the selected
/// transactions produce no fee-locked outputs (or all such outputs
/// are spent within the same block, or none fits the miner box).
///
/// Mirrors `CandidateGenerator.collectRewards` lines 803-820, with one
/// addition: the single miner output must pass the same output checks
/// the validator applies (`params.max_box_size` measured by
/// [`serialized_box_size`], `params.max_tokens_per_box`). Fee boxes are
/// visited in block order (transaction order, then output index); equal
/// token ids are merged with checked addition, and a fee box is collected
/// only if the miner box still fits every limit with it included. A box
/// that does not fit is left uncollected: it stays an ordinary unspent
/// fee-proposition box and can be collected by a later block.
pub fn build_fee_tx(
    selected_user_txs: &[Transaction],
    miner_pk: &[u8; 33],
    next_height: u32,
    params: &ProtocolParams,
) -> Result<Option<Transaction>, MiningError> {
    let fee_boxes = find_unspent_fee_boxes(selected_user_txs)?;
    if fee_boxes.is_empty() {
        return Ok(None);
    }

    let reward_script_bytes = reward_output_script(miner_pk).to_vec();
    let reward_tree = parse_ergo_tree(&reward_script_bytes)?;
    let miner_box_with = |value: u64, tokens: Vec<Token>| {
        ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            reward_tree.clone(),
            reward_script_bytes.clone(),
            next_height,
            tokens,
            AdditionalRegisters::empty(),
            vec![0x00],
        )
    };
    let max_box_size = params.max_box_size as usize;
    let max_tokens = params.max_tokens_per_box as usize;

    let mut collected: Vec<&ErgoBox> = Vec::new();
    let mut miner_box: Option<ErgoBoxCandidate> = None;
    let mut total_value: u64 = 0;
    let mut combined_tokens: Vec<Token> = Vec::new();
    for b in &fee_boxes {
        let Some(value) = total_value
            .checked_add(b.candidate.value)
            .filter(|v| *v <= i64::MAX as u64)
        else {
            continue;
        };
        let Some(tokens) = merge_tokens(&combined_tokens, &b.candidate.tokens) else {
            continue;
        };
        if tokens.len() > max_tokens {
            continue;
        }
        let probe = miner_box_with(value, tokens.clone());
        // The miner box is output 0 of the fee transaction.
        let size = serialized_box_size(&probe, 0).map_err(|e| MiningError::IdComputation {
            op: "fee_box_size",
            reason: format!("{e:?}"),
        })?;
        if size > max_box_size {
            continue;
        }
        total_value = value;
        combined_tokens = tokens;
        miner_box = Some(probe);
        collected.push(b);
    }
    let Some(miner_box) = miner_box else {
        return Ok(None);
    };

    let inputs: Vec<Input> = collected
        .iter()
        .map(|b| {
            b.box_id().map(|box_id| Input {
                box_id,
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty())
                    .expect("empty spending proof always builds"),
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MiningError::IdComputation {
            op: "fee_input_box_id",
            reason: format!("{e:?}"),
        })?;

    Ok(Some(Transaction {
        inputs,
        data_inputs: Vec::new(),
        output_candidates: vec![miner_box],
    }))
}

/// Merge `extra` into a copy of `base`: equal token ids sum their amounts,
/// new ids are appended in first-seen order. `None` when a sum leaves the
/// positive signed-Long range token amounts must stay within.
fn merge_tokens(base: &[Token], extra: &[Token]) -> Option<Vec<Token>> {
    let mut merged = base.to_vec();
    for token in extra {
        if let Some(existing) = merged.iter_mut().find(|t| t.token_id == token.token_id) {
            existing.amount = existing
                .amount
                .checked_add(token.amount)
                .filter(|v| *v <= i64::MAX as u64)?;
        } else {
            merged.push(token.clone());
        }
    }
    Some(merged)
}

/// Walk `txs` and return every output box whose script bytes match
/// the mainnet fee proposition AND is not spent within `txs` itself.
/// Mirrors the `feeBoxes` computation at `CandidateGenerator.scala:803-806`.
fn find_unspent_fee_boxes(txs: &[Transaction]) -> Result<Vec<ErgoBox>, MiningError> {
    // Collect every input.box_id from the batch, so we can filter
    // out fee outputs that the batch immediately re-spends.
    let mut spent_in_batch: std::collections::HashSet<[u8; 32]> = Default::default();
    for tx in txs {
        for inp in &tx.inputs {
            spent_in_batch.insert(*inp.box_id.as_bytes());
        }
    }

    let mut out = Vec::new();
    for tx in txs {
        // Compute tx_id = blake2b256(bytes_to_sign(tx)).
        let bts = bytes_to_sign(tx).map_err(|e| MiningError::IdComputation {
            op: "bytes_to_sign",
            reason: format!("{e:?}"),
        })?;
        let tx_id: ModifierId = ModifierId::from_bytes(*blake2b256(&bts).as_bytes());

        for (i, candidate) in tx.output_candidates.iter().enumerate() {
            if candidate.ergo_tree_bytes() != MAINNET_FEE_PROPOSITION_BYTES {
                continue;
            }
            let ergo_box = ErgoBox {
                candidate: candidate.clone(),
                transaction_id: tx_id,
                index: i as u16,
            };
            let box_id = ergo_box.box_id().map_err(|e| MiningError::IdComputation {
                op: "fee_output_box_id",
                reason: format!("{e:?}"),
            })?;
            if spent_in_batch.contains(box_id.as_bytes()) {
                continue;
            }
            out.push(ergo_box);
        }
    }
    Ok(out)
}

/// Parse 54-or-more bytes of canonical ErgoTree wire-form into an
/// `ergo_ser::ergo_tree::ErgoTree`.
fn parse_ergo_tree(bytes: &[u8]) -> Result<ergo_ser::ergo_tree::ErgoTree, MiningError> {
    use ergo_primitives::reader::VlqReader;
    let mut r = VlqReader::new(bytes);
    ergo_ser::ergo_tree::read_ergo_tree(&mut r).map_err(|e| MiningError::Decode {
        op: "reward_ergo_tree",
        reason: format!("{e:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    // ----- helpers -----

    #[derive(Deserialize)]
    struct EmissionTxFixture {
        #[allow(dead_code)]
        height: u32,
        #[allow(dead_code)]
        header_id: String,
        emission_tx: TxJson,
    }
    #[derive(Deserialize)]
    struct TxJson {
        id: String,
        inputs: Vec<InputJson>,
        #[allow(dead_code)]
        #[serde(rename = "dataInputs")]
        data_inputs: Vec<serde_json::Value>,
        outputs: Vec<OutputJson>,
    }
    #[derive(Deserialize)]
    struct InputJson {
        #[serde(rename = "boxId")]
        box_id: String,
        #[allow(dead_code)]
        #[serde(rename = "spendingProof")]
        spending_proof: serde_json::Value,
    }

    // The `box_id` field IS read by the parity test (mainnet input check).
    impl InputJson {
        #[allow(dead_code)]
        fn _read(&self) -> &str {
            &self.box_id
        }
    }
    #[derive(Deserialize)]
    struct OutputJson {
        #[serde(rename = "boxId")]
        #[allow(dead_code)]
        box_id: String,
        value: u64,
        #[serde(rename = "ergoTree")]
        ergo_tree: String,
        #[serde(rename = "creationHeight")]
        creation_height: u32,
        #[serde(default)]
        assets: Vec<AssetJson>,
    }
    #[derive(Deserialize)]
    struct AssetJson {
        #[serde(rename = "tokenId")]
        token_id: String,
        amount: u64,
    }

    fn load(h: u32) -> EmissionTxFixture {
        let path = format!(
            "{}/../test-vectors/mining/emission_txs/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        let bytes = std::fs::read(&path).expect("read");
        serde_json::from_slice(&bytes).expect("parse")
    }

    fn ergo_box_from_output(o: &OutputJson, tx_id_hex: &str, index: u16) -> ErgoBox {
        let tree_bytes = hex::decode(&o.ergo_tree).expect("tree hex");
        let tree = parse_ergo_tree(&tree_bytes).expect("parse tree");
        let tokens: Vec<Token> = o
            .assets
            .iter()
            .map(|a| {
                let mut id = [0u8; 32];
                hex::decode_to_slice(&a.token_id, &mut id).expect("token hex");
                Token {
                    token_id: Digest32::from_bytes(id),
                    amount: a.amount,
                }
            })
            .collect();
        let candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            o.value,
            tree,
            tree_bytes,
            o.creation_height,
            tokens,
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let mut tx_id_arr = [0u8; 32];
        hex::decode_to_slice(tx_id_hex, &mut tx_id_arr).expect("tx_id hex");
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id_arr),
            index,
        }
    }

    /// Recover the miner pubkey from a real reward box's ergoTree at
    /// the canonical pk offset (7..40 of the 54-byte script).
    fn miner_pk_from_reward_tree_hex(tree_hex: &str) -> [u8; 33] {
        let raw = hex::decode(tree_hex).expect("tree hex");
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&raw[7..40]);
        pk
    }

    // ----- happy path -----

    #[test]
    fn pre_eip27_emission_tx_matches_mainnet_at_700000() {
        // Parent emission box: output[0] of h=699999's emission tx.
        let parent = load(699_999);
        let input_box =
            ergo_box_from_output(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);

        // Target: h=700000's emission tx.
        let target = load(700_000);
        let miner_pk = miner_pk_from_reward_tree_hex(&target.emission_tx.outputs[1].ergo_tree);

        let settings = MonetarySettings::mainnet();
        let built = build_pre_eip27_emission_tx(&input_box, &miner_pk, 700_000, &settings)
            .expect("build emission tx");

        // Inputs: single input pointing at parent emission box.
        assert_eq!(built.inputs.len(), 1);
        assert_eq!(built.data_inputs.len(), 0);
        assert_eq!(built.output_candidates.len(), 2);
        let captured_input_box_id = hex::decode(&target.emission_tx.inputs[0].box_id).expect("hex");
        assert_eq!(
            built.inputs[0].box_id.as_bytes()[..],
            captured_input_box_id[..],
            "emission input box_id mismatch (input == h=699999.tx.outputs[0].box_id)"
        );
        // Empty spending proof.
        assert!(built.inputs[0].spending_proof.proof.is_empty());
        assert!(built.inputs[0].spending_proof.extension().is_empty());

        // Output[0] = new emission box.
        let new_em = &built.output_candidates[0];
        assert_eq!(new_em.value, target.emission_tx.outputs[0].value);
        assert_eq!(new_em.creation_height, 700_000);
        let captured_tree = hex::decode(&target.emission_tx.outputs[0].ergo_tree).expect("hex");
        assert_eq!(
            new_em.ergo_tree_bytes(),
            &captured_tree[..],
            "new emission box ergo_tree must equal input emission box's ergo_tree"
        );
        assert!(
            new_em.tokens.is_empty(),
            "pre-EIP-27 emission has no tokens"
        );

        // Output[1] = miner reward box.
        let miner = &built.output_candidates[1];
        assert_eq!(miner.value, target.emission_tx.outputs[1].value);
        assert_eq!(miner.creation_height, 700_000);
        let captured_reward_tree =
            hex::decode(&target.emission_tx.outputs[1].ergo_tree).expect("hex");
        assert_eq!(miner.ergo_tree_bytes(), &captured_reward_tree[..]);
        assert!(miner.tokens.is_empty(), "pre-EIP-27 miner gets no tokens");
    }

    #[test]
    fn pre_eip27_emission_tx_matches_mainnet_at_700001() {
        let parent = load(700_000);
        let input_box =
            ergo_box_from_output(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let target = load(700_001);
        let miner_pk = miner_pk_from_reward_tree_hex(&target.emission_tx.outputs[1].ergo_tree);
        let built = build_pre_eip27_emission_tx(
            &input_box,
            &miner_pk,
            700_001,
            &MonetarySettings::mainnet(),
        )
        .expect("build");

        assert_eq!(
            built.output_candidates[0].value,
            target.emission_tx.outputs[0].value
        );
        assert_eq!(
            built.output_candidates[1].value,
            target.emission_tx.outputs[1].value
        );
        assert_eq!(built.output_candidates[1].creation_height, 700_001);
    }

    // ----- fee tx happy path -----

    #[test]
    fn build_fee_tx_returns_none_for_empty_batch() {
        let miner_pk = [0x02u8; 33];
        let fee = build_fee_tx(
            &[],
            &miner_pk,
            1_000_000,
            &ProtocolParams::mainnet_default(),
        )
        .expect("ok");
        assert!(fee.is_none(), "empty user-tx batch must produce no fee tx");
    }

    fn token(seed: u8, index: u8, amount: u64) -> Token {
        let mut id = [seed; 32];
        id[0] = index;
        Token {
            token_id: Digest32::from_bytes(id),
            amount,
        }
    }

    fn fee_output(value: u64, tokens: Vec<Token>) -> ErgoBoxCandidate {
        let tree = parse_ergo_tree(MAINNET_FEE_PROPOSITION_BYTES).expect("fee tree");
        ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            tree,
            MAINNET_FEE_PROPOSITION_BYTES.to_vec(),
            1_000,
            tokens,
            AdditionalRegisters::empty(),
            vec![0x00],
        )
    }

    /// A user transaction (inputs are irrelevant to fee collection) whose
    /// outputs are the given fee boxes.
    fn user_tx(seed: u8, outputs: Vec<ErgoBoxCandidate>) -> Transaction {
        Transaction {
            inputs: vec![Input {
                box_id: Digest32::from_bytes([seed; 32]),
                spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty())
                    .expect("proof"),
            }],
            data_inputs: Vec::new(),
            output_candidates: outputs,
        }
    }

    fn assert_within_limits(tx: &Transaction, params: &ProtocolParams) {
        assert_eq!(tx.output_candidates.len(), 1);
        let miner_box = &tx.output_candidates[0];
        assert!(miner_box.tokens.len() <= params.max_tokens_per_box as usize);
        let size = serialized_box_size(miner_box, 0).expect("size");
        assert!(
            size <= params.max_box_size as usize,
            "miner box is {size} bytes"
        );
    }

    #[test]
    fn fee_collection_merges_equal_token_ids() {
        let params = ProtocolParams::mainnet_default();
        let miner_pk = [0x02u8; 33];
        // 122 entries of one token id, split over two fee outputs of two
        // transactions, plus a second id: the miner box carries two entries.
        let repeated = |n: usize| vec![token(7, 0, 1); n];
        let mut second = repeated(61);
        second.push(token(8, 1, 5));
        let txs = vec![
            user_tx(1, vec![fee_output(1_000_000, repeated(61))]),
            user_tx(2, vec![fee_output(2_000_000, second)]),
        ];
        let fee_tx = build_fee_tx(&txs, &miner_pk, 1_001, &params)
            .expect("build")
            .expect("fee tx");
        assert_eq!(fee_tx.inputs.len(), 2, "both fee boxes are collected");
        let miner_box = &fee_tx.output_candidates[0];
        assert_eq!(miner_box.value, 3_000_000);
        assert_eq!(miner_box.tokens, vec![token(7, 0, 122), token(8, 1, 5)]);
        assert_within_limits(&fee_tx, &params);
    }

    #[test]
    fn fee_collection_stays_within_box_limits() {
        let params = ProtocolParams::mainnet_default();
        let miner_pk = [0x02u8; 33];
        // Five fee boxes of 70 distinct tokens each (350 ids in total) and a
        // final token-free fee box.
        let mut txs: Vec<Transaction> = (1..=5u8)
            .map(|seed| {
                let tokens = (0..70).map(|i| token(seed, i, 1)).collect();
                user_tx(seed, vec![fee_output(1_000_000, tokens)])
            })
            .collect();
        txs.push(user_tx(9, vec![fee_output(500_000, Vec::new())]));
        let fee_tx = build_fee_tx(&txs, &miner_pk, 1_001, &params)
            .expect("build")
            .expect("fee tx");
        assert_within_limits(&fee_tx, &params);

        // Each 70-token box adds ~2.3 KiB, so only the first token box fits;
        // the later ones are skipped, the token-free box still fits.
        let fee_boxes = find_unspent_fee_boxes(&txs).expect("fee boxes");
        let collected: Vec<_> = fee_tx.inputs.iter().map(|i| i.box_id).collect();
        let expected: Vec<_> = [0usize, 5]
            .iter()
            .map(|&i| fee_boxes[i].box_id().expect("id"))
            .collect();
        assert_eq!(collected, expected);
        let miner_box = &fee_tx.output_candidates[0];
        assert_eq!(miner_box.value, 1_500_000);
        assert_eq!(miner_box.tokens, fee_boxes[0].candidate.tokens);

        // The same input yields the same transaction.
        let again = build_fee_tx(&txs, &miner_pk, 1_001, &params)
            .expect("build")
            .expect("fee tx");
        assert_eq!(again, fee_tx);
    }

    #[test]
    fn fee_collection_respects_the_token_count_limit() {
        let mut params = ProtocolParams::mainnet_default();
        params.max_tokens_per_box = 3;
        let miner_pk = [0x02u8; 33];
        let txs = vec![
            user_tx(
                1,
                vec![fee_output(1_000_000, vec![token(1, 0, 1), token(1, 1, 1)])],
            ),
            user_tx(
                2,
                vec![fee_output(1_000_000, vec![token(2, 0, 1), token(2, 1, 1)])],
            ),
            // Repeats an id already collected: merging keeps the count at 2.
            user_tx(3, vec![fee_output(1_000_000, vec![token(1, 0, 4)])]),
        ];
        let fee_tx = build_fee_tx(&txs, &miner_pk, 1_001, &params)
            .expect("build")
            .expect("fee tx");
        assert_eq!(fee_tx.inputs.len(), 2);
        let miner_box = &fee_tx.output_candidates[0];
        assert_eq!(miner_box.value, 2_000_000);
        assert_eq!(miner_box.tokens, vec![token(1, 0, 5), token(1, 1, 1)]);
    }

    #[test]
    fn fee_collection_skips_a_box_whose_token_sum_overflows() {
        let params = ProtocolParams::mainnet_default();
        let miner_pk = [0x02u8; 33];
        let max = i64::MAX as u64;
        let txs = vec![
            user_tx(1, vec![fee_output(1_000_000, vec![token(1, 0, max)])]),
            user_tx(2, vec![fee_output(1_000_000, vec![token(1, 0, 1)])]),
        ];
        let fee_tx = build_fee_tx(&txs, &miner_pk, 1_001, &params)
            .expect("build")
            .expect("fee tx");
        assert_eq!(fee_tx.inputs.len(), 1);
        assert_eq!(fee_tx.output_candidates[0].tokens, vec![token(1, 0, max)]);
    }

    // ----- error paths -----

    #[test]
    fn pre_eip27_emission_tx_rejects_exhausted_emission_box() {
        // Take a real emission box from the captured corpus and
        // overwrite its value with 1 nanoERG so the per-height
        // emission exceeds the box's value. This exercises the
        // "emission curve exhausted" guard without forging a tree.
        let parent = load(699_999);
        let real_input =
            ergo_box_from_output(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        // Rebuild with value=1.
        let exhausted_candidate = ErgoBoxCandidate::from_trusted_raw_parts(
            1,
            real_input.candidate.ergo_tree().clone(),
            real_input.candidate.ergo_tree_bytes().to_vec(),
            real_input.candidate.creation_height,
            real_input.candidate.tokens.clone(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let input_box = ErgoBox {
            candidate: exhausted_candidate,
            transaction_id: real_input.transaction_id,
            index: 0,
        };
        let err = build_pre_eip27_emission_tx(
            &input_box,
            &[0x02u8; 33],
            700_000,
            &MonetarySettings::mainnet(),
        )
        .expect_err("must reject");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_pre_eip27_emission_tx");
                assert!(
                    reason.contains("emission box value") && reason.contains("exhausted"),
                    "{reason}"
                );
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }
}

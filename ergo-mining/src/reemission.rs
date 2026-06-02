//! EIP-27 re-emission emission-tx assembly.
//!
//! Port of the EIP-27 branches of Scala `CandidateGenerator.collectRewards`
//! (`CandidateGenerator.scala:736-800`). Three regimes:
//!
//! - **Pre-activation** (`next_height < activation_height`): handled
//!   by `crate::coinbase::build_pre_eip27_emission_tx`. No reemission
//!   tokens involved.
//! - **At activation** (`next_height == activation_height`): emission tx
//!   has TWO inputs (emission box + injection box) and the injection
//!   box's NFT + reemission tokens get moved into the updated emission
//!   box. Miner gets `emission_amount + injection_box.value` nanoERG
//!   plus a reemission-token share.
//! - **Post-activation** (`next_height > activation_height`): emission
//!   tx has one input. The emission box carries the NFT + a depleting
//!   stash of reemission tokens; each block deducts
//!   `reemission_for_height` tokens, transferring them to the miner.
//!
//! Reemission ends at `reemission_start_height` (mainnet 2,080,800) —
//! `reemission_for_height` returns 0 from that height onward. The
//! emission tx is otherwise structurally identical to the
//! pre-activation form (no token movement) but still 2-output.
//!
//! Byte-parity-verified against captured mainnet fixtures at h=777217
//! (activation) and h=777218 (first post-activation).

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::token::Token;
use ergo_ser::transaction::Transaction;

use crate::emission_rules::{
    emission_at_height, miners_reward_at_height, MonetarySettings, COINS_IN_ONE_ERGO,
};
use crate::error::MiningError;
use crate::reward_script::reward_output_script;

/// Per-network EIP-27 re-emission parameters (activation height,
/// distribution schedule, token / NFT identities). Re-exported from
/// `ergo-chain-spec` so the existing API surface keeps working while
/// the type lives in the chain-spec crate.
pub use ergo_chain_spec::ReemissionParams as ReemissionSettings;

/// Reemission share unlocked at `height`. Mirror of Scala
/// `ReemissionRules.reemissionForHeight` (`ReemissionRules.scala:22-39`).
///
/// `basicChargeAmount = 12 ERG` is moved from emission to reemission
/// each block while the per-height emission is at least 15 ERG. As
/// emission decays past 15 ERG, a proportional charge is taken (leaving
/// a 3 ERG floor). Below 3 ERG, nothing is moved.
pub fn reemission_for_height(
    height: u32,
    settings: &MonetarySettings,
    reemission: &ReemissionSettings,
) -> u64 {
    let emission = emission_at_height(height, settings);
    let basic = 12u64 * COINS_IN_ONE_ERGO;
    let buffer = 3u64 * COINS_IN_ONE_ERGO;
    if height >= reemission.activation_height && emission >= basic + buffer {
        basic
    } else if height >= reemission.activation_height && emission > buffer {
        emission - buffer
    } else {
        0
    }
}

/// Build the at-activation emission tx — `next_height ==
/// reemission.activation_height`. Two inputs: the consumed emission
/// box (no tokens pre-activation) and the consumed injection box
/// (carrying NFT + the full reemission token stash). Two outputs:
/// updated emission box with NFT + (stash − reemission_for_height),
/// miner reward box with `emission_amount + injection.value` nanoERG
/// plus a `reemission_for_height` reemission-token share.
pub fn build_activation_emission_tx(
    input_emission_box: &ErgoBox,
    injection_box: &ErgoBox,
    miner_pk: &[u8; 33],
    next_height: u32,
    settings: &MonetarySettings,
    reemission: &ReemissionSettings,
) -> Result<Transaction, MiningError> {
    if next_height != reemission.activation_height {
        return Err(MiningError::EmissionInvariant {
            op: "build_activation_emission_tx",
            reason: format!(
                "called at height {next_height}, expected activation_height {}",
                reemission.activation_height
            ),
        });
    }

    let emission_amount = miners_reward_at_height(next_height, settings);
    let reem_amount = reemission_for_height(next_height, settings, reemission);

    // Updated emission box: takes injection box's tokens, reduces
    // reemission amount.
    let injection_tokens = injection_box.candidate.tokens.clone();
    if injection_tokens.len() != 2 {
        return Err(MiningError::EmissionInvariant {
            op: "build_activation_emission_tx",
            reason: format!(
                "injection box must carry exactly 2 tokens (NFT + reemission), got {}",
                injection_tokens.len()
            ),
        });
    }
    // Scala swaps if NFT is at index 1 (`CandidateGenerator.scala:749-753`).
    let (em_tokens, reem_idx) = normalize_emission_tokens(&injection_tokens);
    let updated_reem_amount = em_tokens[reem_idx]
        .amount
        .checked_sub(reem_amount)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "build_activation_emission_tx",
            reason: format!(
                "reemission stash {} < reem_amount {} at h={next_height}",
                em_tokens[reem_idx].amount, reem_amount,
            ),
        })?;
    let mut updated_tokens = em_tokens.clone();
    updated_tokens[reem_idx] = Token {
        token_id: reemission.reemission_token_id,
        amount: updated_reem_amount,
    };

    // Updated emission box value
    let new_em_value = input_emission_box
        .candidate
        .value
        .checked_sub(emission_amount)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "build_activation_emission_tx",
            reason: format!(
                "emission box value {} < emission_amount {} at h={next_height}",
                input_emission_box.candidate.value, emission_amount,
            ),
        })?;
    let new_emission_box = coinbase_clone_emission_box(
        input_emission_box,
        new_em_value,
        next_height,
        updated_tokens,
    )?;

    // Miner box: emission_amount + injection.value nanoERG plus
    // `reem_amount` reemission tokens.
    let miner_value = emission_amount
        .checked_add(injection_box.candidate.value)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "build_activation_emission_tx",
            reason: format!(
                "miner value overflow: emission {} + injection {} at h={next_height}",
                emission_amount, injection_box.candidate.value,
            ),
        })?;
    let miner_tokens = vec![Token {
        token_id: reemission.reemission_token_id,
        amount: reem_amount,
    }];
    let miner_box = build_miner_box(miner_pk, miner_value, next_height, miner_tokens)?;

    Ok(Transaction {
        inputs: vec![
            empty_input(
                input_emission_box
                    .box_id()
                    .map_err(|e| MiningError::IdComputation {
                        op: "emission_box_id",
                        reason: format!("{e:?}"),
                    })?,
            )?,
            empty_input(
                injection_box
                    .box_id()
                    .map_err(|e| MiningError::IdComputation {
                        op: "injection_box_id",
                        reason: format!("{e:?}"),
                    })?,
            )?,
        ],
        data_inputs: Vec::new(),
        output_candidates: vec![new_emission_box, miner_box],
    })
}

/// Build a post-activation emission tx — `next_height >
/// activation_height`. One input (the emission box now carrying
/// NFT + depleting reemission stash). Two outputs. Pre-2,080,800
/// the miner receives a reemission-token share; from 2,080,800 onward
/// `reemission_for_height` returns 0 and the tx is structurally just
/// the pre-EIP-27 form with tokens preserved verbatim.
pub fn build_post_eip27_emission_tx(
    input_emission_box: &ErgoBox,
    miner_pk: &[u8; 33],
    next_height: u32,
    settings: &MonetarySettings,
    reemission: &ReemissionSettings,
) -> Result<Transaction, MiningError> {
    if next_height <= reemission.activation_height {
        return Err(MiningError::EmissionInvariant {
            op: "build_post_eip27_emission_tx",
            reason: format!(
                "called at h={next_height} but activation_height={}, expected h > activation",
                reemission.activation_height
            ),
        });
    }
    let emission_amount = miners_reward_at_height(next_height, settings);
    let reem_amount = reemission_for_height(next_height, settings, reemission);

    let in_tokens = input_emission_box.candidate.tokens.clone();
    if in_tokens.len() != 2 {
        return Err(MiningError::EmissionInvariant {
            op: "build_post_eip27_emission_tx",
            reason: format!(
                "post-EIP-27 emission box must carry NFT + reemission tokens (2 entries), got {}",
                in_tokens.len()
            ),
        });
    }
    let (em_tokens, reem_idx) = normalize_emission_tokens(&in_tokens);
    let updated_reem_amount = em_tokens[reem_idx]
        .amount
        .checked_sub(reem_amount)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "build_post_eip27_emission_tx",
            reason: format!(
                "reemission stash {} < reem_amount {} at h={next_height}",
                em_tokens[reem_idx].amount, reem_amount,
            ),
        })?;
    let mut updated_tokens = em_tokens.clone();
    updated_tokens[reem_idx] = Token {
        token_id: reemission.reemission_token_id,
        amount: updated_reem_amount,
    };

    let new_em_value = input_emission_box
        .candidate
        .value
        .checked_sub(emission_amount)
        .ok_or_else(|| MiningError::EmissionInvariant {
            op: "build_post_eip27_emission_tx",
            reason: format!(
                "emission box value {} < emission_amount {} at h={next_height}",
                input_emission_box.candidate.value, emission_amount,
            ),
        })?;
    let new_emission_box = coinbase_clone_emission_box(
        input_emission_box,
        new_em_value,
        next_height,
        updated_tokens,
    )?;

    let miner_tokens = if reem_amount == 0 {
        Vec::new() // post-2,080,800: no more reemission share
    } else {
        vec![Token {
            token_id: reemission.reemission_token_id,
            amount: reem_amount,
        }]
    };
    let miner_box = build_miner_box(miner_pk, emission_amount, next_height, miner_tokens)?;

    Ok(Transaction {
        inputs: vec![empty_input(input_emission_box.box_id().map_err(|e| {
            MiningError::IdComputation {
                op: "emission_box_id",
                reason: format!("{e:?}"),
            }
        })?)?],
        data_inputs: Vec::new(),
        output_candidates: vec![new_emission_box, miner_box],
    })
}

/// Token ordering: if NFT is at index 1 in the source, swap so NFT
/// is at index 0 and reemission tokens at index 1. Matches Scala
/// `CandidateGenerator.scala:749-753`.
fn normalize_emission_tokens(tokens: &[Token]) -> (Vec<Token>, usize) {
    assert_eq!(tokens.len(), 2, "caller must check length");
    if tokens[1].amount == 1 {
        // NFT is at index 1; swap so it's at index 0.
        (vec![tokens[1].clone(), tokens[0].clone()], 1)
    } else {
        (tokens.to_vec(), 1)
    }
}

fn coinbase_clone_emission_box(
    input: &ErgoBox,
    new_value: u64,
    new_height: u32,
    tokens: Vec<Token>,
) -> Result<ErgoBoxCandidate, MiningError> {
    ErgoBoxCandidate::new(
        new_value,
        input.candidate.ergo_tree().clone(),
        new_height,
        tokens,
        AdditionalRegisters::empty(),
    )
    .map_err(|e| MiningError::IdComputation {
        op: "clone_emission_box",
        reason: format!("{e:?}"),
    })
}

fn build_miner_box(
    miner_pk: &[u8; 33],
    value: u64,
    height: u32,
    tokens: Vec<Token>,
) -> Result<ErgoBoxCandidate, MiningError> {
    let reward_bytes = reward_output_script(miner_pk).to_vec();
    let reward_tree = coinbase_parse_reward_tree(&reward_bytes)?;
    Ok(ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        reward_tree,
        reward_bytes,
        height,
        tokens,
        AdditionalRegisters::empty(),
        vec![0x00],
    ))
}

fn coinbase_parse_reward_tree(bytes: &[u8]) -> Result<ergo_ser::ergo_tree::ErgoTree, MiningError> {
    let mut r = ergo_primitives::reader::VlqReader::new(bytes);
    ergo_ser::ergo_tree::read_ergo_tree(&mut r).map_err(|e| MiningError::Decode {
        op: "reward_tree",
        reason: format!("{e:?}"),
    })
}

fn empty_input(box_id: Digest32) -> Result<Input, MiningError> {
    Ok(Input {
        box_id,
        spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).map_err(|e| {
            MiningError::IdComputation {
                op: "empty_spending_proof",
                reason: format!("{e:?}"),
            }
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use serde::Deserialize;

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
        outputs: Vec<OutputJson>,
    }
    #[derive(Deserialize)]
    struct InputJson {
        #[serde(rename = "boxId")]
        box_id: String,
    }
    #[derive(Deserialize)]
    struct OutputJson {
        #[allow(dead_code)]
        #[serde(rename = "boxId")]
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

    #[derive(Deserialize)]
    struct InjectionBoxFixture {
        #[allow(dead_code)]
        #[serde(rename = "boxId")]
        box_id: String,
        value: u64,
        #[serde(rename = "ergoTree")]
        ergo_tree: String,
        #[serde(rename = "creationHeight")]
        creation_height: u32,
        assets: Vec<AssetJson>,
        #[serde(rename = "transactionId")]
        transaction_id: String,
        index: u16,
    }

    fn load(h: u32) -> EmissionTxFixture {
        let path = format!(
            "{}/../test-vectors/mining/reemission/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse")
    }
    fn load_injection() -> InjectionBoxFixture {
        let path = format!(
            "{}/../test-vectors/mining/reemission/injection_box.json",
            env!("CARGO_MANIFEST_DIR"),
        );
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse")
    }

    fn ergo_box_from(o: &OutputJson, tx_id_hex: &str, index: u16) -> ErgoBox {
        let tree_bytes = hex::decode(&o.ergo_tree).expect("tree hex");
        let tree = coinbase_parse_reward_tree(&tree_bytes).expect("parse tree");
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
        let mut tx_id = [0u8; 32];
        hex::decode_to_slice(tx_id_hex, &mut tx_id).expect("tx_id hex");
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id),
            index,
        }
    }

    fn injection_box_from_fixture(j: &InjectionBoxFixture) -> ErgoBox {
        let tree_bytes = hex::decode(&j.ergo_tree).expect("inj tree");
        let tree = coinbase_parse_reward_tree(&tree_bytes).expect("parse");
        let tokens: Vec<Token> = j
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
            j.value,
            tree,
            tree_bytes,
            j.creation_height,
            tokens,
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let mut tx_id = [0u8; 32];
        hex::decode_to_slice(&j.transaction_id, &mut tx_id).expect("inj txid");
        ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id),
            index: j.index,
        }
    }

    fn miner_pk_from_tree(hex_tree: &str) -> [u8; 33] {
        let raw = hex::decode(hex_tree).expect("tree");
        let mut pk = [0u8; 33];
        pk.copy_from_slice(&raw[7..40]);
        pk
    }

    // ----- happy path -----

    #[test]
    fn reemission_for_height_pinned_values() {
        let s = MonetarySettings::mainnet();
        let r = ReemissionSettings::mainnet();
        // Pre-activation: always 0.
        assert_eq!(reemission_for_height(777_216, &s, &r), 0);
        // At/post-activation while emission >= 15 ERG: basic = 12 ERG.
        assert_eq!(
            reemission_for_height(777_217, &s, &r),
            12 * COINS_IN_ONE_ERGO
        );
        assert_eq!(
            reemission_for_height(1_786_000, &s, &r),
            12 * COINS_IN_ONE_ERGO
        );
    }

    #[test]
    fn activation_tx_matches_mainnet_at_777217() {
        let parent = load(777_216);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let injection = injection_box_from_fixture(&load_injection());
        let target = load(777_217);
        let miner_pk = miner_pk_from_tree(&target.emission_tx.outputs[1].ergo_tree);

        let built = build_activation_emission_tx(
            &input_em,
            &injection,
            &miner_pk,
            777_217,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect("build activation");

        assert_eq!(built.inputs.len(), 2);
        assert_eq!(
            built.inputs[0].box_id.as_bytes()[..],
            hex::decode(&target.emission_tx.inputs[0].box_id).unwrap()[..],
            "input[0] must equal parent emission box id"
        );
        assert_eq!(
            built.inputs[1].box_id.as_bytes()[..],
            hex::decode(&target.emission_tx.inputs[1].box_id).unwrap()[..],
            "input[1] must equal injection box id"
        );

        assert_eq!(
            built.output_candidates[0].value, target.emission_tx.outputs[0].value,
            "updated emission box value"
        );
        assert_eq!(
            built.output_candidates[1].value, target.emission_tx.outputs[1].value,
            "miner box value (emission + injection.value)"
        );
        assert_eq!(built.output_candidates[1].creation_height, 777_217);
        // Miner gets exactly one reemission-token entry.
        assert_eq!(built.output_candidates[1].tokens.len(), 1);
        assert_eq!(
            built.output_candidates[1].tokens[0].amount,
            target.emission_tx.outputs[1].assets[0].amount,
            "miner reemission token share"
        );
        assert_eq!(built.output_candidates[0].tokens.len(), 2);
    }

    #[test]
    fn post_activation_tx_matches_mainnet_at_777218() {
        let parent = load(777_217);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let target = load(777_218);
        let miner_pk = miner_pk_from_tree(&target.emission_tx.outputs[1].ergo_tree);

        let built = build_post_eip27_emission_tx(
            &input_em,
            &miner_pk,
            777_218,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect("build post-eip27");
        assert_eq!(built.inputs.len(), 1);
        assert_eq!(
            built.output_candidates[0].value,
            target.emission_tx.outputs[0].value
        );
        assert_eq!(
            built.output_candidates[1].value,
            target.emission_tx.outputs[1].value
        );
        // Updated emission box has 2 tokens.
        assert_eq!(built.output_candidates[0].tokens.len(), 2);
        // Miner box has 1 token (reemission share).
        assert_eq!(built.output_candidates[1].tokens.len(), 1);
        assert_eq!(
            built.output_candidates[1].tokens[0].amount,
            target.emission_tx.outputs[1].assets[0].amount,
        );
    }

    // ----- error paths -----

    #[test]
    fn rejects_wrong_height_at_activation() {
        let parent = load(777_216);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let injection = injection_box_from_fixture(&load_injection());
        let err = build_activation_emission_tx(
            &input_em,
            &injection,
            &[0x02u8; 33],
            777_218,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("must reject wrong height");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_activation_emission_tx");
                assert!(reason.contains("activation_height"), "{reason}");
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }

    #[test]
    fn rejects_pre_activation_height_for_post_path() {
        let parent = load(777_216);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let err = build_post_eip27_emission_tx(
            &input_em,
            &[0x02u8; 33],
            777_217, // == activation, not >
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("must reject");
        assert!(matches!(
            err,
            MiningError::EmissionInvariant {
                op: "build_post_eip27_emission_tx",
                ..
            }
        ));
    }

    // ----- arithmetic-hardening branches (checked_sub / checked_add) -----

    #[test]
    fn activation_rejects_reemission_token_underflow() {
        // Zero the injection box's reemission-token stash so it is below the
        // per-block reem_amount: the checked_sub at the token step must error
        // instead of wrapping.
        let parent = load(777_216);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let mut injection = injection_box_from_fixture(&load_injection());
        for t in &mut injection.candidate.tokens {
            t.amount = 0;
        }
        let err = build_activation_emission_tx(
            &input_em,
            &injection,
            &[0x02u8; 33],
            777_217,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("reemission stash underflow must error");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_activation_emission_tx");
                assert!(reason.contains("reemission stash"), "{reason}");
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }

    #[test]
    fn activation_rejects_emission_box_value_underflow() {
        // Tiny emission-box value (< emission_amount) must error at the
        // box-value checked_sub instead of wrapping.
        let parent = load(777_216);
        let mut input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        input_em.candidate.value = 1;
        let injection = injection_box_from_fixture(&load_injection());
        let err = build_activation_emission_tx(
            &input_em,
            &injection,
            &[0x02u8; 33],
            777_217,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("emission box value underflow must error");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_activation_emission_tx");
                assert!(reason.contains("emission box value"), "{reason}");
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }

    #[test]
    fn activation_rejects_miner_value_overflow() {
        // u64::MAX injection value makes `emission_amount + injection.value`
        // overflow at the miner-value checked_add.
        let parent = load(777_216);
        let input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        let mut injection = injection_box_from_fixture(&load_injection());
        injection.candidate.value = u64::MAX;
        let err = build_activation_emission_tx(
            &input_em,
            &injection,
            &[0x02u8; 33],
            777_217,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("miner value overflow must error");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_activation_emission_tx");
                assert!(reason.contains("overflow"), "{reason}");
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }

    #[test]
    fn post_activation_rejects_emission_box_value_underflow() {
        // Same box-value underflow guard on the post-activation path.
        let parent = load(777_217);
        let mut input_em = ergo_box_from(&parent.emission_tx.outputs[0], &parent.emission_tx.id, 0);
        input_em.candidate.value = 1;
        let err = build_post_eip27_emission_tx(
            &input_em,
            &[0x02u8; 33],
            777_218,
            &MonetarySettings::mainnet(),
            &ReemissionSettings::mainnet(),
        )
        .expect_err("post emission box value underflow must error");
        match err {
            MiningError::EmissionInvariant { op, reason } => {
                assert_eq!(op, "build_post_eip27_emission_tx");
                assert!(reason.contains("emission box value"), "{reason}");
            }
            other => panic!("expected EmissionInvariant, got {other:?}"),
        }
    }
}

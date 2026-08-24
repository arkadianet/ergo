//! UTXO-backend block processing (Modes 1/3): load sections, validate,
//! apply to the AVL+ box arena. This is the original `process_block`
//! body, unchanged — the UTXO path stays byte-for-byte equivalent to
//! the pre-Mode-5 code and is deliberately NOT unified with the digest
//! path in [`super::digest`].

use std::time::Instant;

use tracing::debug;

use ergo_primitives::digest::blake2b256;
use ergo_primitives::reader::VlqReader;
use ergo_ser::block_transactions::read_block_transactions_with_group_elements;
use ergo_ser::extension::read_extension;
use ergo_ser::header::read_header;
use ergo_ser::modifier_id::{compute_section_id, ExpectedSections, TYPE_EXTENSION};
use ergo_state::store::StateStore;
use ergo_validation::block::{
    validate_full_block_parallel_with_group_elements, BlockValidationContext,
};
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;
use ergo_validation::voting::validate_epoch_extension;
use ergo_validation::{ChainHeaderReader, ChainHeaderReaderError, HeaderView};

use crate::perf::BlockPerfCounters;

use super::{BlockProcessError, ProcessedBlock};

/// Bridge `StateStore` → `ChainHeaderReader` so the voting recompute
/// pipeline can read `header.votes` for the previous voting epoch
/// (`compute_epoch_votes` walks 1024 headers per call).
struct StoreChainHeaderReader<'a> {
    store: &'a StateStore,
}

impl<'a> ChainHeaderReader for StoreChainHeaderReader<'a> {
    fn header_at(&self, height: u32) -> Result<HeaderView, ChainHeaderReaderError> {
        let header_id = self
            .store
            .get_header_id_at_height(height)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let header_bytes = self
            .store
            .get_header(&header_id)
            .map_err(|e| ChainHeaderReaderError::Backend {
                height,
                source: Box::new(e),
            })?
            .ok_or(ChainHeaderReaderError::NotFound(height))?;
        let mut r = VlqReader::new(&header_bytes);
        let header = read_header(&mut r).map_err(|e| ChainHeaderReaderError::Backend {
            height,
            source: format!("header decode at h={height}: {e:?}").into(),
        })?;
        Ok(HeaderView {
            votes: header.votes,
        })
    }
}

/// Build the last 10 headers preceding a block at `height` by walking
/// backward from `parent_id`. Used for CONTEXT.headers in script evaluation.
///
/// Returns headers in order: [H-1, H-2, ..., H-10] (most recent first).
/// Stops early if the chain is shorter than 10 blocks.
fn load_last_headers(
    store: &StateStore,
    parent_id: &[u8; 32],
) -> Result<Vec<CheckedHeader>, BlockProcessError> {
    let mut result = Vec::with_capacity(10);
    let mut current_id = *parent_id;

    for _ in 0..10 {
        let header_bytes = match store.get_header(&current_id)? {
            Some(b) => b,
            None => break, // chain shorter than 10
        };
        let meta = match store.get_header_meta(&current_id)? {
            Some(m) => m,
            None => break,
        };
        let checked = CheckedHeader::from_persisted_parts(
            &header_bytes,
            current_id,
            meta.pow_validity,
            meta.height,
            meta.parent_id,
            meta.timestamp,
        )?;
        let next_parent = *checked.header().parent_id.as_bytes();
        result.push(checked);

        if next_parent == [0u8; 32] {
            break; // reached genesis
        }
        current_id = next_parent;
    }

    Ok(result)
}

/// UTXO-backend block processing: load sections, validate, apply to the
/// AVL+ box arena. This is the original `process_block` body, unchanged —
/// the UTXO path stays byte-for-byte equivalent to the pre-Mode-5 code.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(block = %hex::encode(header_id), height = tracing::field::Empty))]
pub(super) fn process_block_utxo(
    store: &mut StateStore,
    header_id: &[u8; 32],
    _params: &ProtocolParams, // legacy arg; ignored — params are now sourced from
    // `store.active_params()`. Kept in the signature to avoid
    // an executor.rs callsite churn; will drop in a follow-up.
    cached_last_headers: Option<&[CheckedHeader]>,
    script_validation_checkpoint: Option<(u32, [u8; 32])>,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
    perf: Option<&BlockPerfCounters>,
    wallet_hook: Option<&dyn ergo_state::wallet::WalletApplyHook>,
) -> Result<ProcessedBlock, BlockProcessError> {
    // Build ProtocolParams from the store's in-memory cache. The
    // cache reflects the PREVIOUS epoch's params per the
    // effective-height rule: this block is validated under those
    // params; the new params from this block's extension only take
    // effect for H+1 onward.
    let active_for_this_block = ProtocolParams::from_active(store.active_params());
    let params = &active_for_this_block;
    let t_total = Instant::now();

    // 1. Load and parse header
    let t0 = Instant::now();
    let header_bytes = store
        .get_header(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let header_id_computed = *blake2b256(&header_bytes).as_bytes();
    if header_id_computed != *header_id {
        return Err(BlockProcessError::Deserialize(format!(
            "stored header_id {} does not match blake2b256 of header bytes {}",
            hex::encode(header_id),
            hex::encode(header_id_computed),
        )));
    }
    let mut r = VlqReader::new(&header_bytes);
    let header = read_header(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("header: {e:?}")))?;
    tracing::Span::current().record("height", header.height);
    let height = header.height;
    let state_root = header.state_root;
    let t_header = t0.elapsed();

    // 2. Compute expected section IDs + load/parse sections
    let t0 = Instant::now();
    let expected = ExpectedSections::from_header(
        &header_id_computed,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );

    let bt_bytes = store.get_block_section(&expected.transactions_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 102,
            modifier_id: expected.transactions_id,
        },
    )?;
    let mut r = VlqReader::new(&bt_bytes);
    let (block_txs, tx_group_elements) = read_block_transactions_with_group_elements(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("block_transactions: {e:?}")))?;

    let ext_bytes = store.get_block_section(&expected.extension_id)?.ok_or(
        BlockProcessError::SectionNotFound {
            type_id: 108,
            modifier_id: expected.extension_id,
        },
    )?;
    let mut r = VlqReader::new(&ext_bytes);
    let extension = read_extension(&mut r)
        .map_err(|e| BlockProcessError::Deserialize(format!("extension: {e:?}")))?;

    let t_sections = t0.elapsed();

    // 3. Genesis block (height 1): no parent exists.
    let parent_id = *header.parent_id.as_bytes();
    if height == 1 && parent_id == [0u8; 32] {
        store.apply_genesis(&header_id_computed, &state_root, &block_txs.transactions)?;
        return Ok(ProcessedBlock {
            header_id: header_id_computed,
            height,
            checked_header: None,
        });
    }

    // 2c. Full proofHash parity — UTXO-mode counterpart of Scala's
    // "Regenerated proofHash is not equal to the declared one" check.
    // The declared `adProofsRoot` is verified by REGENERATING the proofs:
    // the block's transactions are replayed against a scratch copy of the
    // parent AVL tree (canonical op stream — data-input lookups, removes,
    // inserts) and the prover's emitted bytes must hash exactly to the
    // declared root. A block that ships no proofs, garbage proofs, or a
    // self-consistent-but-false root/proof pair is rejected. Live mainnet
    // divergence at h1,853,301 (block 437601cd…, applied here for 697s)
    // was the no-binding version of this hole.
    //
    // The ADProofs *section* itself is pure data availability in this
    // mode: it may be absent from storage without affecting validity,
    // exactly as in digest mode's download semantics.
    let regenerated = store.regenerate_ad_proofs(&block_txs.transactions)?;
    let regenerated_root = *ergo_primitives::digest::blake2b256(&regenerated.1).as_bytes();
    if regenerated_root != *header.ad_proofs_root.as_bytes() {
        return Err(BlockProcessError::AdProofsHashMismatch {
            header_id: header_id_computed,
            declared_root: *header.ad_proofs_root.as_bytes(),
            computed_root: regenerated_root,
        });
    }

    // Voted parameters: at epoch starts, run the full
    // epoch-extension validation before constructing CheckedHeader.
    // The `&header` borrow here is fine — header is still owned at
    // this point. The resulting `voted_params_row` (the recomputed
    // active set; matches parsed for valid blocks) flows into
    // apply_block.
    let voting_length = store.voting_settings().voting_length;
    let (voted_params_row, mode2_trust_consumed): (
        Option<ergo_validation::ActiveProtocolParameters>,
        bool,
    ) = if height > 0 && height.is_multiple_of(voting_length) {
        let chain_reader = StoreChainHeaderReader { store };
        let epoch_votes = ergo_validation::compute_epoch_votes(
            &chain_reader,
            height,
            voting_length,
        )
        .map_err(|e| {
            BlockProcessError::Deserialize(format!("compute_epoch_votes at h={height}: {e}"))
        })?;
        // Mode 2 install trust path: armed by `install_snapshot_state`,
        // peeked here, consumed only AFTER apply commits. Peeking
        // (rather than taking) keeps the flag set across an in-process
        // retry if apply fails for any non-validator reason.
        let trust_extension_settings = store.is_mode2_trust_first_epoch_armed();
        let mut outcome = validate_epoch_extension(
            &extension,
            &header,
            store.active_params(),
            store.validation_settings(),
            &epoch_votes,
            store.voting_settings(),
            trust_extension_settings,
        )?;
        // When the trust path is armed, encode the trusted cumulative
        // into THIS epoch's `activated_update` so the standard
        // apply_block persistence path writes it to `voted_params` on
        // disk and the cache-fold step updates `cached_validation_settings`
        // in lockstep. Without this, the trusted cumulative would live
        // only in RAM and any restart / cache refresh / reorg would
        // recompute from disk and silently drop it across a restart,
        // cache refresh, or reorg.
        //
        // The genuine `parsed.proposed_update` (the activation that
        // technically belongs to this epoch alone) is folded INTO the
        // trusted cumulative already (parsed_cumulative_from_extension
        // includes everything up to and including this block). So
        // overwriting `activated_update` with the cumulative is a
        // lossless representation for our Mode 2 node, which has no
        // pre-snapshot history to attribute updates to.
        if trust_extension_settings {
            outcome.computed.activated_update = outcome.next_settings.update_from_initial.clone();
        }
        (Some(outcome.computed), trust_extension_settings)
    } else {
        (None, false)
    };

    let chain_state = store.chain_state();
    if height == chain_state.best_full_block_height.saturating_add(1)
        && parent_id != chain_state.best_full_block_id
    {
        return Err(BlockProcessError::ParentNotBestFull {
            parent_id,
            best_full_id: chain_state.best_full_block_id,
            best_full_height: chain_state.best_full_block_height,
        });
    }

    // 4. Build CheckedHeader for parent from persisted metadata
    let t_parent_ctx_start = Instant::now();
    let parent_bytes = store
        .get_header(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_meta = store
        .get_header_meta(&parent_id)?
        .ok_or(BlockProcessError::ParentNotFound { id: parent_id })?;
    let parent_checked = CheckedHeader::from_persisted_parts(
        &parent_bytes,
        parent_id,
        parent_meta.pow_validity,
        parent_meta.height,
        parent_meta.parent_id,
        parent_meta.timestamp,
    )?;

    // 5. Build CheckedHeader for this block from persisted metadata.
    // `from_persisted_parts` re-derives the id from `header_bytes` and
    // verifies it matches `*header_id`, which is the same guard the
    // explicit check above already performs — kept as belt-and-braces
    // since it shapes the early-return error type.
    let block_meta = store
        .get_header_meta(header_id)?
        .ok_or(BlockProcessError::HeaderNotFound { id: *header_id })?;
    let checked_header = CheckedHeader::from_persisted_parts(
        &header_bytes,
        *header_id,
        block_meta.pow_validity,
        block_meta.height,
        block_meta.parent_id,
        block_meta.timestamp,
    )?;

    // 6. Load last 10 headers for CONTEXT.headers (use cache if provided)
    let loaded_last_headers;
    let last_headers: &[CheckedHeader] = match cached_last_headers {
        Some(cached) if !cached.is_empty() => cached,
        _ => {
            loaded_last_headers = load_last_headers(store, &parent_id)?;
            &loaded_last_headers
        }
    };
    let t_parent_ctx = t_parent_ctx_start.elapsed();

    // 7. Build validation context.
    // Rules 401/402 (NiPoPoW interlinks): load the parent's extension so the
    // validator runs the strict Some/Some branch of Scala's
    // `ExtensionValidator.validateInterlinks`. The parent was applied before
    // this child, so its extension section is in-store on the normal forward
    // path. An absent section (pruned, or a deep-reorg parent) falls through to
    // `None` — Scala's recoverable `exIlUnableToValidate` (rule 413). A PRESENT
    // but undecodable section is store corruption, surfaced as a hard error,
    // never silently coerced to `None` (which would mask a real reject).
    let parent_extension =
        {
            let parent_ext_id = compute_section_id(
                TYPE_EXTENSION,
                &parent_id,
                parent_checked.header().extension_root.as_bytes(),
            );
            match store.get_block_section(&parent_ext_id)? {
                Some(bytes) => Some(read_extension(&mut VlqReader::new(&bytes)).map_err(|e| {
                    BlockProcessError::Deserialize(format!("parent extension: {e:?}"))
                })?),
                None => None,
            }
        };
    let voting_settings = store.voting_settings();
    let voting_length = voting_settings.voting_length;
    // Rule 407 soft-fork-vote state. Sourced from active_params'
    // `extra` slot ids 121 + 122 (Scala
    // `softForkVotesCollected` / `softForkStartingHeight`). Only
    // present when there's an in-progress soft-fork; `None` means
    // the rule trivially passes.
    let sf_starting_height = store.active_params().soft_fork_starting_height();
    let sf_votes_collected = store.active_params().soft_fork_votes_collected();
    // Rule 407 (`exCheckForkVote`) is soft-fork-DISABLEABLE: Scala enforces it
    // via `validateNoThrow(exCheckForkVote, ...)`, so a disabled rule 407 skips
    // `checkForkVote` entirely — no prohibited-window reject AND no
    // `softForkVotesCollected.get` throw. Gate the whole rule here: a disabled
    // 407 nulls `soft_fork_state` (the window check becomes a no-op) and the
    // hostile-table guard short-circuits to Ok.
    let rule_407_disabled = store.validation_settings().is_rule_disabled(407);
    let soft_fork_state = if rule_407_disabled {
        None
    } else {
        match (sf_starting_height, sf_votes_collected) {
            (Some(starting_height), Some(votes_collected)) if starting_height >= 0 => {
                let approved = voting_settings.soft_fork_approved(votes_collected);
                Some(ergo_validation::block::SoftForkState {
                    starting_height: starting_height as u32,
                    votes_collected,
                    voting_length: voting_settings.voting_length,
                    soft_fork_epochs: voting_settings.soft_fork_epochs,
                    activation_epochs: voting_settings.activation_epochs,
                    approved,
                })
            }
            _ => None,
        }
    };
    // Rule 407 hostile-table guard (Scala `checkForkVote` reads
    // `softForkVotesCollected.get`): a soft-fork start height with no
    // votes-collected entry (122-without-121) rejects a SoftFork-voting header.
    // The `Option<SoftForkState>` above collapses this to `None`
    // (indistinguishable from "no soft fork"), so enforce it here from the raw
    // params, before the block validator's prohibited-window check.
    ergo_validation::block::check_fork_vote_votes_collected_present(
        checked_header.header(),
        sf_starting_height,
        sf_votes_collected,
        rule_407_disabled,
    )?;
    // Rule 215 (`hdrVotesUnknown`) is soft-fork-deactivatable. Mainnet's
    // v6.0 activation disabled it (`rules_to_disable = [215, 409]`), so an
    // epoch-start header may legitimately propose downward / new-param
    // votes (e.g. block 1802240 votes -4 = MaxBlockCostDecrease). Honor
    // the activated validation settings so we don't reject canonical
    // blocks the rest of the network accepted.
    let votes_unknown_rule_disabled = store.validation_settings().is_rule_disabled(215);
    // Rule 212 (`hdrVotesNumber`, ≤2 non-soft-fork votes) is also soft-fork-
    // deactivatable; honor the activated settings here at block time (the
    // header pipeline can't see them). 213/214 already ran at header time.
    ergo_validation::header::check_votes_number_active(
        checked_header.header(),
        store.validation_settings().is_rule_disabled(212),
    )
    .map_err(ergo_validation::block::BlockValidationError::Header)?;
    let ctx = BlockValidationContext {
        parent: &parent_checked,
        utxo: store,
        params,
        voting_length,
        votes_unknown_rule_disabled,
        parent_extension: parent_extension.as_ref(),
        soft_fork_state,
        last_headers,
        script_validation_checkpoint,
        reemission,
    };

    // 8. Validate the full block (no PoW/difficulty — already validated by header pipeline)
    let t0 = Instant::now();
    let checked_block = validate_full_block_parallel_with_group_elements(
        checked_header,
        &block_txs,
        &extension,
        &ctx,
        &tx_group_elements,
    )?;
    let t_validate = t0.elapsed();
    let tx_count = checked_block.transactions().len();

    // 9. Apply to UTXO state. apply_block now derives height/header_id/
    // expected_state_root from the embedded CheckedHeader, so we don't
    // pass them separately.
    //
    let t0 = Instant::now();
    // Wallet-hook plumbing (atomicity depends on path):
    //   - sync path: chain + wallet commit inside the same redb
    //     write_txn (truly atomic).
    //   - pipeline path: chain commits durably first (flush + fsync
    //     when needed), THEN wallet commits on a separate write_txn.
    //     Two-commit, not atomic; failure mode is "wallet behind
    //     chain" (covered by rescan), not "wallet ahead of chain".
    //     Closing this seam requires pipeline-worker integration that
    //     does not yet exist.
    // Caller threads `wallet_hook` from NodeState; `None` is
    // acceptable for tests and non-wallet deployments.
    store.apply_block(&checked_block, voted_params_row, wallet_hook)?;
    if mode2_trust_consumed {
        // apply_block committed the synthetic `voted_params` row (with
        // `activated_update = trusted cumulative`) and folded it into
        // `cached_validation_settings`. Now consume the trust claim
        // — in-memory + persisted — since the trusted state is durable
        // in the standard tables and the validator's
        // `prev_settings == empty()` gate keeps any stale disk byte
        // from firing again at later epoch boundaries.
        store.consume_mode2_trust_first_epoch();
    }
    let t_apply = t0.elapsed();

    let t_total_elapsed = t_total.elapsed();

    if let Some(p) = perf {
        p.add_block(
            tx_count as u64,
            t_header.as_nanos() as u64,
            t_sections.as_nanos() as u64,
            t_parent_ctx.as_nanos() as u64,
            t_validate.as_nanos() as u64,
            t_apply.as_nanos() as u64,
            t_total_elapsed.as_nanos() as u64,
        );
    }

    if height % 1000 == 0 || height <= 5 {
        debug!(
            height,
            tx_count,
            total_ms = t_total_elapsed.as_secs_f64() * 1000.0,
            hdr_ms = t_header.as_secs_f64() * 1000.0,
            sec_ms = t_sections.as_secs_f64() * 1000.0,
            pctx_ms = t_parent_ctx.as_secs_f64() * 1000.0,
            validate_ms = t_validate.as_secs_f64() * 1000.0,
            apply_ms = t_apply.as_secs_f64() * 1000.0,
            "block apply timing"
        );
    }

    let (validated_header, _) = checked_block.into_parts();
    Ok(ProcessedBlock {
        header_id: header_id_computed,
        height,
        checked_header: Some(validated_header),
    })
}

#[cfg(test)]
mod ad_proofs_regeneration_tests {
    use super::*;
    use ergo_primitives::digest::{Digest32, ModifierId};
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::address::NetworkPrefix;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::{AdditionalRegisters, RegisterValue};
    use ergo_ser::sigma_value::read_constant;
    use ergo_state::store::StateStore;
    use std::collections::BTreeMap;

    const VEC_DIR: &str = "../test-vectors/mainnet";

    #[derive(serde::Deserialize)]
    struct GenesisBoxJson {
        #[serde(rename = "boxId")]
        _box_id: String,
        value: u64,
        #[serde(rename = "ergoTree")]
        ergo_tree: String,
        #[serde(rename = "creationHeight")]
        creation_height: u32,
        #[serde(rename = "transactionId")]
        transaction_id: String,
        index: u16,
        #[serde(rename = "additionalRegisters", default)]
        additional_registers: BTreeMap<String, String>,
    }

    fn parse_genesis_box(json: &GenesisBoxJson) -> ergo_ser::ergo_box::ErgoBox {
        let tree_bytes = hex::decode(&json.ergo_tree).unwrap();
        let mut r = VlqReader::new(&tree_bytes);
        let ergo_tree = read_ergo_tree(&mut r).unwrap();
        let mut reg_vec: Vec<(usize, RegisterValue)> = Vec::new();
        for (key, val_hex) in &json.additional_registers {
            let reg_idx = match key.as_str() {
                "R4" => 0,
                "R5" => 1,
                "R6" => 2,
                "R7" => 3,
                "R8" => 4,
                "R9" => 5,
                _ => panic!("unknown register {key}"),
            };
            let val_bytes = hex::decode(val_hex).unwrap();
            let mut vr = VlqReader::new(&val_bytes);
            let (tpe, value) = read_constant(&mut vr).unwrap();
            reg_vec.push((reg_idx, RegisterValue { tpe, value }));
        }
        reg_vec.sort_by_key(|(idx, _)| *idx);
        let registers = AdditionalRegisters {
            registers: reg_vec.into_iter().map(|(_, rv)| rv).collect(),
        };
        let candidate = ErgoBoxCandidate::new(
            json.value,
            ergo_tree,
            json.creation_height,
            Vec::new(),
            registers,
        )
        .unwrap();
        let tx_id_bytes: [u8; 32] = hex::decode(&json.transaction_id)
            .unwrap()
            .try_into()
            .unwrap();
        ergo_ser::ergo_box::ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id_bytes),
            index: json.index,
        }
    }

    /// Store at mainnet h=1: real genesis boxes + real block-1 tx applied.
    fn store_at_height_1() -> StateStore {
        let dir = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(dir.path().join("state.redb").as_path()).unwrap();
        let genesis_data =
            std::fs::read_to_string(format!("{VEC_DIR}/genesis_boxes.json")).unwrap();
        let genesis_boxes: Vec<GenesisBoxJson> = serde_json::from_str(&genesis_data).unwrap();
        let boxes: Vec<([u8; 32], Vec<u8>)> = genesis_boxes
            .iter()
            .map(|jb| {
                let b = parse_genesis_box(jb);
                let id = *b.box_id().unwrap().as_bytes();
                (id, serialize_ergo_box(&b).unwrap())
            })
            .collect();
        store.initialize_genesis(&boxes).unwrap();

        // Apply real mainnet block 1 so the tree matches the chain at h=1.
        let tx_data: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(format!("{VEC_DIR}/transactions_1_10.json")).unwrap(),
        )
        .unwrap();
        let digests_data: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(format!("{VEC_DIR}/utxo_digests_1_10.json")).unwrap(),
        )
        .unwrap();
        let tx1_hex = tx_data
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == 1)
            .unwrap()["bytes"]
            .as_str()
            .unwrap()
            .to_string();
        let digest1: [u8; 33] = {
            let d = digests_data
                .iter()
                .find(|d| d["height"].as_u64().unwrap() == 1)
                .unwrap();
            hex::decode(d["stateRoot"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let headers: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(format!("{VEC_DIR}/headers_1_2000.json")).unwrap(),
        )
        .unwrap();
        let h1_entry = headers
            .iter()
            .find(|x| x["height"].as_u64() == Some(1))
            .unwrap();
        let h1_bytes = hex::decode(h1_entry["bytes"].as_str().unwrap()).unwrap();
        let h1_id = *blake2b256(&h1_bytes).as_bytes();
        let tx1 = read_transaction_from_hex(&tx1_hex);
        store
            .apply_block_unchecked_for_test(
                1,
                &h1_id,
                &ergo_primitives::digest::ADDigest::from_bytes(digest1),
                &[tx1],
            )
            .unwrap();
        // Keep the tempdir alive for the store's lifetime via leak-by-forget
        // semantics is unnecessary: StateStore owns its redb handle and the
        // dir only needs to outlive `store`, which it does within this scope.
        drop(dir); // redb file already opened; deletion deferred to scope end
        store
    }

    fn read_transaction_from_hex(hex_str: &str) -> ergo_ser::transaction::Transaction {
        let bytes = hex::decode(hex_str).unwrap();
        ergo_ser::transaction::read_transaction(&mut VlqReader::new(&bytes)).unwrap()
    }

    fn header_at(height: u64) -> ergo_ser::header::Header {
        let headers: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(format!("{VEC_DIR}/headers_1_2000.json")).unwrap(),
        )
        .unwrap();
        let entry = headers
            .iter()
            .find(|x| x["height"].as_u64() == Some(height))
            .unwrap();
        let bytes = hex::decode(entry["bytes"].as_str().unwrap()).unwrap();
        read_header(&mut VlqReader::new(&bytes)).unwrap()
    }

    fn tx_at(height: u64) -> ergo_ser::transaction::Transaction {
        let tx_data: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(format!("{VEC_DIR}/transactions_1_10.json")).unwrap(),
        )
        .unwrap();
        let hex_str = tx_data
            .iter()
            .find(|t| t["height"].as_u64().unwrap() == height)
            .unwrap()["bytes"]
            .as_str()
            .unwrap();
        read_transaction_from_hex(hex_str)
    }

    #[test]
    fn regenerated_proof_hash_matches_mainnet_declared_root() {
        // The full-parity oracle: replaying block 2's txs against the real
        // h=1 tree must emit proof bytes whose blake2b256 equals the root
        // mainnet declared in header 2. This is exactly what
        // process_block_utxo now enforces on every block.
        let store = store_at_height_1();
        let h2 = header_at(2);
        let tx2 = tx_at(2);

        let (_new_root, proof_bytes) = store.regenerate_ad_proofs(&[tx2]).unwrap();
        let computed = *blake2b256(&proof_bytes).as_bytes();
        assert_eq!(
            computed,
            *h2.ad_proofs_root.as_bytes(),
            "regenerated proofHash must equal mainnet's declared adProofsRoot"
        );
    }

    #[test]
    fn tampered_transaction_changes_regenerated_hash() {
        // A mutated tx produces different AVL operations ⇒ a different
        // proofHash ⇒ the declared root no longer binds. This is the exact
        // property that makes forged receipt/seal pairs impossible.
        let store = store_at_height_1();
        let h2 = header_at(2);
        let mut tx2 = tx_at(2);
        tx2.output_candidates[0].value += 1;

        let (_new_root, proof_bytes) = store.regenerate_ad_proofs(&[tx2]).unwrap();
        let computed = *blake2b256(&proof_bytes).as_bytes();
        assert_ne!(computed, *h2.ad_proofs_root.as_bytes());
        let _ = NetworkPrefix::Mainnet; // keep import honest if unused above
        let _ = Digest32::from_bytes([0u8; 32]);
    }
}

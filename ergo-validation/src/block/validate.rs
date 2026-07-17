use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_primitives::cost::{CostAccumulator, JitCost};
use ergo_ser::block_transactions::BlockTransactions;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::extension::Extension;
use rayon::prelude::*;

use crate::context::{TransactionContext, UtxoView};
use crate::error::ValidationError;
use crate::header::CheckedHeader;
use crate::tx::{
    validate_transaction_parsed, validate_transaction_parsed_with_group_elements,
    CheckedTransaction,
};

use super::extension::validate_extension_structural;
use super::fork_vote::validate_fork_vote;
use super::interlinks::validate_interlinks;
use super::layering::{build_tx_layers, TxLayerInput, TxLayerResult};
use super::overlay::BlockUtxoOverlay;
use super::size::check_block_transactions_size;
use super::{BlockValidationContext, BlockValidationError, CheckedBlock};

/// Validate a full block: section linkage + tx root + ext root + all txs.
///
/// The header is accepted as a [`CheckedHeader`], constructed either via
/// `validate_header()` (during header sync) or `from_persisted_parts()`
/// (during block processing). PoW/difficulty validation is NOT repeated here.
///
/// Returns a [`CheckedBlock`] whose header and transactions are bound
/// together — state application via `StateStore::apply_block` derives
/// height/header_id/state_root from the embedded header, closing the old
/// hole where caller-supplied height could drift from the validated
/// header.
#[tracing::instrument(
    name = "validate_block",
    level = "debug",
    skip_all,
    fields(
        height = checked_header.height(),
        header_id = %hex::encode(checked_header.header_id()),
        n_txs = block_transactions.transactions.len(),
    ),
)]
// Sequential variant retained for differential / regression
// testing against the parallel path. Production uses
// `validate_full_block_parallel` from `ergo-sync::block_proc`;
// gating this behind `test-helpers` keeps the public surface
// narrow without losing cross-validation coverage in the test
// crates.
#[cfg(any(test, feature = "test-helpers"))]
pub fn validate_full_block(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<CheckedBlock, BlockValidationError> {
    let header = checked_header.header();
    let header_id = checked_header.header_id();

    // Checkpoint enforcement (matches Scala mainnet.conf ergo.node.checkpoint).
    // At exactly the configured height, the observed header_id MUST equal
    // the configured block_id — this is the single point of trust that
    // protects every block below the checkpoint from a chain-switch attack.
    let skip_scripts = match ctx.script_validation_checkpoint {
        Some((ckpt_h, ckpt_id)) => {
            if header.height == ckpt_h && header_id != &ckpt_id {
                return Err(BlockValidationError::CheckpointMismatch {
                    height: ckpt_h,
                    expected: ckpt_id,
                    got: *header_id,
                });
            }
            header.height <= ckpt_h
        }
        None => false,
    };

    // 2. Section-to-header linkage
    if block_transactions.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "BlockTransactions",
            expected: *header_id,
            got: *block_transactions.header_id.as_bytes(),
        });
    }
    if extension.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "Extension",
            expected: *header_id,
            got: *extension.header_id.as_bytes(),
        });
    }

    // 2.5. Header vote-known check (Scala rule 215). Fires only on
    // epoch-start headers; off-epoch headers no-op. Skipped entirely
    // when an activated soft-fork has disabled the rule
    // (`ctx.votes_unknown_rule_disabled`) — mainnet did so at v6.0.
    // Block-level because `voting_length` is a chain config carried on
    // the validation context. Wired into
    // `validate_full_block_parallel_impl` too — keep both paths in sync.
    crate::header::check_votes_known_active(
        header,
        ctx.voting_length,
        ctx.votes_unknown_rule_disabled,
    )
    .map_err(BlockValidationError::Header)?;

    // 2.6. Fork-vote prohibited-window check (Scala rule 407).
    // No-op when no soft-fork is in progress (ctx.soft_fork_state
    // is None) OR when the header doesn't cast a SoftFork vote.
    validate_fork_vote(header, ctx.soft_fork_state.as_ref())?;

    // 3. Transactions root
    let txs = &block_transactions.transactions;
    let mut tx_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let bts = ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::Deserialization(format!("bytes_to_sign: {e}")),
            }
        })?;
        tx_ids.push(ergo_crypto::autolykos::common::blake2b256(&bts).to_vec());
    }
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let witness_data: Vec<Vec<u8>>;
    let witness_refs: Option<Vec<&[u8]>>;
    if header.version >= 2 {
        witness_data = txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                let hash = ergo_crypto::autolykos::common::blake2b256(&all_proofs);
                hash[1..].to_vec() // 31 bytes: drop first byte
            })
            .collect();
        let refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
        witness_refs = Some(refs);
    } else {
        witness_refs = None;
    }

    let computed_tx_root = transactions_root(&tx_id_refs, witness_refs.as_deref());
    if computed_tx_root != *header.transactions_root.as_bytes() {
        return Err(BlockValidationError::TransactionsRootMismatch {
            expected: *header.transactions_root.as_bytes(),
            computed: computed_tx_root,
        });
    }

    // 4. Extension root
    let ext_fields: Vec<(&[u8], &[u8])> = extension
        .fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_ext_root = extension_root(&ext_fields);
    if computed_ext_root != *header.extension_root.as_bytes() {
        return Err(BlockValidationError::ExtensionRootMismatch {
            expected: *header.extension_root.as_bytes(),
            computed: computed_ext_root,
        });
    }

    // 4a. Structural extension checks (rules 400, 404, 405, 406).
    // Runs AFTER the merkle-root recompute so an adversarial unbound
    // extension can't force the O(N²) duplicate scan as a DoS — the
    // root match cryptographically binds the extension to the header
    // before we walk its fields.
    validate_extension_structural(extension, header.height)?;

    // 4a.5. Interlink validation (rules 401, 402). Skipped when the
    // parent extension isn't on the context — that's Scala's
    // `exIlUnableToValidate` recoverable path. Production callers
    // wire `parent_extension` from the store for the consensus-path
    // enforcement; pre-NiPoPoW or genesis paths pass `None`.
    if let Some(parent_ext) = ctx.parent_extension {
        validate_interlinks(extension, ctx.parent.header(), parent_ext)?;
    }

    // 4b. Block-transactions section size (rule 306).
    // Same defensive ordering as 4a: runs AFTER the transactions
    // root recompute so an unbound oversized payload can't force
    // the re-serialize work as a DoS vector. Mirrors Scala's order
    // at `ErgoStateContext.appendFullBlock:308-310` (extension
    // validation → block-tx-size → ex-size).
    check_block_transactions_size(
        block_transactions,
        header.version,
        ctx.params.max_block_size,
    )?;

    // 5. Per-tx validation with intra-block UTXO overlay
    // Extract raw headers for the tx validation layer (which takes &[Header]).
    let raw_last_headers: Vec<ergo_ser::header::Header> = ctx
        .last_headers
        .iter()
        .map(|ch| ch.header().clone())
        .collect();
    let tx_ctx = TransactionContext {
        height: header.height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: *header.parent_id.as_bytes(),
        pre_header_n_bits: header.n_bits as u64,
        pre_header_votes: header.votes,
    };

    let mut overlay = BlockUtxoOverlay::new(ctx.utxo);
    let mut checked_txs = Vec::with_capacity(txs.len());
    let mut total_block_cost: u64 = 0;

    for (i, tx) in txs.iter().enumerate() {
        let tx_bytes = {
            let mut w = ergo_primitives::writer::VlqWriter::new();
            ergo_ser::transaction::write_transaction(&mut w, tx).map_err(|e| {
                BlockValidationError::Transaction {
                    index: i,
                    error: ValidationError::Deserialization(e.to_string()),
                }
            })?;
            w.result()
        };

        // Resolve inputs from overlay (respects intra-block spending)
        let resolved_inputs: Vec<ErgoBox> = tx
            .inputs
            .iter()
            .map(|inp| {
                overlay
                    .get_box(&inp.box_id)
                    .ok_or_else(|| BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::InputBoxNotFound {
                            box_id: hex::encode(inp.box_id.as_bytes()),
                        },
                    })
            })
            .collect::<Result<_, _>>()?;

        // Resolve data inputs through `BlockUtxoOverlay::get_box_from_base`,
        // which returns the union of pre-block UTXO + intra-block creates
        // without filtering on `spent_in_block`. See the helper's rustdoc
        // for the mainnet oracle evidence (blocks 290684 + 422179).
        let resolved_data_inputs: Vec<ErgoBox> = tx
            .data_inputs
            .iter()
            .map(|di| {
                overlay.get_box_from_base(&di.box_id).ok_or_else(|| {
                    BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::DataInputBoxNotFound {
                            box_id: hex::encode(di.box_id.as_bytes()),
                        },
                    }
                })
            })
            .collect::<Result<_, _>>()?;

        let block_cap = JitCost::from_block_cost(ctx.params.max_block_cost).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::JitCostOverflow(e.to_string()),
            }
        })?;
        let mut cost = CostAccumulator::new(block_cap);

        let mut tx_cx = crate::tx::TxValidationCtx {
            ctx: &tx_ctx,
            params: ctx.params,
            cost: &mut cost,
            last_headers: &raw_last_headers,
            // EIP-27 re-emission is enforced inside the tx validator (Scala
            // `validateStateful`), so it covers every caller uniformly.
            rules: crate::tx::TxValidationRules {
                reemission: ctx.reemission,
            },
        };
        let checked = validate_transaction_parsed(
            tx.clone(),
            &tx_bytes,
            resolved_inputs,
            resolved_data_inputs,
            skip_scripts,
            &mut tx_cx,
        )
        .map_err(|e| BlockValidationError::Transaction { index: i, error: e })?;

        total_block_cost += cost.total_block_cost();
        overlay.apply_tx(checked.transaction());
        checked_txs.push(checked);
    }

    if total_block_cost > ctx.params.max_block_cost {
        return Err(BlockValidationError::BlockCostExceeded {
            total: total_block_cost,
            limit: ctx.params.max_block_cost,
        });
    }

    Ok(CheckedBlock {
        checked_header,
        checked_transactions: checked_txs,
    })
}

/// Parallel equivalent of [`validate_full_block`]: topologically layers the
/// block's transactions by intra-block dependency, then validates each layer
/// via `rayon::par_iter`. Identical output to the sequential path for any
/// block the sequential path accepts (and for every rejection — first-failing
/// tx by index wins, matching Scala's error-order semantics).
///
/// Consensus invariants held constant across both paths:
/// - Per-tx structural / monetary / script validation is untouched — same
///   `validate_transaction_parsed` call, same `CostAccumulator`, same
///   `TransactionContext`.
/// - Section-id linkage + merkle-root checks are performed identically and
///   up-front, before any per-tx work.
/// - Total block cost is summed from per-tx totals after all layers finish;
///   `max_block_cost` comparison is the exact same inequality.
/// - Returned `CheckedBlock.transactions()` is ordered by original tx index,
///   so downstream AVL application mutates the UTXO tree in consensus order.
/// - Intra-block double-spend (two txs listing the same input box_id) is
///   rejected up front via `build_tx_layers` rather than being caught
///   implicitly by the sequential overlay's spent-set.
///
/// Only difference visible to callers: errors report the first-by-index
/// failing tx, which matches sequential behavior. If two txs in the same
/// layer fail concurrently, the lower tx index is reported (deterministic).
fn validate_full_block_parallel_impl(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
    mut costs_out: Option<&mut Vec<(usize, u64)>>,
    // Per-tx group-element points, index-aligned with
    // `block_transactions.transactions`, collected at the block deserialize so
    // the curve-check needn't re-parse each tx. `None` ⇒ each tx re-parses its
    // own bytes to collect them (the backward-compatible path).
    group_elements: Option<&[Vec<[u8; 33]>]>,
) -> Result<CheckedBlock, BlockValidationError> {
    let header = checked_header.header();
    let header_id = checked_header.header_id();

    // The points (when supplied) must be 1:1 with the transactions. The
    // production caller guarantees this (same parse), so a mismatch is a caller
    // bug: assert it in debug, and degrade safely below via `.get(i)` (a missing
    // index falls back to re-parsing that tx's points — correct, just slower —
    // so a wiring error can never bypass or misapply the curve-check).
    debug_assert!(
        group_elements.is_none_or(|ge| ge.len() == block_transactions.transactions.len()),
        "per-tx group_elements must be index-aligned with transactions",
    );

    // Checkpoint enforcement — see validate_full_block for invariant doc.
    let skip_scripts = match ctx.script_validation_checkpoint {
        Some((ckpt_h, ckpt_id)) => {
            if header.height == ckpt_h && header_id != &ckpt_id {
                return Err(BlockValidationError::CheckpointMismatch {
                    height: ckpt_h,
                    expected: ckpt_id,
                    got: *header_id,
                });
            }
            header.height <= ckpt_h
        }
        None => false,
    };

    // Section linkage + merkle roots — identical to sequential path.
    // Kept inline rather than factored so the sequential path is not
    // coupled to the parallel path's later structure.
    if block_transactions.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "BlockTransactions",
            expected: *header_id,
            got: *block_transactions.header_id.as_bytes(),
        });
    }
    if extension.header_id.as_bytes() != header_id {
        return Err(BlockValidationError::SectionIdMismatch {
            section: "Extension",
            expected: *header_id,
            got: *extension.header_id.as_bytes(),
        });
    }

    // 2.5. Header vote-known check (Scala rule 215). Same step as
    // sequential `validate_full_block`; keep both paths in sync. Skipped
    // when an activated soft-fork disabled the rule.
    crate::header::check_votes_known_active(
        header,
        ctx.voting_length,
        ctx.votes_unknown_rule_disabled,
    )
    .map_err(BlockValidationError::Header)?;

    // 2.6. Fork-vote prohibited-window check (Scala rule 407).
    // Mirror of sequential step 2.6.
    validate_fork_vote(header, ctx.soft_fork_state.as_ref())?;

    let txs = &block_transactions.transactions;
    let mut tx_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        let bts = ergo_ser::transaction::bytes_to_sign(tx).map_err(|e| {
            BlockValidationError::Transaction {
                index: i,
                error: ValidationError::Deserialization(format!("bytes_to_sign: {e}")),
            }
        })?;
        tx_ids.push(ergo_crypto::autolykos::common::blake2b256(&bts).to_vec());
    }
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let witness_data: Vec<Vec<u8>>;
    let witness_refs: Option<Vec<&[u8]>>;
    if header.version >= 2 {
        witness_data = txs
            .iter()
            .map(|tx| {
                let mut all_proofs = Vec::new();
                for input in &tx.inputs {
                    all_proofs.extend_from_slice(&input.spending_proof.proof);
                }
                let hash = ergo_crypto::autolykos::common::blake2b256(&all_proofs);
                hash[1..].to_vec()
            })
            .collect();
        let refs: Vec<&[u8]> = witness_data.iter().map(|w| w.as_slice()).collect();
        witness_refs = Some(refs);
    } else {
        witness_refs = None;
    }

    let computed_tx_root = transactions_root(&tx_id_refs, witness_refs.as_deref());
    if computed_tx_root != *header.transactions_root.as_bytes() {
        return Err(BlockValidationError::TransactionsRootMismatch {
            expected: *header.transactions_root.as_bytes(),
            computed: computed_tx_root,
        });
    }

    let ext_fields: Vec<(&[u8], &[u8])> = extension
        .fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_ext_root = extension_root(&ext_fields);
    if computed_ext_root != *header.extension_root.as_bytes() {
        return Err(BlockValidationError::ExtensionRootMismatch {
            expected: *header.extension_root.as_bytes(),
            computed: computed_ext_root,
        });
    }

    // 4a. Structural extension checks (rules 400/404/405/406) +
    // 4a.5. interlink validation (rules 401/402) +
    // 4b. block-transactions section size (rule 306).
    // Mirrors the sequential path's steps 4a/4a.5/4b; both must run
    // here too because production routes can switch between the
    // sequential and parallel impls at any height. Same defensive
    // post-merkle ordering: the root match has cryptographically
    // bound the bytes to the header, so an unbound adversarial
    // payload can't trip the O(N²) duplicate scan / re-serialize
    // walks as a DoS vector.
    validate_extension_structural(extension, header.height)?;
    if let Some(parent_ext) = ctx.parent_extension {
        validate_interlinks(extension, ctx.parent.header(), parent_ext)?;
    }
    check_block_transactions_size(
        block_transactions,
        header.version,
        ctx.params.max_block_size,
    )?;

    // Layered parallel tx validation
    let layering = build_tx_layers(txs)?;

    let raw_last_headers: Vec<ergo_ser::header::Header> = ctx
        .last_headers
        .iter()
        .map(|ch| ch.header().clone())
        .collect();
    let tx_ctx = TransactionContext {
        height: header.height,
        miner_pubkey: *header.solution.pk().as_bytes(),
        pre_header_timestamp: header.timestamp,
        activated_script_version: header.version.saturating_sub(1),
        pre_header_version: header.version,
        pre_header_parent_id: *header.parent_id.as_bytes(),
        pre_header_n_bits: header.n_bits as u64,
        pre_header_votes: header.votes,
    };

    let mut overlay = BlockUtxoOverlay::new(ctx.utxo);
    let mut checked_slots: Vec<Option<CheckedTransaction>> = (0..txs.len()).map(|_| None).collect();
    let mut total_block_cost: u64 = 0;

    for layer in &layering.layers {
        // Step 1: resolve inputs + serialize tx_bytes serially. The overlay
        // is mutated between layers, so its lookup must stay single-threaded.
        // Only the CPU-heavy validation (structural/monetary/script eval)
        // is dispatched to rayon.
        let mut per_tx_inputs: Vec<TxLayerInput> = Vec::with_capacity(layer.len());
        for &i in layer {
            let tx = &txs[i];
            let tx_bytes = {
                let mut w = ergo_primitives::writer::VlqWriter::new();
                ergo_ser::transaction::write_transaction(&mut w, tx).map_err(|e| {
                    BlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::Deserialization(e.to_string()),
                    }
                })?;
                w.result()
            };
            let resolved_inputs: Vec<ErgoBox> = tx
                .inputs
                .iter()
                .map(|inp| {
                    overlay
                        .get_box(&inp.box_id)
                        .ok_or_else(|| BlockValidationError::Transaction {
                            index: i,
                            error: ValidationError::InputBoxNotFound {
                                box_id: hex::encode(inp.box_id.as_bytes()),
                            },
                        })
                })
                .collect::<Result<_, _>>()?;
            let resolved_data_inputs: Vec<ErgoBox> = tx
                .data_inputs
                .iter()
                .map(|di| {
                    overlay.get_box_from_base(&di.box_id).ok_or_else(|| {
                        BlockValidationError::Transaction {
                            index: i,
                            error: ValidationError::DataInputBoxNotFound {
                                box_id: hex::encode(di.box_id.as_bytes()),
                            },
                        }
                    })
                })
                .collect::<Result<_, _>>()?;
            per_tx_inputs.push((i, tx_bytes, resolved_inputs, resolved_data_inputs));
        }

        // Step 2: validate_transaction_parsed in parallel. Each closure owns
        // its inputs and runs independently — they cannot reach each other's
        // state. Per-tx CostAccumulator stays local and is folded post-join.
        let max_block_cost = ctx.params.max_block_cost;
        let params = ctx.params;
        let raw_headers_ref = &raw_last_headers;
        let tx_ctx_ref = &tx_ctx;
        // `Option<&_>` is Copy — capture it into each parallel closure and
        // thread it through the per-tx validator's rule bundle.
        let reemission = ctx.reemission;
        let layer_results: Vec<TxLayerResult> = per_tx_inputs
            .into_par_iter()
            .map(|(i, tx_bytes, inputs, data_inputs)| {
                let block_cap = match JitCost::from_block_cost(max_block_cost) {
                    Ok(c) => c,
                    Err(e) => return (i, Err(ValidationError::JitCostOverflow(e.to_string()))),
                };
                let mut cost = CostAccumulator::new(block_cap);
                let mut tx_cx = crate::tx::TxValidationCtx {
                    ctx: tx_ctx_ref,
                    params,
                    cost: &mut cost,
                    last_headers: raw_headers_ref,
                    rules: crate::tx::TxValidationRules { reemission },
                };
                // Pre-collected points (from the block deserialize) skip the
                // per-tx re-parse; borrowed (not cloned) and indexed here.
                // `.get(i)` (not `[i]`) degrades safely to the re-parse path if
                // the slice is missing/mis-sized, rather than panicking.
                let result = match group_elements.and_then(|ge| ge.get(i)) {
                    Some(ge) => validate_transaction_parsed_with_group_elements(
                        txs[i].clone(),
                        &tx_bytes,
                        ge,
                        inputs,
                        data_inputs,
                        skip_scripts,
                        &mut tx_cx,
                    ),
                    None => validate_transaction_parsed(
                        txs[i].clone(),
                        &tx_bytes,
                        inputs,
                        data_inputs,
                        skip_scripts,
                        &mut tx_cx,
                    ),
                };
                match result {
                    Ok(checked) => (i, Ok((checked, cost.total_block_cost()))),
                    Err(e) => (i, Err(e)),
                }
            })
            .collect();

        // Step 3: deterministic error ordering + commit. Layer members
        // are already sorted ascending by tx index in `build_tx_layers`,
        // and par_iter preserves input order in collect, so iterating
        // `layer_results` is ascending. First Err wins — matches the
        // sequential path's early-return on first failing tx (Scala
        // parity). The owned `ValidationError` is taken directly from
        // the parallel result, not reconstructed by re-running the
        // failing tx through a second validator instance.
        let mut successes: Vec<(usize, CheckedTransaction, u64)> =
            Vec::with_capacity(layer_results.len());
        for (i, outcome) in layer_results {
            match outcome {
                Ok((checked, cost)) => successes.push((i, checked, cost)),
                Err(error) => {
                    return Err(BlockValidationError::Transaction { index: i, error });
                }
            }
        }

        // Step 4: commit successful layer results. Overlay.apply_tx is
        // deterministic — applied in ascending tx index, matching the
        // sequential path's commit order.
        for (i, checked, tx_cost) in successes {
            total_block_cost += tx_cost;
            overlay.apply_tx(checked.transaction());
            checked_slots[i] = Some(checked);
            if let Some(ref mut v) = costs_out {
                v.push((i, tx_cost));
            }
        }
    }

    if total_block_cost > ctx.params.max_block_cost {
        return Err(BlockValidationError::BlockCostExceeded {
            total: total_block_cost,
            limit: ctx.params.max_block_cost,
        });
    }

    let checked_txs: Vec<CheckedTransaction> = checked_slots
        .into_iter()
        .map(|opt| {
            opt.expect("every tx index must have a validated slot after successful layering")
        })
        .collect();

    Ok(CheckedBlock {
        checked_header,
        checked_transactions: checked_txs,
    })
}

/// Parallel variant of [`validate_full_block`]. Per-transaction
/// validation runs across rayon worker threads after the structural
/// (root / linkage / layering) checks have passed; output is the same
/// [`CheckedBlock`] type, so callers can use either entry point
/// interchangeably.
pub fn validate_full_block_parallel(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<CheckedBlock, BlockValidationError> {
    validate_full_block_parallel_impl(
        checked_header,
        block_transactions,
        extension,
        ctx,
        None,
        None,
    )
}

/// Like [`validate_full_block_parallel`], but the caller supplies the per-tx
/// group-element points (collected once at the block deserialize, index-aligned
/// with `block_transactions.transactions`). This lets per-tx validation
/// curve-check group elements without re-deserializing each transaction — the
/// production block-processing entry point. A mis-sized slice degrades to the
/// re-parse path per transaction, so it can never bypass the curve-check.
pub fn validate_full_block_parallel_with_group_elements(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
    group_elements: &[Vec<[u8; 33]>],
) -> Result<CheckedBlock, BlockValidationError> {
    validate_full_block_parallel_impl(
        checked_header,
        block_transactions,
        extension,
        ctx,
        None,
        Some(group_elements),
    )
}

/// Parallel full-block validation returning per-tx costs indexed by tx
/// position. Only available under `test-helpers` for differential testing.
#[cfg(feature = "test-helpers")]
pub fn validate_full_block_parallel_with_costs(
    checked_header: CheckedHeader,
    block_transactions: &BlockTransactions,
    extension: &Extension,
    ctx: &BlockValidationContext<'_>,
) -> Result<(CheckedBlock, Vec<(usize, u64)>), BlockValidationError> {
    let mut costs = Vec::new();
    validate_full_block_parallel_impl(
        checked_header,
        block_transactions,
        extension,
        ctx,
        Some(&mut costs),
        None,
    )
    .map(|block| (block, costs))
}

//! Inline input-block transaction validation (spec 6.4, 9.2 step 6).
//!
//! The processor never validates: it emits `Effect::Validate` and waits
//! for `Event::ValidationResult`. In M2 the node answers that
//! synchronously on the action loop, against the committed UTXO snapshot
//! of the best full block at that moment.
//!
//! The context is the sharp part. Scala validates input-block
//! transactions with the state's EXISTING `stateContext` — the context
//! AFTER the last applied full block `B`, not an "upcoming" context for
//! `B+1`. So this is deliberately NOT `tip_context::build_tip_context`,
//! which builds `B+1` for mempool admission: `height` is `B.height`, the
//! pre-header fields come from `B`, and `last_headers` is Scala's
//! `lastHeaders.drop(1)` — the 9 headers BEFORE `B`.

use ergo_inputblocks::processor::{JobId, ValidationOutcome};
use ergo_inputblocks::types::{InputBlockId, TxRef};
use ergo_ser::header::Header;
use ergo_ser::transaction::Transaction;
use ergo_state::ChainStateRead;
use ergo_validation::input_block::{validate_input_block_transactions, InputBlockTxBytes};
use ergo_validation::tx::TxValidationRules;
use ergo_validation::{ProtocolParams, TransactionContext};

use super::super::NodeState;
use super::runtime::InputBlocksRuntime;

/// The `Effect::Validate` payload, in the node's own shape.
#[derive(Debug, Clone)]
pub(in crate::node) struct ValidateJob {
    pub(in crate::node) job: JobId,
    pub(in crate::node) generation: u64,
    pub(in crate::node) input_block_id: InputBlockId,
    /// The block's own bodies, in announced order.
    pub(in crate::node) txs: Vec<TxRef>,
    /// Bodies of the already-processed chain prefix.
    pub(in crate::node) previous: Vec<TxRef>,
}

/// The spec-6.4 validation context: everything `validate_input_block_transactions`
/// needs except the box view and the bodies.
pub(in crate::node) struct InputBlockContext {
    pub(in crate::node) tx_context: TransactionContext,
    pub(in crate::node) params: ProtocolParams,
    /// Scala `sigmaLastHeaders` = `lastHeaders.drop(1)`: the headers
    /// BEFORE `B`, newest first.
    pub(in crate::node) last_headers: Vec<Header>,
}

/// Build the spec-6.4 context from the best full block `B`.
/// `None` while the recent-headers window is cold (no full block applied).
pub(in crate::node) fn build_input_block_context(state: &NodeState) -> Option<InputBlockContext> {
    let ctx_headers = state.executor.block_context_headers();
    let best = ctx_headers.first()?.header();
    let tx_context = TransactionContext {
        // Scala `currentHeight = sigmaPreHeader.height`, and the
        // pre-header IS `B` — so the height is B's, NOT B+1's.
        height: best.height,
        miner_pubkey: *best.solution.pk().as_bytes(),
        pre_header_timestamp: best.timestamp,
        // Scala `activatedScriptVersion = blockVersion - 1`; `exBlockVersion`
        // pins `blockVersion == header.version` for every accepted block,
        // so B's header version is an equivalent source (same derivation
        // `tip_context` documents).
        activated_script_version: best.version.saturating_sub(1),
        pre_header_version: best.version,
        pre_header_parent_id: *best.parent_id.as_bytes(),
        pre_header_n_bits: u64::from(best.n_bits),
        pre_header_votes: best.votes,
    };
    Some(InputBlockContext {
        tx_context,
        params: ProtocolParams::from_active(state.store.active_params()),
        last_headers: ctx_headers
            .iter()
            .skip(1)
            .map(|ch| ch.header().clone())
            .collect(),
    })
}

/// Run one validation job and report what the node concluded, for the
/// processor to feed back as `Event::ValidationResult`.
///
/// Reasons are STRINGS, not error types: the processor treats them as
/// opaque telemetry. What it does NOT treat as opaque is the arm — an
/// [`ValidationOutcome::Invalid`] verdict retires the combination and
/// charges the block's retry budget, an [`ValidationOutcome::Unavailable`]
/// node-local condition does neither. Anything this node cannot answer —
/// no UTXO set, no applied full block, a body that left the cache — is
/// `Unavailable`, so a later event can re-offer the same combination.
pub(in crate::node) fn run_validation(
    state: &NodeState,
    rt: &InputBlocksRuntime,
    job: &ValidateJob,
) -> ValidationOutcome {
    // Input blocks need a UTXO set (Scala `processInputBlock` refuses in
    // digest mode). The config gate already forbids it, but the runtime
    // must not assume a gate it does not own.
    let Some(utxo) = state.store.as_utxo() else {
        return ValidationOutcome::Unavailable(
            "DigestMode: no UTXO set to validate against".to_string(),
        );
    };

    let previous: Vec<Transaction> = match collect(rt, &job.previous, "previous") {
        Ok(v) => v,
        Err(reason) => return ValidationOutcome::Unavailable(reason),
    };
    let own: Vec<(Transaction, std::sync::Arc<[u8]>)> = match job
        .txs
        .iter()
        .map(|r| {
            rt.processor()
                .body(r)
                .map(|b| (b.tx.clone(), b.bytes.clone()))
                .ok_or_else(|| format!("CacheEvicted: body {} missing", hex::encode(r.tx_id)))
        })
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(reason) => return ValidationOutcome::Unavailable(reason),
    };

    // Node-local and transient: the node has not applied a full block
    // yet, so there is no context to evaluate scripts against. This says
    // nothing about the block, so it must NOT reach the processor as a
    // verdict — see `ValidationOutcome::Unavailable`.
    let Some(ctx) = build_input_block_context(state) else {
        return ValidationOutcome::Unavailable(
            "TipUnready: no applied full block to validate against".to_string(),
        );
    };

    let txs: Vec<InputBlockTxBytes<'_>> = own
        .iter()
        .map(|(tx, bytes)| InputBlockTxBytes { bytes, tx })
        .collect();
    let previous_refs: Vec<&Transaction> = previous.iter().collect();

    match validate_input_block_transactions(
        &txs,
        &previous_refs,
        utxo,
        &ctx.tx_context,
        &ctx.params,
        &ctx.last_headers,
        TxValidationRules {
            reemission: state.executor.reemission_rules(),
            // Spec 6.4 / 2.6: soft fields are unavailable to input-block
            // transactions — a script reading them must fail here so the
            // miner never seats it in an input block.
            soft_fields_allowed: false,
        },
    ) {
        Ok(cost) => ValidationOutcome::Valid(cost),
        Err(e) => ValidationOutcome::Invalid(format!("{}: {e}", job_label(&job.input_block_id))),
    }
}

fn collect(
    rt: &InputBlocksRuntime,
    refs: &[TxRef],
    which: &'static str,
) -> Result<Vec<Transaction>, String> {
    refs.iter()
        .map(|r| {
            rt.processor().body(r).map(|b| b.tx.clone()).ok_or_else(|| {
                format!(
                    "CacheEvicted: {which} body {} missing",
                    hex::encode(r.tx_id)
                )
            })
        })
        .collect()
}

fn job_label(id: &InputBlockId) -> String {
    format!("input block {}", hex::encode(id))
}

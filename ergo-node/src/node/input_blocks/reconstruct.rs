//! Ordering-block reconstruction (spec 9.3, Scala `processOrderingBlock`).
//!
//! An ordering-block announcement carries everything a node that already
//! holds the input chain needs to rebuild the block's transaction
//! section itself, instead of downloading it: the transactions the miner
//! did not broadcast, the ids of the ones it did, and — through the
//! processor — the input blocks the ordering block builds on.
//!
//! This module turns the processor's [`ReconstructionPlan`] into the
//! node actions that hand that section to the ORDINARY block pipeline:
//!
//! 1. `ValidateHeader` with the announcement's header bytes, when the
//!    store does not have the header yet;
//! 2. `PersistSection { section_type: 108 }` with the extension built
//!    from the announcement's `extension_fields`, when the store lacks it;
//! 3. `PersistSection { section_type: 102 }` with the rebuilt
//!    `BlockTransactions`, then `AssembleBlock` — the executor runs full
//!    block validation from there, so a bad reconstruction is rejected by
//!    the ordinary invalid-block path and needs no special handling here.
//!
//! Steps 1 and 2 run in BOTH outcomes (Scala applies the header and
//! extension before it decides); only step 3 is conditional on the
//! rebuilt transactions reproducing the header's `transactions_root`.

use ergo_crypto::merkle::transactions_root;
use ergo_inputblocks::ordering::ReconstructionPlan;
use ergo_mempool::types::TxId;
use ergo_mempool::Mempool;
use ergo_p2p::peer::PeerId;
use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::extension::{write_extension, Extension, ExtensionField};
use ergo_ser::header::serialize_header;
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION};
use ergo_ser::transaction::{read_transaction, Transaction};
use ergo_state::store::StateError;
use ergo_state::{HeaderSectionStore, StateBackendKind};
use ergo_sync::coordinator::Action;
use tracing::{debug, warn};

use super::runtime::InputBlocksRuntime;

/// The two chain-store reads reconstruction needs, behind a trait so a
/// failing store can be injected in tests — there is no other way to
/// reach the abort path, and "a read error is treated as missing data"
/// is exactly the bug this seam exists to keep fixed.
pub(in crate::node) trait ReconstructStore {
    /// Is this header already validated and stored?
    fn header_known(&self, header_id: &[u8; 32]) -> Result<bool, StateError>;
    /// Is this block section already stored?
    fn section_known(&self, modifier_id: &[u8; 32]) -> Result<bool, StateError>;
}

impl ReconstructStore for StateBackendKind {
    fn header_known(&self, header_id: &[u8; 32]) -> Result<bool, StateError> {
        Ok(self.get_header(header_id)?.is_some())
    }

    fn section_known(&self, modifier_id: &[u8; 32]) -> Result<bool, StateError> {
        Ok(self.get_block_section(modifier_id)?.is_some())
    }
}

/// A chain-store read failed while planning a reconstruction.
///
/// Distinct from every [`Outcome::Fallback`] reason: a database error is
/// NOT "the data was missing", and classifying it as one would hide a
/// failing store behind a routine full download. The effect boundary
/// reports it through the node's storage-failure observability (error
/// level, counted in the global storage-error totals) and falls back
/// under its own [`STORAGE_ERROR`] reason.
#[derive(Debug)]
pub(in crate::node) struct StorageFailure {
    /// The store call that failed, for the failure context.
    pub(in crate::node) operation: &'static str,
    /// Height of the announced ordering block, for the event feed.
    pub(in crate::node) height: u32,
    /// The error itself, propagated verbatim.
    pub(in crate::node) error: StateError,
}

impl StorageFailure {
    /// How the effect boundary classifies an aborted reconstruction: a
    /// fallback with no actions — nothing planned from a failed read is
    /// trustworthy — under the distinct [`STORAGE_ERROR`] reason.
    pub(in crate::node) fn as_fallback(&self) -> Reconstruction {
        Reconstruction {
            actions: Vec::new(),
            outcome: Outcome::Fallback {
                reason: STORAGE_ERROR,
            },
            height: self.height,
        }
    }
}

/// What the planner decided, and the actions that carry it out.
#[derive(Debug)]
pub(in crate::node) struct Reconstruction {
    /// Header / extension handoff, then — on [`Outcome::Assemble`] — the
    /// rebuilt section and `AssembleBlock`. Executed in this order.
    pub(in crate::node) actions: Vec<Action>,
    pub(in crate::node) outcome: Outcome,
    /// Height of the announced ordering block, for the event feed.
    pub(in crate::node) height: u32,
}

/// The decision itself.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::node) enum Outcome {
    /// The rebuilt transactions reproduce the header's root; the section
    /// is being handed to the ordinary pipeline. Carries the tx count.
    Assemble { txs: u32 },
    /// Reconstruction is impossible or wrong; the caller falls back to a
    /// full `BlockTransactions` download.
    Fallback { reason: &'static str },
}

/// Missing-ingredient / mismatch reasons, as the event feed reports them.
const MISSING_BROADCASTED_TX: &str = "missing_broadcasted_tx";
const MISSING_INPUT_BODY: &str = "missing_input_body";
const ROOT_MISMATCH: &str = "root_mismatch";
/// A chain-store read failed; never conflated with the reasons above.
pub(in crate::node) const STORAGE_ERROR: &str = "storage_error";

/// Plan the reconstruction of `plan.header_id`.
///
/// `peer` is the announcing peer, needed for the `ValidateHeader`
/// handoff; `None` (an unknown tag) only costs the header handoff, which
/// the ordinary header path will do anyway when the peer re-announces.
///
/// `Ok(None)` when the announcement is no longer in the processor's
/// store or its header does not serialize — nothing can be planned and
/// there is nothing to fall back to either. `Err` when a chain-store read
/// failed; see [`StorageFailure`].
pub(in crate::node) fn plan_reconstruction(
    store: &dyn ReconstructStore,
    mempool: &Mempool,
    rt: &InputBlocksRuntime,
    plan: &ReconstructionPlan,
    peer: Option<PeerId>,
) -> Result<Option<Reconstruction>, StorageFailure> {
    let Some(ann) = rt.processor().ordering_announcement(&plan.header_id) else {
        return Ok(None);
    };
    let header = &ann.header;
    let (header_bytes, header_id) = match serialize_header(header) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "input_blocks: announced ordering header does not serialize");
            return Ok(None);
        }
    };
    let header_id = *header_id.as_bytes();
    let height = header.height;
    let failed = |operation: &'static str, error: StateError| StorageFailure {
        operation,
        height,
        error,
    };

    let mut actions = Vec::new();

    // ----- 1. the header, through the ordinary path -----
    let header_known = store
        .header_known(&header_id)
        .map_err(|e| failed("get_header", e))?;
    match (header_known, peer) {
        (true, _) => {}
        (false, Some(peer)) => actions.push(Action::ValidateHeader { peer, header_bytes }),
        (false, None) => debug!(
            ordering = %hex::encode(header_id),
            "input_blocks: no peer for the header handoff, header stays unknown"
        ),
    }

    // ----- 2. the extension, from the announcement's fields -----
    let extension_id =
        compute_section_id(TYPE_EXTENSION, &header_id, header.extension_root.as_bytes());
    if !store
        .section_known(&extension_id)
        .map_err(|e| failed("get_block_section", e))?
    {
        let extension = Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields: ann
                .extension_fields
                .iter()
                .map(|(key, value)| ExtensionField {
                    key: *key,
                    value: value.clone(),
                })
                .collect(),
        };
        let mut w = VlqWriter::new();
        match write_extension(&mut w, &extension) {
            Ok(()) => actions.push(Action::PersistSection {
                modifier_id: extension_id,
                section_bytes: w.result(),
                section_type: TYPE_EXTENSION,
            }),
            Err(e) => warn!(
                ordering = %hex::encode(header_id),
                error = %e,
                "input_blocks: announced extension does not serialize"
            ),
        }
    }

    let fallback = |reason: &'static str, actions: Vec<Action>| {
        Ok(Some(Reconstruction {
            actions,
            outcome: Outcome::Fallback { reason },
            height,
        }))
    };

    // ----- 3. the transaction section -----
    let txs = match collect_transactions(mempool, rt, plan) {
        Ok(txs) => txs,
        Err(reason) => {
            debug!(
                ordering = %hex::encode(header_id),
                reason, "input_blocks: reconstruction is missing a transaction"
            );
            return fallback(reason, actions);
        }
    };
    let Some(root) = compute_root(&txs, header.version) else {
        return fallback(ROOT_MISMATCH, actions);
    };
    if root != *header.transactions_root.as_bytes() {
        debug!(
            ordering = %hex::encode(header_id),
            computed = %hex::encode(root),
            announced = %hex::encode(header.transactions_root.as_bytes()),
            "input_blocks: reconstruction does not reproduce the transactions root"
        );
        return fallback(ROOT_MISMATCH, actions);
    }

    let section = BlockTransactions {
        header_id: ModifierId::from_bytes(header_id),
        transactions: txs,
    };
    let mut w = VlqWriter::new();
    if let Err(e) = write_block_transactions_with_version(&mut w, &section, header.version) {
        warn!(
            ordering = %hex::encode(header_id),
            error = %e,
            "input_blocks: rebuilt section does not serialize"
        );
        return fallback(ROOT_MISMATCH, actions);
    }
    actions.push(Action::PersistSection {
        modifier_id: compute_section_id(TYPE_BLOCK_TRANSACTIONS, &header_id, &root),
        section_bytes: w.result(),
        section_type: TYPE_BLOCK_TRANSACTIONS,
    });
    actions.push(Action::AssembleBlock { header_id });
    Ok(Some(Reconstruction {
        actions,
        outcome: Outcome::Assemble {
            txs: section_tx_count(&section),
        },
        height,
    }))
}

fn section_tx_count(section: &BlockTransactions) -> u32 {
    u32::try_from(section.transactions.len()).unwrap_or(u32::MAX)
}

/// Spec 9.3 order: `nonBroadcasted ++ mempool.get_all(broadcastedIds) ++
/// collected input-chain transactions`. `Err` when any broadcasted id is
/// not in the pool or any input-chain body has been evicted — both are
/// fallback conditions, never a partial section.
fn collect_transactions(
    mempool: &Mempool,
    rt: &InputBlocksRuntime,
    plan: &ReconstructionPlan,
) -> Result<Vec<Transaction>, &'static str> {
    let mut txs = plan.non_broadcasted.clone();
    for id in &plan.broadcasted_ids {
        let bytes = mempool
            .get_bytes(&TxId::from_bytes(*id))
            .ok_or(MISSING_BROADCASTED_TX)?;
        let mut r = VlqReader::new(&bytes);
        // A pooled entry that no longer decodes is as unusable as one
        // that is gone, and it is the same fallback either way.
        txs.push(read_transaction(&mut r).map_err(|_| MISSING_BROADCASTED_TX)?);
    }
    for tx_ref in &plan.input_chain_txs {
        let body = rt.processor().body(tx_ref).ok_or(MISSING_INPUT_BODY)?;
        txs.push(body.tx.clone());
    }
    Ok(txs)
}

/// The header's `transactions_root` over `txs`: the Merkle root of the
/// transaction ids, with the witness ids as the second leaf half from
/// header version 2 on (`ergo-validation/src/block/validate.rs`).
fn compute_root(txs: &[Transaction], header_version: u8) -> Option<[u8; 32]> {
    let mut tx_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());
    for tx in txs {
        let bts = ergo_ser::transaction::bytes_to_sign(tx).ok()?;
        tx_ids.push(ergo_crypto::autolykos::common::blake2b256(&bts).to_vec());
    }
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let witness_data: Vec<Vec<u8>>;
    let witness_refs: Option<Vec<&[u8]>> = if header_version >= 2 {
        witness_data = txs
            .iter()
            .map(|tx| ergo_ser::weak_id::witness_id(tx).to_vec())
            .collect();
        Some(witness_data.iter().map(|w| w.as_slice()).collect())
    } else {
        None
    };
    Some(transactions_root(&tx_id_refs, witness_refs.as_deref()))
}

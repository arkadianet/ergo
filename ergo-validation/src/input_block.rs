//! Input-block (weak-block) transaction validation.
//!
//! Port of Scala `UtxoState.applyInputBlock`
//! (`nodeView/state/UtxoState.scala`), which is the consensus seam where a
//! candidate input block's body is accepted or rejected. Scala's order is
//! fixed and reproduced here exactly:
//!
//! 1. double spends across `previous ++ txs` (previous first),
//! 2. topological ordering *within* the block (`ErgoState.
//!    validateTopologicalOrdering`; data inputs are exempt),
//! 3. per-transaction validation against a UTXO view widened with the
//!    outputs of `previous` **and** of every transaction in this block
//!    (`withTransactions` + `applyTransactions`'s `createdOutputs`
//!    pre-population), with `softFieldsAllowed = false`.
//!
//! No state is mutated: Scala runs `applyTransactions` with
//! `checkUtxoSetTransformations = false`, so the AVL+ tree is never touched
//! and no state root is produced. The return value is the summed block cost.
//!
//! The validation context is the one described in spec 6.4: the state context
//! of the **last applied full block** `B`, not of an upcoming block. Callers
//! are responsible for building it (see [`validate_input_block_transactions`]'s
//! contract).

use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_ser::transaction::{transaction_id, Transaction};

use crate::context::{ProtocolParams, TransactionContext, UtxoView};
use crate::cost::{CostAccumulator, JitCost};
use crate::error::ValidationError;
use crate::tx::{validate_transaction_parsed, TxValidationCtx, TxValidationRules};

/// A transaction of the input block together with the exact bytes it was
/// deserialized from. The tx validator needs both: the parsed form for the
/// rules, the original bytes for the canonical-encoding check.
pub struct InputBlockTxBytes<'a> {
    /// Wire bytes this transaction was parsed from.
    pub bytes: &'a [u8],
    /// The parsed transaction.
    pub tx: &'a Transaction,
}

/// Why an input block's body was rejected.
#[derive(Debug, thiserror::Error)]
pub enum InputBlockValidationError {
    /// Two transactions of the already-processed input blocks spend the
    /// same box (Scala: "Double spending detected in previous transactions").
    #[error("double spend of box {box_id} (previous input blocks)")]
    DoubleSpendPrevious {
        /// Hex box id spent twice.
        box_id: String,
    },
    /// A box is spent twice across `previous ++ txs` (Scala: "Double spending
    /// detected in current input block").
    #[error("double spend of box {box_id} within the input block")]
    DoubleSpendCurrent {
        /// Hex box id spent twice.
        box_id: String,
    },
    /// A transaction spends a box created by a *later* transaction of the same
    /// input block (Scala `validateTopologicalOrdering`).
    #[error("out-of-order spending: tx {spending_index} spends box {box_id} created by tx {creating_index}")]
    OutOfOrder {
        /// Index of the spending transaction.
        spending_index: usize,
        /// Hex id of the box spent too early.
        box_id: String,
        /// Index of the transaction that creates it.
        creating_index: usize,
    },
    /// Per-transaction validation failed.
    #[error("transaction {index}: {error}")]
    Transaction {
        /// Index within `txs`.
        index: usize,
        /// The underlying rejection.
        #[source]
        error: ValidationError,
    },
    /// The block's summed cost exceeded `max_block_cost`.
    #[error("input block cost {total} exceeds {limit}")]
    CostExceeded {
        /// Cost reached.
        total: u64,
        /// Active `max_block_cost`.
        limit: u64,
    },
}

/// Validate the transactions of one input block. Spec 2.5 + 6.4.
///
/// `previous` = bodies of the already-processed input blocks of this chain
/// (oldest first). `ctx` MUST be the state context of the best full block `B`
/// (height = `B.height`, pre-header from `B`, `last_headers` = the 9 headers
/// before `B`) with `rules.soft_fields_allowed == false`. Never mutates state.
/// Returns the summed block cost of `txs`.
pub fn validate_input_block_transactions(
    txs: &[InputBlockTxBytes<'_>],
    previous: &[&Transaction],
    utxo: &dyn UtxoView,
    tx_ctx: &TransactionContext,
    params: &ProtocolParams,
    last_headers: &[Header],
    rules: TxValidationRules<'_>,
) -> Result<u64, InputBlockValidationError> {
    // 1. Double spends across previous ++ current (Scala order: previous
    //    first, so a collision *within* `previous` is reported as such).
    let mut seen: HashSet<Digest32> = HashSet::new();
    for tx in previous {
        for input in &tx.inputs {
            if !seen.insert(input.box_id) {
                return Err(InputBlockValidationError::DoubleSpendPrevious {
                    box_id: hex::encode(input.box_id.as_bytes()),
                });
            }
        }
    }
    for item in txs {
        for input in &item.tx.inputs {
            if !seen.insert(input.box_id) {
                return Err(InputBlockValidationError::DoubleSpendCurrent {
                    box_id: hex::encode(input.box_id.as_bytes()),
                });
            }
        }
    }

    // 2. Topological order within the block. Data inputs are exempt: Scala
    //    only walks `tx.inputs`, so a transaction may reference an output of a
    //    later transaction as a *data* input.
    let mut creator: HashMap<Digest32, usize> = HashMap::new();
    for (i, item) in txs.iter().enumerate() {
        for (id, _) in outputs_of(item.tx, i)? {
            creator.insert(id, i);
        }
    }
    for (i, item) in txs.iter().enumerate() {
        for input in &item.tx.inputs {
            if let Some(&c) = creator.get(&input.box_id) {
                if c >= i {
                    return Err(InputBlockValidationError::OutOfOrder {
                        spending_index: i,
                        box_id: hex::encode(input.box_id.as_bytes()),
                        creating_index: c,
                    });
                }
            }
        }
    }

    // 3. Per-tx validation over UTXO ∪ previous outputs ∪ all outputs of this
    //    block. Scala's `withTransactions(previous)` widens the state view and
    //    `applyTransactions` pre-populates `createdOutputs` with *every* output
    //    of `txs` (not only the preceding ones) — step 2 is what keeps that
    //    from admitting out-of-order spending.
    let mut overlay = PreviousOverlay::new(utxo);
    for (i, tx) in previous.iter().enumerate() {
        overlay.add_outputs(tx, i)?;
    }
    for (i, item) in txs.iter().enumerate() {
        overlay.add_outputs(item.tx, i)?;
    }

    let cap = JitCost::from_block_cost(params.max_block_cost).map_err(|e| {
        InputBlockValidationError::Transaction {
            index: 0,
            error: ValidationError::JitCostOverflow(e.to_string()),
        }
    })?;
    let mut total = 0u64;
    for (i, item) in txs.iter().enumerate() {
        let resolved_inputs = item
            .tx
            .inputs
            .iter()
            .map(|inp| {
                overlay
                    .get_box(&inp.box_id)
                    .ok_or_else(|| InputBlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::InputBoxNotFound {
                            box_id: hex::encode(inp.box_id.as_bytes()),
                        },
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Scala resolves data inputs through the same `checkBoxExistence`
        // function as inputs, so they see the identical union.
        let resolved_data_inputs = item
            .tx
            .data_inputs
            .iter()
            .map(|di| {
                overlay
                    .get_box(&di.box_id)
                    .ok_or_else(|| InputBlockValidationError::Transaction {
                        index: i,
                        error: ValidationError::DataInputBoxNotFound {
                            box_id: hex::encode(di.box_id.as_bytes()),
                        },
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut cost = CostAccumulator::new(cap);
        let mut cx = TxValidationCtx {
            ctx: tx_ctx,
            params,
            cost: &mut cost,
            last_headers,
            rules,
        };
        validate_transaction_parsed(
            item.tx.clone(),
            item.bytes,
            resolved_inputs,
            resolved_data_inputs,
            false,
            &mut cx,
        )
        .map_err(|error| InputBlockValidationError::Transaction { index: i, error })?;

        // Scala `execTransactions` threads the running block cost into each
        // `validateStateful` as `accumulatedCost` and rejects once
        // `maxBlockCost < accumulatedCost + initialCost`. The per-tx
        // accumulator capped at `max_block_cost` plus this running check
        // reproduces "fail when the cumulative cost exceeds the block limit".
        total += cost.total_block_cost();
        if total > params.max_block_cost {
            return Err(InputBlockValidationError::CostExceeded {
                total,
                limit: params.max_block_cost,
            });
        }
    }
    Ok(total)
}

/// The `(box_id, box)` pairs a transaction creates, with `index` only used to
/// attribute a serialization failure to the right transaction.
fn outputs_of(
    tx: &Transaction,
    index: usize,
) -> Result<Vec<(Digest32, ErgoBox)>, InputBlockValidationError> {
    let fail = |e: ergo_ser::error::WriteError| InputBlockValidationError::Transaction {
        index,
        error: ValidationError::Deserialization(e.to_string()),
    };
    let tx_id = transaction_id(tx).map_err(fail)?;
    tx.output_candidates
        .iter()
        .enumerate()
        .map(|(idx, cand)| {
            let b = ErgoBox {
                candidate: cand.clone(),
                transaction_id: tx_id,
                index: idx as u16,
            };
            let id = b.box_id().map_err(fail)?;
            Ok((id, b))
        })
        .collect()
}

/// UTXO view widened with boxes created by transactions that are not (yet)
/// in the committed set.
struct PreviousOverlay<'a> {
    base: &'a dyn UtxoView,
    created: HashMap<Digest32, ErgoBox>,
}

impl<'a> PreviousOverlay<'a> {
    fn new(base: &'a dyn UtxoView) -> Self {
        Self {
            base,
            created: HashMap::new(),
        }
    }

    fn add_outputs(
        &mut self,
        tx: &Transaction,
        index: usize,
    ) -> Result<(), InputBlockValidationError> {
        for (id, b) in outputs_of(tx, index)? {
            self.created.insert(id, b);
        }
        Ok(())
    }
}

impl UtxoView for PreviousOverlay<'_> {
    /// Created outputs first, then the committed set — Scala's
    /// `createdOutputs.get(id).orElse(boxById(id))`. Boxes spent by `previous`
    /// or `txs` were already rejected as double spends in step 1, so no
    /// spent-set filtering is needed here (`withTransactions` only adds
    /// outputs).
    fn get_box(&self, box_id: &Digest32) -> Option<ErgoBox> {
        self.created
            .get(box_id)
            .cloned()
            .or_else(|| self.base.get_box(box_id))
    }
}

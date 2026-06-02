//! UnsignedTxBuilder: payment requests → unsigned tx.

use crate::box_selector::{BoxSelector, BoxSummary, SelectionTarget};
use crate::error::WalletError;
use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::ErgoBoxCandidate;
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::input::{ContextExtension, DataInput, UnsignedInput};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::token::Token;
use ergo_ser::transaction::UnsignedTransaction;
use std::collections::BTreeMap;

/// A single payment the builder must include as an output.
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    /// ErgoTree bytes of the recipient's script.
    pub to_ergo_tree: Vec<u8>,
    /// Value to send in nanoERG.
    pub value: u64,
    /// Token id (32-byte mint box id) → amount.
    pub assets: BTreeMap<[u8; 32], u64>,
}

/// Builds an `UnsignedTransaction` from payment requests.
///
/// The caller supplies:
/// - `available_summaries`: wallet UTXO summaries (from `WalletReader::all_unspent_boxes`).
/// - `selector`: box selector (DefaultBoxSelector or ReplaceCompactCollectBoxSelector).
/// - fee/change/fee_ergo_tree/change_ergo_tree: fee amount + fee-destination script +
///   change-destination script.
/// - `current_height`: candidate block height for output creation_height.
/// - `min_box_value`: minimum ERG a change box must carry (skip change if below this and
///   the remainder is zero, fold remainder into fee if non-zero and below min).
/// - `data_inputs`: read-only box references included in the unsigned tx.
///
/// The builder is pure: it does not access chain state. Full ErgoBox lookup
/// for signing happens at the writer-task boundary via `ChainStateAccessor::lookup_utxo`.
pub struct UnsignedTxBuilder<'a> {
    pub available_summaries: &'a [BoxSummary],
    pub selector: &'a dyn BoxSelector,
    pub fee: u64,
    /// ErgoTree bytes for the fee output (canonical miner-fee script).
    pub fee_ergo_tree: Vec<u8>,
    /// ErgoTree bytes for the change output (wallet's change address).
    pub change_ergo_tree: Vec<u8>,
    pub current_height: u32,
    pub min_box_value: u64,
    pub data_inputs: Vec<DataInput>,
}

impl<'a> UnsignedTxBuilder<'a> {
    /// Build an `UnsignedTransaction` from the given payment requests.
    pub fn build(&self, requests: &[PaymentRequest]) -> Result<UnsignedTransaction, WalletError> {
        // 1. Sum totals required across all payment outputs + fee.
        let mut total_erg: u64 = self.fee;
        let mut total_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for r in requests {
            total_erg = total_erg
                .checked_add(r.value)
                .ok_or_else(|| WalletError::TxBuild("erg overflow".into()))?;
            for (&id, &amt) in &r.assets {
                let entry = total_tokens.entry(id).or_insert(0);
                *entry = entry
                    .checked_add(amt)
                    .ok_or_else(|| WalletError::TxBuild("token overflow".into()))?;
            }
        }

        // 2. Select inputs.
        let target = SelectionTarget {
            erg_amount: total_erg,
            tokens: total_tokens,
            min_change_value: self.min_box_value,
        };
        let selection = self.selector.select(self.available_summaries, &target)?;

        // 3. Build output candidates.
        let mut output_candidates: Vec<ErgoBoxCandidate> = Vec::new();

        // Payment outputs.
        for r in requests {
            let ergo_tree = parse_ergo_tree(&r.to_ergo_tree)
                .map_err(|e| WalletError::TxBuild(format!("decode payment ergo_tree: {e}")))?;
            let tokens = assets_to_tokens(&r.assets);
            output_candidates.push(
                ErgoBoxCandidate::new(
                    r.value,
                    ergo_tree,
                    self.current_height,
                    tokens,
                    AdditionalRegisters::empty(),
                )
                .map_err(|e| WalletError::TxBuild(format!("ErgoBoxCandidate (payment): {e:?}")))?,
            );
        }

        // Decide change vs fee-fold BEFORE building the fee box. Mirrors
        // Scala `TransactionBuilder.buildUnsignedTx`: token-less change below
        // `min_box_value` is added to the miner fee (`changeGoesToFee`) rather
        // than emitted as a dust box the validator would reject; change that
        // carries tokens is always kept as a box (tokens must live somewhere),
        // regardless of its ERG value.
        let change_has_tokens = !selection.change_tokens.is_empty();
        let change_goes_to_fee = selection.change_erg > 0
            && selection.change_erg < self.min_box_value
            && !change_has_tokens;
        let fee_value = if change_goes_to_fee {
            self.fee
                .checked_add(selection.change_erg)
                .ok_or_else(|| WalletError::TxBuild("fee + folded change overflow".into()))?
        } else {
            self.fee
        };

        // Fee output (value includes any folded sub-minimum change).
        let fee_tree = parse_ergo_tree(&self.fee_ergo_tree)
            .map_err(|e| WalletError::TxBuild(format!("decode fee ergo_tree: {e}")))?;
        output_candidates.push(
            ErgoBoxCandidate::new(
                fee_value,
                fee_tree,
                self.current_height,
                vec![],
                AdditionalRegisters::empty(),
            )
            .map_err(|e| WalletError::TxBuild(format!("ErgoBoxCandidate (fee): {e:?}")))?,
        );

        // Change output — emitted unless the change was folded into the fee
        // above. Exact selection (change_erg == 0, no tokens) emits nothing.
        if !change_goes_to_fee && (selection.change_erg > 0 || change_has_tokens) {
            let change_tree = parse_ergo_tree(&self.change_ergo_tree)
                .map_err(|e| WalletError::TxBuild(format!("decode change ergo_tree: {e}")))?;
            let change_tokens = assets_to_tokens(&selection.change_tokens);
            output_candidates.push(
                ErgoBoxCandidate::new(
                    selection.change_erg,
                    change_tree,
                    self.current_height,
                    change_tokens,
                    AdditionalRegisters::empty(),
                )
                .map_err(|e| WalletError::TxBuild(format!("ErgoBoxCandidate (change): {e:?}")))?,
            );
        }

        // 4. Build unsigned inputs from selected box ids.
        let inputs: Vec<UnsignedInput> = selection
            .selected_ids
            .iter()
            .map(|box_id| UnsignedInput {
                box_id: Digest32::from_bytes(*box_id),
                extension: ContextExtension::empty(),
            })
            .collect();

        Ok(UnsignedTransaction {
            inputs,
            data_inputs: self.data_inputs.clone(),
            output_candidates,
        })
    }
}

/// Parse an `ErgoTree` from raw wire bytes.
fn parse_ergo_tree(bytes: &[u8]) -> Result<ergo_ser::ergo_tree::ErgoTree, String> {
    let mut r = VlqReader::new(bytes);
    read_ergo_tree(&mut r).map_err(|e| format!("{e:?}"))
}

/// Convert a `BTreeMap<[u8; 32], u64>` assets map into the `Vec<Token>`
/// form that `ErgoBoxCandidate::new` expects.
fn assets_to_tokens(assets: &BTreeMap<[u8; 32], u64>) -> Vec<Token> {
    assets
        .iter()
        .map(|(&id, &amt)| Token {
            token_id: Digest32::from_bytes(id),
            amount: amt,
        })
        .collect()
}

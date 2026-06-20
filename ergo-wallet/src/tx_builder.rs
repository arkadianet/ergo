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
    /// EIP-27 re-emission rules for this network, or `None` off EIP-27 nets
    /// (e.g. testnet, where `ChainSpec::reemission` is `None`). When `Some` and
    /// a selected input is a reward box (value `<=` the emission floor) carrying
    /// the re-emission token at [`Self::reemission_height`], consensus requires
    /// the token to be burned and `1` nanoErg/token paid to the pay-to-reemission
    /// contract. The owed amount comes from the SHARED
    /// [`ergo_validation::reemission_obligation_core`], the same obligation the
    /// consensus validator and the wallet balance surface use — so the figures
    /// cannot drift.
    pub reemission: Option<&'a ergo_validation::ReemissionRuleInputs>,
    /// Candidate block height the re-emission burn obligation is evaluated at —
    /// the height the validator will run this tx at (`tip + 1`), which is NOT the
    /// output `creation_height` ([`Self::current_height`] = `tip`). The
    /// reemission-spending branch triggers *strictly above* the activation
    /// height, so this off-by-one is load-bearing at the activation boundary.
    /// Ignored when [`Self::reemission`] is `None`.
    pub reemission_height: u32,
}

/// The result of a burn-aware input selection — the single source of truth shared
/// by the unsigned-tx builder ([`UnsignedTxBuilder::build`]) and the native
/// wallet's `boxes/select` + `transactions/build` surfaces, so the selection,
/// change, and EIP-27 burn they report can never drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionPlan {
    /// Box ids the selector chose, in selector-preferred order.
    pub selected_ids: Vec<[u8; 32]>,
    /// Real change nanoErg, **after** the re-emission burn output (if any) is
    /// debited from the selected value.
    pub change_erg: u64,
    /// Real change tokens — the re-emission token is already removed when a burn
    /// is owed (it may appear on no output).
    pub change_tokens: BTreeMap<[u8; 32], u64>,
    /// nanoErg owed to the pay-to-reemission contract (1 per burned re-emission
    /// token, summed over ALL selected inputs). `0` when no burn is triggered.
    pub to_burn: u64,
}

/// Select inputs to cover `target_erg` + `target_tokens`, resolving the EIP-27
/// re-emission burn obligation to a fixed point.
///
/// Spending a reward box (value `<=` the emission floor, carrying the re-emission
/// token) past activation forces the token to be **burned** and `to_burn` nanoErg
/// (1 per token, summed over ALL selected inputs) paid to the pay-to-reemission
/// contract — an extra output that must itself be funded from the inputs.
/// Reserving that ERG (`burn_budget`) can pull in another reward box, raising the
/// owed burn, so this reselects until the reservation covers what the selection
/// owes. Each non-terminating pass strictly raises the reservation → the target
/// grows → `select` adds inputs and the loop terminates (or reports insufficient
/// funds). Off EIP-27 nets (`reemission` is `None`) this collapses to a single
/// ordinary selection with no burn. The owed amount comes from the SHARED
/// [`ergo_validation::reemission_obligation_core`] so the builder, the consensus
/// validator, and the balance surface cannot drift.
pub fn select_with_reemission(
    selector: &dyn BoxSelector,
    available: &[BoxSummary],
    target_erg: u64,
    target_tokens: &BTreeMap<[u8; 32], u64>,
    min_box_value: u64,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
    reemission_height: u32,
) -> Result<SelectionPlan, WalletError> {
    // box_id -> (value, re-emission token amount): the per-input pair the shared
    // obligation consumes (built once, only when EIP-27 rules apply).
    #[allow(clippy::type_complexity)]
    let reemission_ctx: Option<(
        &ergo_validation::ReemissionRuleInputs,
        BTreeMap<[u8; 32], (u64, u64)>,
    )> = reemission.map(|rules| {
        let value_token_by_id = available
            .iter()
            .map(|s| {
                let token = s
                    .tokens
                    .get(&rules.reemission_token_id)
                    .copied()
                    .unwrap_or(0);
                (s.box_id, (s.value, token))
            })
            .collect();
        (rules, value_token_by_id)
    });

    let mut burn_budget: u64 = 0;
    let (selection, to_burn) = loop {
        let target = SelectionTarget {
            erg_amount: target_erg
                .checked_add(burn_budget)
                .ok_or_else(|| WalletError::TxBuild("erg + re-emission burn overflow".into()))?,
            tokens: target_tokens.clone(),
            min_change_value: min_box_value,
        };
        let selection = selector.select(available, &target)?;
        // Burn owed by THIS input set (0 off EIP-27 nets / when untriggered).
        let owed = match &reemission_ctx {
            Some((rules, value_token_by_id)) => {
                let per_input = selection
                    .selected_ids
                    .iter()
                    .filter_map(|id| value_token_by_id.get(id).copied());
                ergo_validation::reemission_obligation_core(
                    per_input,
                    reemission_height,
                    rules.activation_height,
                )
                .to_burn
            }
            None => 0,
        };
        if owed <= burn_budget {
            break (selection, owed);
        }
        // Reserve exactly what this set owes and reselect (monotonic increase).
        burn_budget = owed;
    };

    // True change after the pay-to-reemission output claims `to_burn` of the
    // reserved budget. `to_burn <= burn_budget` holds at the loop break, so the
    // inner subtraction never underflows; on the no-burn path both are zero and
    // this is exactly `selection.change_erg`.
    let change_erg = selection.change_erg + (burn_budget - to_burn);
    let mut change_tokens = selection.change_tokens;
    if to_burn > 0 {
        // The re-emission token may not appear on ANY output (Scala
        // `require(!out.tokens.contains(reemissionTokenId))`), so strip it from
        // change; the equivalent nanoErg is paid to pay-to-reemission downstream.
        let (rules, _) = reemission_ctx
            .as_ref()
            .expect("to_burn > 0 implies re-emission rules are present");
        change_tokens.remove(&rules.reemission_token_id);
    }
    Ok(SelectionPlan {
        selected_ids: selection.selected_ids,
        change_erg,
        change_tokens,
        to_burn,
    })
}

/// Whether token-less change below the minimum box value is folded into the miner
/// fee rather than emitted as a dust box the validator would reject (Scala
/// `TransactionBuilder.buildUnsignedTx` `changeGoesToFee`). Change carrying tokens
/// is always kept as a box (tokens must live somewhere), regardless of ERG value.
/// Shared so the builder and the native `transactions/build` response agree on
/// whether a change box exists.
pub fn change_goes_to_fee(change_erg: u64, change_has_tokens: bool, min_box_value: u64) -> bool {
    change_erg > 0 && change_erg < min_box_value && !change_has_tokens
}

impl<'a> UnsignedTxBuilder<'a> {
    /// Build an `UnsignedTransaction` from the given payment requests.
    pub fn build(&self, requests: &[PaymentRequest]) -> Result<UnsignedTransaction, WalletError> {
        self.build_with_plan(requests).map(|(tx, _plan)| tx)
    }

    /// Build an `UnsignedTransaction` AND return the [`SelectionPlan`] it was built
    /// from (selected inputs, real change, EIP-27 burn) — so the native
    /// `transactions/build` surface can report exactly what was built without
    /// re-deriving it from the serialized bytes.
    pub fn build_with_plan(
        &self,
        requests: &[PaymentRequest],
    ) -> Result<(UnsignedTransaction, SelectionPlan), WalletError> {
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

        // 2. Burn-aware input selection (shared with the native select surface).
        let plan = select_with_reemission(
            self.selector,
            self.available_summaries,
            total_erg,
            &total_tokens,
            self.min_box_value,
            self.reemission,
            self.reemission_height,
        )?;
        let change_erg = plan.change_erg;
        let change_tokens = plan.change_tokens.clone();
        let to_burn = plan.to_burn;

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
        let change_has_tokens = !change_tokens.is_empty();
        let change_goes_to_fee =
            change_goes_to_fee(change_erg, change_has_tokens, self.min_box_value);
        let fee_value = if change_goes_to_fee {
            self.fee
                .checked_add(change_erg)
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

        // EIP-27 pay-to-reemission output: exactly `to_burn` nanoErg (1 per burned
        // re-emission token). For a real reward box `to_burn` is ERG-scale, so this
        // is never dust; the validator requires the paid value to EQUAL the burned
        // token count, so it must be `to_burn` exactly (never padded to
        // `min_box_value`). Placed before the change output to mirror the explicit
        // builder's output order.
        if to_burn > 0 {
            let rules = self
                .reemission
                .expect("to_burn > 0 implies re-emission rules are present");
            let pay2r_tree = parse_ergo_tree(&rules.pay_to_reemission_tree).map_err(|e| {
                WalletError::TxBuild(format!("decode pay-to-reemission ergo_tree: {e}"))
            })?;
            output_candidates.push(
                ErgoBoxCandidate::new(
                    to_burn,
                    pay2r_tree,
                    self.current_height,
                    vec![],
                    AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletError::TxBuild(format!("ErgoBoxCandidate (pay-to-reemission): {e:?}"))
                })?,
            );
        }

        // Change output — emitted unless the change was folded into the fee
        // above. Exact selection (change_erg == 0, no tokens) emits nothing.
        if !change_goes_to_fee && (change_erg > 0 || change_has_tokens) {
            let change_tree = parse_ergo_tree(&self.change_ergo_tree)
                .map_err(|e| WalletError::TxBuild(format!("decode change ergo_tree: {e}")))?;
            let change_tokens = assets_to_tokens(&change_tokens);
            output_candidates.push(
                ErgoBoxCandidate::new(
                    change_erg,
                    change_tree,
                    self.current_height,
                    change_tokens,
                    AdditionalRegisters::empty(),
                )
                .map_err(|e| WalletError::TxBuild(format!("ErgoBoxCandidate (change): {e:?}")))?,
            );
        }

        // 4. Build unsigned inputs from selected box ids.
        let inputs: Vec<UnsignedInput> = plan
            .selected_ids
            .iter()
            .map(|box_id| UnsignedInput {
                box_id: Digest32::from_bytes(*box_id),
                extension: ContextExtension::empty(),
            })
            .collect();

        Ok((
            UnsignedTransaction {
                inputs,
                data_inputs: self.data_inputs.clone(),
                output_candidates,
            },
            plan,
        ))
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

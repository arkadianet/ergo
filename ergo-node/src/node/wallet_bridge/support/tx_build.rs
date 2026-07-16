//! Native transaction construction (`boxes/select` + `transactions/build`),
//! and the shared burn-aware unsigned-tx builder both the compat and native
//! send paths route through.

use std::collections::BTreeMap;

use parking_lot::RwLock;

use crate::node::wallet_bridge::{ChainStateAccessor, WalletAdminError};
use ergo_api::wallet::sending::PaymentRequestDto;

/// Minimum fee in nanoERG. Mirrors Scala's `Parameters.MinFee`.
pub(crate) const MIN_FEE: u64 = 1_000_000;
/// Minimum box value in nanoERG. Mirrors Scala's `BoxUtils.MinBoxValue`.
pub(crate) const MIN_BOX_VALUE: u64 = 1_000_000;

/// A selected input box, captured for the native `transactions/build` response.
#[derive(Debug, Clone)]
pub(crate) struct SelectedInputInfo {
    pub(crate) box_id: [u8; 32],
    pub(crate) value: u64,
    pub(crate) tokens: BTreeMap<[u8; 32], u64>,
}

/// What [`build_unsigned_tx`] produced: the serialized unsigned tx plus the exact
/// selection / change / fee / EIP-27 burn it was built from, so the native
/// `transactions/build` surface can report it precisely without re-deriving it
/// from the serialized bytes. Compat callers use only [`BuiltTx::bytes`].
pub(crate) struct BuiltTx {
    /// Serialized `UnsignedTransaction` bytes.
    pub(crate) bytes: Vec<u8>,
    /// Selected inputs (box_id, value, tokens), in input order.
    pub(crate) selected: Vec<SelectedInputInfo>,
    /// Emitted change boxes (0 or 1): `(erg, tokens)`. Empty when the change was
    /// folded into the fee or the selection was exact.
    pub(crate) change_outputs: Vec<(u64, BTreeMap<[u8; 32], u64>)>,
    /// Actual miner-fee-box value (the requested fee plus any folded sub-minimum
    /// change). Both branches preserve the requested fee — an EIP-27 burn is
    /// debited from change, never the fee.
    pub(crate) fee: u64,
    /// EIP-27 burn `(reemission_token_id, to_burn_nanoerg)`, or `None`.
    pub(crate) reemission_burn: Option<([u8; 32], u64)>,
    /// Wallet scan height the inputs were read at (`asOf`).
    pub(crate) as_of: u32,
}

/// Build an unsigned transaction from payment requests (the shared build path).
///
/// `override_inputs` / `override_data_inputs`: hex box ids supplied by the
/// caller; `None` means "use automatic box selection".
/// `fee_override`: explicit fee; `None` uses `MIN_FEE`.
///
/// Returns the [`BuiltTx`] (serialized bytes + the selection/change/fee/burn plan).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_unsigned_tx(
    requests: &[PaymentRequestDto],
    override_inputs: Option<&[String]>,
    override_data_inputs: Option<&[String]>,
    fee_override: Option<u64>,
    change_address_override: Option<&str>,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<BuiltTx, WalletAdminError> {
    let state = state.read();
    let as_of = chain.wallet_scan_height();

    // Decode payment requests: address → pubkey → ErgoTree bytes.
    let payment_reqs: Vec<ergo_wallet::tx_builder::PaymentRequest> = requests
        .iter()
        .map(|r| {
            let pubkey =
                ergo_ser::address::decode_p2pk_address(&r.address, network).map_err(|e| {
                    WalletAdminError::BadRequest(format!("bad address {}: {e}", r.address))
                })?;
            // Canonical (non-segregated) P2PK tree — matches Scala
            // ErgoAddressEncoder and the wallet's own tracked_p2pk_trees.
            // The segregated build_prove_dlog_ergo_tree would emit a P2S
            // shape that recipients' wallets render as the wrong address
            // and that our own scan would not recognize as change.
            let to_ergo_tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey)
                .map_err(|e| WalletAdminError::Internal(format!("recipient p2pk tree: {e:?}")))?;
            let assets: BTreeMap<[u8; 32], u64> = r
                .assets
                .iter()
                .map(|a| {
                    let id = hex::decode(&a.token_id)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| {
                            WalletAdminError::Internal(format!("bad token_id: {}", a.token_id))
                        })?;
                    Ok((id, a.amount))
                })
                .collect::<Result<_, WalletAdminError>>()?;
            Ok(ergo_wallet::tx_builder::PaymentRequest {
                to_ergo_tree,
                value: r.value,
                assets,
            })
        })
        .collect::<Result<_, WalletAdminError>>()?;

    let fee = fee_override.unwrap_or(MIN_FEE);

    // Resolve change address → ErgoTree bytes. A native caller may override the
    // persisted change address (`TxIntent.changeAddress`); the override MUST decode
    // as a P2PK for this network AND be a tracked wallet tree, else
    // `change_address_untracked(422)` — so change never leaves the wallet.
    let change_address = match change_address_override {
        Some(addr) => addr,
        None => state
            .change_address()
            .ok_or_else(|| WalletAdminError::Internal("no change address set".into()))?,
    };
    let change_pubkey =
        ergo_ser::address::decode_p2pk_address(change_address, network).map_err(|_| {
            if change_address_override.is_some() {
                WalletAdminError::ChangeAddressUntracked
            } else {
                WalletAdminError::Internal("change address decode failed".into())
            }
        })?;
    // Canonical (non-segregated) P2PK tree so the change box matches the
    // wallet's own tracked_p2pk_trees and is recognized on the next scan.
    let change_ergo_tree = ergo_ser::address::build_p2pk_tree_bytes(&change_pubkey)
        .map_err(|e| WalletAdminError::Internal(format!("change p2pk tree: {e:?}")))?;
    if change_address_override.is_some() && !state.is_tracked_tree(&change_ergo_tree) {
        return Err(WalletAdminError::ChangeAddressUntracked);
    }

    let fee_ergo_tree = ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES.to_vec();

    // Get the chain tip height for candidate creation_height.
    let current_height = chain.tip_height();

    // Build unsigned tx.
    if let Some(explicit_inputs) = override_inputs {
        // Caller-supplied box ids: decode, look up full boxes from UTXO set,
        // sum ERG + tokens, compute change, emit change output if any.

        let data_inputs: Vec<ergo_ser::input::DataInput> = override_data_inputs
            .unwrap_or(&[])
            .iter()
            .map(|hex_id| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("bad data input id: {hex_id}"))
                    })?;
                Ok(ergo_ser::input::DataInput {
                    box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                })
            })
            .collect::<Result<_, WalletAdminError>>()?;

        // Decode, look up, and sum all provided input boxes.
        let mut input_erg_total: u64 = 0;
        let mut input_tokens_total: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut inputs: Vec<ergo_ser::input::UnsignedInput> =
            Vec::with_capacity(explicit_inputs.len());
        // EIP-27 rules for this net (None off EIP-27); per-input (value, token)
        // captured for the shared re-emission obligation below.
        let reemission_rules = chain.reemission_rules();
        let mut per_input_reemission: Vec<(u64, u64)> = Vec::with_capacity(explicit_inputs.len());
        let mut selected: Vec<SelectedInputInfo> = Vec::with_capacity(explicit_inputs.len());

        for hex_id in explicit_inputs {
            let id: [u8; 32] = hex::decode(hex_id)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| WalletAdminError::BadRequest(format!("bad input id: {hex_id}")))?;

            // A caller-named input absent from the UTXO set is a client error, not a
            // server fault (it may be already spent or never existed).
            let ergo_box = chain
                .lookup_utxo(&id)
                .ok_or(WalletAdminError::BoxNotFound)?;

            input_erg_total = input_erg_total
                .checked_add(ergo_box.candidate.value)
                .ok_or_else(|| WalletAdminError::Internal("input ERG overflow".into()))?;

            let mut box_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
            for token in &ergo_box.candidate.tokens {
                let id = *token.token_id.as_bytes();
                let entry = input_tokens_total.entry(id).or_insert(0);
                *entry = entry
                    .checked_add(token.amount)
                    .ok_or_else(|| WalletAdminError::Internal("input token overflow".into()))?;
                *box_tokens.entry(id).or_insert(0) = box_tokens
                    .get(&id)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(token.amount);
            }

            let reemission_tok = reemission_rules.map_or(0, |r| {
                box_tokens.get(&r.reemission_token_id).copied().unwrap_or(0)
            });
            per_input_reemission.push((ergo_box.candidate.value, reemission_tok));
            selected.push(SelectedInputInfo {
                box_id: id,
                value: ergo_box.candidate.value,
                tokens: box_tokens,
            });

            inputs.push(ergo_ser::input::UnsignedInput {
                box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                extension: ergo_ser::input::ContextExtension::empty(),
            });
        }

        // Sum required outputs (payments + fee).
        let mut required_erg: u64 = fee;
        let mut required_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for req in &payment_reqs {
            required_erg = required_erg
                .checked_add(req.value)
                .ok_or_else(|| WalletAdminError::Internal("output ERG overflow".into()))?;
            for (&id, &amt) in &req.assets {
                let entry = required_tokens.entry(id).or_insert(0);
                *entry = entry
                    .checked_add(amt)
                    .ok_or_else(|| WalletAdminError::Internal("output token overflow".into()))?;
            }
        }

        // Verify ERG coverage (a shortfall is a fundable-request failure, not a 500).
        if input_erg_total < required_erg {
            return Err(WalletAdminError::InsufficientFunds(format!(
                "explicit inputs hold {input_erg_total} nanoErg, need {required_erg}"
            )));
        }

        // Verify token coverage.
        for (token_id, &required_amt) in &required_tokens {
            let available = input_tokens_total.get(token_id).copied().unwrap_or(0);
            if available < required_amt {
                return Err(WalletAdminError::InsufficientFunds(format!(
                    "explicit inputs hold {available} of token {}, need {required_amt}",
                    hex::encode(token_id)
                )));
            }
        }

        // Compute change.
        let mut change_erg = input_erg_total - required_erg;
        let mut change_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (&id, &input_amt) in &input_tokens_total {
            let required_amt = required_tokens.get(&id).copied().unwrap_or(0);
            let rem = input_amt - required_amt;
            if rem > 0 {
                change_tokens.insert(id, rem);
            }
        }

        // EIP-27 burn-aware adjustment. When a selected input is a reward box
        // carrying the re-emission token at the candidate height (`tip+1`),
        // consensus requires the token to be BURNED (on NO output) and 1
        // nanoErg/token paid to the pay-to-reemission contract. Mirror the SHARED
        // validator obligation so the built tx passes self-verify. The burn is
        // funded from CHANGE ONLY — the requested fee is preserved (matching the
        // auto-selection branch); the explicit path never reselects, so an input
        // set whose change cannot cover the burn is `insufficient_funds`.
        let mut reemission_burn: Option<(Vec<u8>, u64)> = None; // (pay2r_tree_bytes, to_burn)
        if let Some(rules) = reemission_rules {
            let obl = ergo_validation::reemission_obligation_core(
                per_input_reemission.iter().copied(),
                current_height.saturating_add(1),
                rules.activation_height,
            );
            if obl.triggered {
                // No output may keep the re-emission token: a requested SEND of it is
                // rejected (it can only be burned), and the change surplus is stripped.
                if required_tokens
                    .get(&rules.reemission_token_id)
                    .is_some_and(|&a| a > 0)
                {
                    return Err(WalletAdminError::ReemissionSpendNotAllowed(
                        "the re-emission token cannot be sent to an output; it is burned \
                         when a reward box is spent"
                            .into(),
                    ));
                }
                change_tokens.remove(&rules.reemission_token_id);
                let to_burn = obl.to_burn;
                if to_burn > change_erg {
                    return Err(WalletAdminError::InsufficientFunds(format!(
                        "explicit inputs cannot fund the {to_burn} nanoErg EIP-27 \
                         re-emission burn from change ({change_erg} available)"
                    )));
                }
                change_erg -= to_burn;
                reemission_burn = Some((rules.pay_to_reemission_tree.clone(), to_burn));
            }
        }

        // Build output candidates.
        let mut output_candidates: Vec<ergo_ser::ergo_box::ErgoBoxCandidate> = Vec::new();
        for req in &payment_reqs {
            let ergo_tree = {
                let mut r = ergo_primitives::reader::VlqReader::new(&req.to_ergo_tree);
                ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                    .map_err(|e| WalletAdminError::Internal(format!("payment ergo_tree: {e:?}")))?
            };
            let tokens = req
                .assets
                .iter()
                .map(|(&id, &amt)| ergo_ser::token::Token {
                    token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                    amount: amt,
                })
                .collect();
            output_candidates.push(
                ergo_ser::ergo_box::ErgoBoxCandidate::new(
                    req.value,
                    ergo_tree,
                    current_height,
                    tokens,
                    ergo_ser::register::AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletAdminError::Internal(format!("ErgoBoxCandidate (payment): {e:?}"))
                })?,
            );
        }

        // Decide change vs fee-fold, matching the auto-selection builder and
        // Scala `TransactionBuilder.buildUnsignedTx` (`changeGoesToFee`):
        // token-less change below MIN_BOX_VALUE is folded into the miner fee
        // rather than emitted as a dust box the validator rejects; change
        // carrying tokens is always kept as a box regardless of ERG value.
        let change_goes_to_fee =
            change_erg > 0 && change_erg < MIN_BOX_VALUE && change_tokens.is_empty();
        let fee_value = if change_goes_to_fee {
            fee.checked_add(change_erg)
                .ok_or_else(|| WalletAdminError::Internal("fee + folded change overflow".into()))?
        } else {
            fee
        };

        // Fee output (value includes any folded sub-minimum change).
        let fee_tree = {
            let mut r = ergo_primitives::reader::VlqReader::new(&fee_ergo_tree);
            ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                .map_err(|e| WalletAdminError::Internal(format!("fee ergo_tree: {e:?}")))?
        };
        output_candidates.push(
            ergo_ser::ergo_box::ErgoBoxCandidate::new(
                fee_value,
                fee_tree,
                current_height,
                vec![],
                ergo_ser::register::AdditionalRegisters::empty(),
            )
            .map_err(|e| WalletAdminError::Internal(format!("ErgoBoxCandidate (fee): {e:?}")))?,
        );

        // EIP-27 pay-to-reemission output (exactly `to_burn` nanoErg = 1 per
        // burned token). For a real reward box `to_burn` is ERG-scale, so this is
        // never dust; the value must match `to_burn` exactly (the validator
        // requires equality, so it cannot be padded to MIN_BOX_VALUE).
        if let Some((pay2r_tree_bytes, to_burn)) = &reemission_burn {
            let pay2r_tree = {
                let mut r = ergo_primitives::reader::VlqReader::new(pay2r_tree_bytes);
                ergo_ser::ergo_tree::read_ergo_tree(&mut r).map_err(|e| {
                    WalletAdminError::Internal(format!("pay-to-reemission tree: {e:?}"))
                })?
            };
            output_candidates.push(
                ergo_ser::ergo_box::ErgoBoxCandidate::new(
                    *to_burn,
                    pay2r_tree,
                    current_height,
                    vec![],
                    ergo_ser::register::AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletAdminError::Internal(format!("ErgoBoxCandidate (pay2reemission): {e:?}"))
                })?,
            );
        }

        // Change output — emitted unless folded into the fee above. Exact
        // selection (change_erg == 0, no tokens) emits nothing.
        if !change_goes_to_fee && (change_erg > 0 || !change_tokens.is_empty()) {
            let change_tree = {
                let mut r = ergo_primitives::reader::VlqReader::new(&change_ergo_tree);
                ergo_ser::ergo_tree::read_ergo_tree(&mut r)
                    .map_err(|e| WalletAdminError::Internal(format!("change ergo_tree: {e:?}")))?
            };
            let change_token_vec: Vec<ergo_ser::token::Token> = change_tokens
                .iter()
                .map(|(&id, &amt)| ergo_ser::token::Token {
                    token_id: ergo_primitives::digest::Digest32::from_bytes(id),
                    amount: amt,
                })
                .collect();
            output_candidates.push(
                ergo_ser::ergo_box::ErgoBoxCandidate::new(
                    change_erg,
                    change_tree,
                    current_height,
                    change_token_vec,
                    ergo_ser::register::AdditionalRegisters::empty(),
                )
                .map_err(|e| {
                    WalletAdminError::Internal(format!("ErgoBoxCandidate (change): {e:?}"))
                })?,
            );
        }

        let unsigned_tx = ergo_ser::transaction::UnsignedTransaction {
            inputs,
            data_inputs,
            output_candidates,
        };
        let bytes = super::sign_submit::serialize_unsigned_tx(&unsigned_tx)?;

        // Mirror the change-output decision above for the response plan.
        let change_outputs = if !change_goes_to_fee && (change_erg > 0 || !change_tokens.is_empty())
        {
            vec![(change_erg, change_tokens.clone())]
        } else {
            vec![]
        };
        let reemission_burn = reemission_burn.as_ref().map(|(_, to_burn)| {
            (
                reemission_rules
                    .expect("a re-emission burn implies the rules are present")
                    .reemission_token_id,
                *to_burn,
            )
        });
        Ok(BuiltTx {
            bytes,
            selected,
            change_outputs,
            fee: fee_value,
            reemission_burn,
            as_of,
        })
    } else {
        // Automatic box selection from wallet unspent boxes.
        let read_txn = db
            .begin_read()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
        let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
        let unspent = wallet_reader
            .unspent_boxes()
            .map_err(|e| WalletAdminError::Internal(e.to_string()))?;

        let summaries: Vec<ergo_wallet::box_selector::BoxSummary> = unspent
            .iter()
            .map(|wb| ergo_wallet::box_selector::BoxSummary {
                box_id: wb.box_id,
                value: wb.value,
                tokens: wb.assets.iter().copied().collect(),
            })
            .collect();

        let data_inputs: Vec<ergo_ser::input::DataInput> = override_data_inputs
            .unwrap_or(&[])
            .iter()
            .map(|hex_id| {
                let id: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| {
                        WalletAdminError::Internal(format!("bad data input id: {hex_id}"))
                    })?;
                Ok(ergo_ser::input::DataInput {
                    box_id: ergo_primitives::digest::Digest32::from_bytes(id),
                })
            })
            .collect::<Result<_, WalletAdminError>>()?;

        let reemission_rules = chain.reemission_rules();
        let selector = ergo_wallet::box_selector::default::DefaultBoxSelector;
        let builder = ergo_wallet::tx_builder::UnsignedTxBuilder {
            available_summaries: &summaries,
            selector: &selector,
            fee,
            fee_ergo_tree,
            change_ergo_tree,
            current_height,
            min_box_value: MIN_BOX_VALUE,
            data_inputs,
            // EIP-27 burn rules for this net (None off EIP-27). The obligation is
            // evaluated at the candidate height `tip + 1` (the height the validator
            // runs the tx at), while output `creation_height` stays `tip`.
            reemission: reemission_rules,
            reemission_height: current_height.saturating_add(1),
        };

        // The builder itself rejects a burn-triggering build that keeps the
        // re-emission token on a payment output (→ `ReemissionTokenOnOutput`,
        // mapped to `reemission_spend_not_allowed` by `map_build_error`), so the
        // invariant holds even on a direct builder call — no extra guard here.
        let (unsigned_tx, plan) = builder
            .build_with_plan(&payment_reqs)
            .map_err(map_build_error)?;
        let bytes = super::sign_submit::serialize_unsigned_tx(&unsigned_tx)?;

        // Reconstruct the response plan from the builder's `SelectionPlan` + the
        // SHARED change-fold rule, so the reported fee/change match the bytes.
        let change_has_tokens = !plan.change_tokens.is_empty();
        let folded = ergo_wallet::tx_builder::change_goes_to_fee(
            plan.change_erg,
            change_has_tokens,
            MIN_BOX_VALUE,
        );
        let fee_value = if folded { fee + plan.change_erg } else { fee };
        let change_outputs = if !folded && (plan.change_erg > 0 || change_has_tokens) {
            vec![(plan.change_erg, plan.change_tokens.clone())]
        } else {
            vec![]
        };
        let summary_by_id: std::collections::HashMap<
            [u8; 32],
            &ergo_wallet::box_selector::BoxSummary,
        > = summaries.iter().map(|s| (s.box_id, s)).collect();
        let selected: Vec<SelectedInputInfo> = plan
            .selected_ids
            .iter()
            .map(|id| {
                let s = summary_by_id.get(id).ok_or_else(|| {
                    WalletAdminError::Internal("selected box not in summaries".into())
                })?;
                Ok(SelectedInputInfo {
                    box_id: *id,
                    value: s.value,
                    tokens: s.tokens.clone(),
                })
            })
            .collect::<Result<_, WalletAdminError>>()?;
        let reemission_burn = (plan.to_burn > 0).then(|| {
            reemission_rules
                .map(|r| (r.reemission_token_id, plan.to_burn))
                .expect("a re-emission burn implies the rules are present")
        });

        Ok(BuiltTx {
            bytes,
            selected,
            change_outputs,
            fee: fee_value,
            reemission_burn,
            as_of,
        })
    }
}

/// Map an `ergo_wallet` build error to a typed [`WalletAdminError`]. A box-selection
/// shortfall (including a reward-box burn the inputs cannot fund) is a well-formed
/// request the wallet cannot satisfy → `InsufficientFunds(422)`, not `Internal`.
pub(crate) fn map_build_error(e: ergo_wallet::error::WalletError) -> WalletAdminError {
    match &e {
        ergo_wallet::error::WalletError::BoxSelection(m) => {
            WalletAdminError::InsufficientFunds(m.clone())
        }
        ergo_wallet::error::WalletError::ReemissionTokenOnOutput(m) => {
            WalletAdminError::ReemissionSpendNotAllowed(m.clone())
        }
        _ => WalletAdminError::Internal(e.to_string()),
    }
}

/// Parse a decimal-string amount into `u64`. A non-numeric / overflowing value is
/// a client error (`bad_request`), the native amounts being decimal strings.
pub(crate) fn parse_u64_dec(s: &str, field: &str) -> Result<u64, WalletAdminError> {
    s.parse::<u64>()
        .map_err(|_| WalletAdminError::BadRequest(format!("{field}: not a u64 decimal string")))
}

/// Decode a 32-byte hex id, `bad_request` on a malformed value.
pub(crate) fn parse_box_id_hex(s: &str) -> Result<[u8; 32], WalletAdminError> {
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| WalletAdminError::BadRequest(format!("bad 32-byte hex id: {s}")))
}

/// Native asset list (`token_id` hex + decimal `amount`) → `(id, amount)` map.
pub(crate) fn parse_native_assets(
    assets: &[ergo_api::wallet::native::dto::WalletAssetDto],
) -> Result<BTreeMap<[u8; 32], u64>, WalletAdminError> {
    let mut out: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for a in assets {
        let id = parse_box_id_hex(&a.token_id)?;
        let amt = parse_u64_dec(&a.amount, "asset.amount")?;
        let entry = out.entry(id).or_insert(0);
        *entry = entry
            .checked_add(amt)
            .ok_or_else(|| WalletAdminError::BadRequest("asset amount overflow".into()))?;
    }
    Ok(out)
}

/// `(id, amount)` map → native asset DTO list (decimal-string amounts).
pub(crate) fn assets_map_to_dto(
    tokens: &BTreeMap<[u8; 32], u64>,
) -> Vec<ergo_api::wallet::native::dto::WalletAssetDto> {
    tokens
        .iter()
        .map(|(id, amt)| ergo_api::wallet::native::dto::WalletAssetDto {
            token_id: hex::encode(id),
            amount: amt.to_string(),
        })
        .collect()
}

/// The `ReemissionBurn` DTO for a `to_burn` (or `None` when no burn). `to_burn > 0`
/// implies EIP-27 rules are present (the obligation only triggers under them).
pub(crate) fn reemission_burn_dto(
    to_burn: u64,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
) -> Option<ergo_api::wallet::native::dto::ReemissionBurn> {
    (to_burn > 0).then(|| {
        let rules = reemission.expect("a re-emission burn implies the rules are present");
        ergo_api::wallet::native::dto::ReemissionBurn {
            token_id: hex::encode(rules.reemission_token_id),
            tokens_burned: to_burn.to_string(),
            nano_erg_routed: to_burn.to_string(),
        }
    })
}

/// Validate a supplied change address: it must decode as a P2PK for `network` AND
/// be a tracked wallet tree, else `change_address_untracked(422)`.
pub(crate) fn validate_tracked_change_address(
    addr: &str,
    state: &RwLock<ergo_wallet::state::WalletState>,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<(), WalletAdminError> {
    let pubkey = ergo_ser::address::decode_p2pk_address(addr, network)
        .map_err(|_| WalletAdminError::ChangeAddressUntracked)?;
    let tree = ergo_ser::address::build_p2pk_tree_bytes(&pubkey)
        .map_err(|e| WalletAdminError::Internal(format!("change p2pk tree: {e:?}")))?;
    if !state.read().is_tracked_tree(&tree) {
        return Err(WalletAdminError::ChangeAddressUntracked);
    }
    Ok(())
}

/// Burn-aware plan over an EXACT input set (no sub-selection). The explicit
/// `boxIds` path uses this so `boxes/select` and `transactions/build` agree on
/// WHICH boxes are spent (and therefore on the burn) — selecting a subset on one
/// and spending all on the other would let a dry-run under-report the burn. Funds
/// the burn from change only (fee preserved); an exact set whose change cannot
/// cover it is `insufficient_funds`. The re-emission token is stripped from change.
pub(crate) fn exact_set_plan(
    boxes: &[ergo_wallet::box_selector::BoxSummary],
    target_erg: u64,
    target_tokens: &BTreeMap<[u8; 32], u64>,
    reemission: Option<&ergo_validation::ReemissionRuleInputs>,
    reemission_height: u32,
) -> Result<ergo_wallet::tx_builder::SelectionPlan, WalletAdminError> {
    let mut input_erg: u64 = 0;
    let mut input_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for b in boxes {
        input_erg = input_erg
            .checked_add(b.value)
            .ok_or_else(|| WalletAdminError::Internal("input ERG overflow".into()))?;
        for (&id, &amt) in &b.tokens {
            let e = input_tokens.entry(id).or_insert(0);
            *e = e
                .checked_add(amt)
                .ok_or_else(|| WalletAdminError::Internal("input token overflow".into()))?;
        }
    }
    for (id, &req) in target_tokens {
        let have = input_tokens.get(id).copied().unwrap_or(0);
        if have < req {
            return Err(WalletAdminError::InsufficientFunds(format!(
                "explicit inputs hold {have} of token {}, need {req}",
                hex::encode(id)
            )));
        }
    }
    let to_burn = match reemission {
        Some(rules) => {
            ergo_validation::reemission_obligation_core(
                boxes.iter().map(|b| {
                    (
                        b.value,
                        b.tokens
                            .get(&rules.reemission_token_id)
                            .copied()
                            .unwrap_or(0),
                    )
                }),
                reemission_height,
                rules.activation_height,
            )
            .to_burn
        }
        None => 0,
    };
    let needed = target_erg
        .checked_add(to_burn)
        .ok_or_else(|| WalletAdminError::Internal("target + burn overflow".into()))?;
    if input_erg < needed {
        return Err(WalletAdminError::InsufficientFunds(format!(
            "explicit inputs hold {input_erg} nanoErg, need {needed} (target + EIP-27 burn)"
        )));
    }
    let change_erg = input_erg - needed;
    let mut change_tokens: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for (&id, &amt) in &input_tokens {
        let req = target_tokens.get(&id).copied().unwrap_or(0);
        if amt > req {
            change_tokens.insert(id, amt - req);
        }
    }
    if to_burn > 0 {
        if let Some(rules) = reemission {
            change_tokens.remove(&rules.reemission_token_id);
        }
    }
    Ok(ergo_wallet::tx_builder::SelectionPlan {
        selected_ids: boxes.iter().map(|b| b.box_id).collect(),
        change_erg,
        change_tokens,
        to_burn,
    })
}

/// Native `boxes/select`: a read-only, burn-aware selection dry-run over the
/// wallet's confirmed unspent boxes — real selected inputs, the real change plan,
/// and the exact EIP-27 burn. `auto` uses the SHARED `select_with_reemission`;
/// `boxIds` uses the exact set (so it agrees with `transactions/build`).
pub(crate) fn select_boxes_impl(
    req: &ergo_api::wallet::native::dto::BoxSelectRequest,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::native::dto::BoxSelectResponse, WalletAdminError> {
    use ergo_api::wallet::native::dto as ndto;

    let target_erg = parse_u64_dec(&req.target.nano_erg, "target.nanoErg")?;
    let target_tokens = parse_native_assets(&req.target.assets)?;

    // Confirmed unspent set → summaries, narrowed by the input source.
    let read_txn = db
        .begin_read()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let wallet_reader = ergo_state::wallet::reader::WalletReader::new(&read_txn);
    let unspent = wallet_reader
        .unspent_boxes()
        .map_err(|e| WalletAdminError::Internal(e.to_string()))?;
    let mut summaries: Vec<ergo_wallet::box_selector::BoxSummary> = unspent
        .iter()
        .map(|wb| ergo_wallet::box_selector::BoxSummary {
            box_id: wb.box_id,
            value: wb.value,
            tokens: wb.assets.iter().copied().collect(),
        })
        .collect();

    let reemission = chain.reemission_rules();
    let reemission_height = chain.tip_height().saturating_add(1);

    // Narrow to the requested input set, then plan: `auto` sub-selects greedily;
    // `boxIds` uses the EXACT set (same as `transactions/build`).
    let plan = match &req.inputs {
        ndto::InputSource::Auto {
            min_confirmations,
            exclude_box_ids,
        } => {
            // The dry-run reads confirmed boxes (minConfirmations 0); a pool-inclusive
            // or N-deep request is a valid shape not yet wired here.
            if *min_confirmations != 0 {
                return Err(WalletAdminError::UnsupportedIntent);
            }
            let mut excluded: std::collections::HashSet<[u8; 32]> =
                std::collections::HashSet::new();
            for id in exclude_box_ids {
                excluded.insert(parse_box_id_hex(id)?);
            }
            summaries.retain(|s| !excluded.contains(&s.box_id));
            ergo_wallet::tx_builder::select_with_reemission(
                &ergo_wallet::box_selector::default::DefaultBoxSelector,
                &summaries,
                target_erg,
                &target_tokens,
                MIN_BOX_VALUE,
                reemission,
                reemission_height,
            )
            .map_err(map_build_error)?
        }
        ndto::InputSource::BoxIds { box_ids } => {
            let mut wanted: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            for id in box_ids {
                wanted.insert(parse_box_id_hex(id)?);
            }
            summaries.retain(|s| wanted.contains(&s.box_id));
            // Every requested id must be a wallet unspent box.
            if summaries.len() != wanted.len() {
                return Err(WalletAdminError::BoxNotFound);
            }
            exact_set_plan(
                &summaries,
                target_erg,
                &target_tokens,
                reemission,
                reemission_height,
            )?
        }
        ndto::InputSource::Boxes { .. } => return Err(WalletAdminError::UnsupportedIntent),
    };

    if let Some(addr) = &req.change_address {
        validate_tracked_change_address(addr, state, network)?;
    }

    if plan.to_burn > 0 {
        if !req.allow_reemission_spend {
            return Err(WalletAdminError::ReemissionSpendNotAllowed(format!(
                "selection includes a reward box; {} re-emission token(s) would be burned \
                 (set allowReemissionSpend to permit it)",
                plan.to_burn
            )));
        }
        // The re-emission token may not be a selection target: when a reward box is
        // spent it can only be burned, never delivered to an output.
        if let Some(rules) = reemission {
            if target_tokens
                .get(&rules.reemission_token_id)
                .is_some_and(|&a| a > 0)
            {
                return Err(WalletAdminError::ReemissionSpendNotAllowed(
                    "the re-emission token cannot be a selection target; it is burned \
                     when a reward box is spent"
                        .into(),
                ));
            }
        }
    }

    let summary_by_id: std::collections::HashMap<[u8; 32], &ergo_wallet::box_selector::BoxSummary> =
        summaries.iter().map(|s| (s.box_id, s)).collect();
    let inputs_selected = plan
        .selected_ids
        .iter()
        .map(|id| {
            let s = summary_by_id.get(id).ok_or_else(|| {
                WalletAdminError::Internal("selected box not in summaries".into())
            })?;
            Ok(ndto::SelectedBoxRef {
                box_id: hex::encode(id),
                value: s.value.to_string(),
                assets: assets_map_to_dto(&s.tokens),
            })
        })
        .collect::<Result<_, WalletAdminError>>()?;

    Ok(ndto::BoxSelectResponse {
        inputs_selected,
        change: ndto::ChangePlan {
            nano_erg: plan.change_erg.to_string(),
            assets: assets_map_to_dto(&plan.change_tokens),
        },
        reemission_burn: reemission_burn_dto(plan.to_burn, reemission),
        as_of: chain.wallet_scan_height(),
    })
}

/// Native `transactions/build`: map a [`TxIntent`] to the burn-aware
/// [`build_unsigned_tx`] and report exactly what was built. `payment` outputs are
/// load-bearing; `mint`/`burn`/`payment.registers` and inline-serialized box
/// sources ship `unsupported_intent(422)` until wired (a later 422→200 for the
/// same well-formed request).
pub(crate) async fn build_transaction_impl(
    intent: &ergo_api::wallet::native::dto::TxIntent,
    state: &RwLock<ergo_wallet::state::WalletState>,
    db: &redb::Database,
    chain: &dyn ChainStateAccessor,
    network: ergo_ser::address::NetworkPrefix,
) -> Result<ergo_api::wallet::native::dto::BuildTxResponse, WalletAdminError> {
    use ergo_api::wallet::native::dto as ndto;

    if intent.outputs.is_empty() {
        return Err(WalletAdminError::BadRequest(
            "at least one output is required".into(),
        ));
    }
    let mut payment_reqs: Vec<PaymentRequestDto> = Vec::with_capacity(intent.outputs.len());
    for o in &intent.outputs {
        match o {
            ndto::OutputIntent::Payment {
                address,
                value,
                assets,
                registers,
            } => {
                if registers.is_some() {
                    return Err(WalletAdminError::UnsupportedIntent);
                }
                let assets = assets
                    .iter()
                    .map(|a| {
                        Ok(ergo_api::wallet::sending::AssetDto {
                            token_id: a.token_id.clone(),
                            amount: parse_u64_dec(&a.amount, "output asset amount")?,
                        })
                    })
                    .collect::<Result<_, WalletAdminError>>()?;
                payment_reqs.push(PaymentRequestDto {
                    address: address.clone(),
                    value: parse_u64_dec(value, "output value")?,
                    assets,
                });
            }
            ndto::OutputIntent::Mint { .. } | ndto::OutputIntent::Burn { .. } => {
                return Err(WalletAdminError::UnsupportedIntent);
            }
        }
    }

    let fee_override = match &intent.fee {
        Some(f) => Some(parse_u64_dec(f, "fee")?),
        None => None,
    };

    let override_inputs: Option<Vec<String>> = match &intent.inputs {
        ndto::InputSource::Auto {
            min_confirmations,
            exclude_box_ids,
        } => {
            // The build path selects over confirmed boxes; pool-inclusive selection
            // and explicit excludes are valid shapes not yet wired here.
            if *min_confirmations != 0 || !exclude_box_ids.is_empty() {
                return Err(WalletAdminError::UnsupportedIntent);
            }
            None
        }
        ndto::InputSource::BoxIds { box_ids } => Some(box_ids.clone()),
        ndto::InputSource::Boxes { .. } => return Err(WalletAdminError::UnsupportedIntent),
    };
    let override_data_inputs: Option<Vec<String>> = match &intent.data_inputs {
        ndto::DataInputSource::BoxIds { box_ids } => (!box_ids.is_empty()).then(|| box_ids.clone()),
        ndto::DataInputSource::Boxes { .. } => return Err(WalletAdminError::UnsupportedIntent),
    };

    let built = build_unsigned_tx(
        &payment_reqs,
        override_inputs.as_deref(),
        override_data_inputs.as_deref(),
        fee_override,
        intent.change_address.as_deref(),
        state,
        db,
        chain,
        network,
    )
    .await?;

    // Fail-closed: a reward-box spend (EIP-27 burn) needs explicit opt-in.
    if built.reemission_burn.is_some() && !intent.allow_reemission_spend {
        return Err(WalletAdminError::ReemissionSpendNotAllowed(
            "the build spends a reward box; set allowReemissionSpend to permit it".into(),
        ));
    }

    let reemission_burn = built
        .reemission_burn
        .map(|(token_id, to_burn)| ndto::ReemissionBurn {
            token_id: hex::encode(token_id),
            tokens_burned: to_burn.to_string(),
            nano_erg_routed: to_burn.to_string(),
        });
    let inputs_selected = built
        .selected
        .iter()
        .map(|s| ndto::SelectedBoxRef {
            box_id: hex::encode(s.box_id),
            value: s.value.to_string(),
            assets: assets_map_to_dto(&s.tokens),
        })
        .collect();
    let change_outputs = built
        .change_outputs
        .iter()
        .map(|(erg, tokens)| ndto::ChangePlan {
            nano_erg: erg.to_string(),
            assets: assets_map_to_dto(tokens),
        })
        .collect();

    Ok(ndto::BuildTxResponse {
        unsigned_transaction: ndto::TxRepr::from_bytes(&built.bytes),
        inputs_selected,
        change_outputs,
        fee: built.fee.to_string(),
        reemission_burn,
        as_of: built.as_of,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::address::NetworkPrefix;

    /// Real mainnet pay-to-reemission contract tree (valid; header byte 0x19).
    const PAY2R_HEX: &str = "193c03040004000e20d3feeffa87f2df63a7a15b4905e618ae3ce4c69a7975f171bd314d0b877927b8d1938cb2e4c6b2a5730000020c4d0e730100017302";
    const REEMISSION_TOKEN: [u8; 32] = [0x11; 32];

    /// A valid mainnet P2PK address derived from the secp256k1 generator pubkey
    /// (used as both change + recipient here).
    fn test_addr() -> String {
        let pk: [u8; 33] =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .try_into()
                .unwrap();
        ergo_wallet::address::pubkey_to_p2pk_address(&pk, NetworkPrefix::Mainnet).unwrap()
    }

    struct BurnTestChain {
        reward_id: [u8; 32],
        reward_box: ergo_ser::ergo_box::ErgoBox,
        rules: ergo_validation::ReemissionRuleInputs,
        tip: u32,
    }

    impl ChainStateAccessor for BurnTestChain {
        fn wallet_scan_height(&self) -> u32 {
            self.tip
        }
        fn tip_height(&self) -> u32 {
            self.tip
        }
        fn is_pruned(&self) -> bool {
            false
        }
        fn read_block_at(&self, _h: u32) -> Option<ergo_state::wallet::scan::RescanBlock> {
            None
        }
        fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
            Some(&self.rules)
        }
        fn lookup_utxo(&self, box_id: &[u8; 32]) -> Option<ergo_ser::ergo_box::ErgoBox> {
            (box_id == &self.reward_id).then(|| self.reward_box.clone())
        }
    }

    fn p2pk_tree(addr: &str) -> ergo_ser::ergo_tree::ErgoTree {
        let pk = ergo_ser::address::decode_p2pk_address(addr, NetworkPrefix::Mainnet).unwrap();
        let bytes = ergo_ser::address::build_p2pk_tree_bytes(&pk).unwrap();
        let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
        ergo_ser::ergo_tree::read_ergo_tree(&mut r).unwrap()
    }

    /// ORACLE: an explicit-input spend of a reward box (value <= floor, carrying
    /// the re-emission token) at a height past activation must BURN the token (no
    /// output keeps it) and pay exactly `to_burn` nanoErg to the pay-to-reemission
    /// contract — the structure the consensus validator requires.
    #[tokio::test]
    async fn explicit_input_reward_box_spend_burns_and_pays_reemission() {
        let addr = test_addr();
        let reward_id = [0xAA; 32];
        let reward_box = ergo_ser::ergo_box::ErgoBox {
            candidate: ergo_ser::ergo_box::ErgoBoxCandidate::new(
                15_000_000_000, // 15 ERG, <= 100k ERG floor → reward box
                p2pk_tree(&addr),
                100,
                vec![ergo_ser::token::Token {
                    token_id: ergo_primitives::digest::Digest32::from_bytes(REEMISSION_TOKEN),
                    amount: 12_000_000_000, // 12e9 re-emission tokens → to_burn = 12e9 nanoErg
                }],
                ergo_ser::register::AdditionalRegisters::empty(),
            )
            .unwrap(),
            transaction_id: ergo_primitives::digest::ModifierId::from(
                ergo_primitives::digest::Digest32::from_bytes([0xBB; 32]),
            ),
            index: 0,
        };
        let pay2r_tree = hex::decode(PAY2R_HEX).unwrap();
        let chain = BurnTestChain {
            reward_id,
            reward_box,
            rules: ergo_validation::ReemissionRuleInputs {
                activation_height: 100,
                reemission_token_id: REEMISSION_TOKEN,
                pay_to_reemission_tree: pay2r_tree.clone(),
            },
            tip: 200, // candidate height 201 > activation 100 → burn triggers
        };

        let mut ws = ergo_wallet::state::WalletState::empty(false);
        ws.set_change_address(addr.clone());
        let state = RwLock::new(ws);

        let dir = tempfile::tempdir().unwrap();
        let db = redb::Database::create(dir.path().join("w.redb")).unwrap();

        let requests = vec![PaymentRequestDto {
            address: addr.clone(),
            value: 1_000_000_000,
            assets: vec![],
        }];
        let override_inputs = vec![hex::encode(reward_id)];

        let bytes = build_unsigned_tx(
            &requests,
            Some(&override_inputs),
            None,
            None,
            None, // change_address_override
            &state,
            &db,
            &chain,
            NetworkPrefix::Mainnet,
        )
        .await
        .expect("burn-aware build of a reward-box spend must succeed")
        .bytes;

        let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
        let utx = ergo_ser::transaction::read_unsigned_transaction(&mut r).unwrap();

        // (a) NO output keeps the re-emission token (it must be burned).
        for out in &utx.output_candidates {
            assert!(
                !out.tokens
                    .iter()
                    .any(|t| t.token_id.as_bytes() == &REEMISSION_TOKEN),
                "no output may keep the re-emission token",
            );
        }

        // (b) Exactly `to_burn` (12e9) nanoErg goes to the pay-to-reemission tree.
        let pay2r_header = pay2r_tree.first().copied();
        let pay2r_parsed = {
            let mut pr = ergo_primitives::reader::VlqReader::new(&pay2r_tree);
            ergo_ser::ergo_tree::read_ergo_tree(&mut pr).unwrap()
        };
        let paid: u64 = utx
            .output_candidates
            .iter()
            .filter(|o| {
                o.ergo_tree_bytes().first().copied() == pay2r_header
                    && *o.ergo_tree() == pay2r_parsed
            })
            .map(|o| o.value)
            .sum();
        assert_eq!(
            paid, 12_000_000_000,
            "must pay exactly to_burn nanoErg to pay-to-reemission",
        );

        // (c) the explicit branch funds the burn from CHANGE ONLY — the
        // requested fee is preserved (NOT shaved), matching the auto branch.
        let fee_tree_bytes = ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES;
        let fee_paid: u64 = utx
            .output_candidates
            .iter()
            .filter(|o| o.ergo_tree_bytes() == fee_tree_bytes)
            .map(|o| o.value)
            .sum();
        assert_eq!(
            fee_paid, MIN_FEE,
            "the miner fee must be preserved (burn funded from change, not fee)",
        );
    }
}

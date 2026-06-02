//! Box selection: choose UTXO subset that funds a payment.
//!
//! Two implementations per Scala:
//! - DefaultBoxSelector: greedy by value DESC (default)
//! - ReplaceCompactCollectBoxSelector: compaction-aware (currently delegates
//!   to DefaultBoxSelector; full compaction optimization not yet implemented)

use crate::error::WalletError;
use std::collections::BTreeMap;

/// What the selector must cover.
#[derive(Debug, Clone)]
pub struct SelectionTarget {
    /// Required ERG (nanoERG) including fee + outputs.
    pub erg_amount: u64,
    /// Token id → required amount.
    pub tokens: BTreeMap<[u8; 32], u64>,
    /// Minimum change box ERG if any (typically the network's minBoxValue).
    /// When the natural change would be less than this, the selector must
    /// accumulate additional boxes until change >= min_change_value (or == 0).
    pub min_change_value: u64,
}

/// Selection-time summary of a wallet box. Built from WALLET_BOXES rows
/// (which store value + tokens; see ergo-state's WalletBox). The selector
/// does not need full ErgoTree bytes — only value + tokens. Full ErgoBox
/// data is fetched via `ChainStateAccessor::lookup_utxo` at the
/// writer-task boundary.
#[derive(Debug, Clone)]
pub struct BoxSummary {
    pub box_id: [u8; 32],
    pub value: u64,
    pub tokens: BTreeMap<[u8; 32], u64>,
}

/// What the selector returns: selected box ids + change metadata.
/// Caller fetches full ErgoBox bytes via `ChainStateAccessor::lookup_utxo`
/// post-selection.
#[derive(Debug, Clone)]
pub struct SelectionResult {
    /// Box ids to spend, in selector-preferred order.
    pub selected_ids: Vec<[u8; 32]>,
    /// Change tokens (input tokens − target tokens). Empty when no surplus.
    pub change_tokens: BTreeMap<[u8; 32], u64>,
    /// Change ERG (total input ERG − target ERG). Zero on exact match.
    pub change_erg: u64,
}

/// Selects a subset of wallet boxes that covers a payment target.
pub trait BoxSelector {
    /// `candidates` is a SUMMARY view: `(box_id, value, tokens)` tuples from
    /// WALLET_BOXES (the wallet's tracked-set). Returns selected box ids and
    /// change amounts on success, or `WalletError::BoxSelection` if no valid
    /// selection exists (insufficient funds, missing token, etc.).
    fn select(
        &self,
        candidates: &[BoxSummary],
        target: &SelectionTarget,
    ) -> Result<SelectionResult, WalletError>;
}

pub mod default;
pub mod replace_compact;

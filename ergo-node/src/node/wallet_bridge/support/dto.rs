//! DTO conversion helpers: box/tx status strings, wallet-row → wire-entry
//! projections, and pagination.

use ergo_api::wallet::types::{
    Page, WalletBoxEntry, WalletBoxesPage, WalletTransactionEntry, WalletTransactionsPage,
};

pub(crate) fn box_status_str(status: &ergo_state::wallet::types::BoxStatus) -> String {
    match status {
        ergo_state::wallet::types::BoxStatus::Confirmed => "Confirmed".to_string(),
        ergo_state::wallet::types::BoxStatus::Immature { .. } => "Immature".to_string(),
        ergo_state::wallet::types::BoxStatus::Spent { .. } => "Spent".to_string(),
    }
}

pub(crate) fn box_provenance_str(provenance: &ergo_state::wallet::types::BoxProvenance) -> String {
    match provenance {
        ergo_state::wallet::types::BoxProvenance::Owned => "Owned".to_string(),
        ergo_state::wallet::types::BoxProvenance::MinerReward => "MinerReward".to_string(),
        ergo_state::wallet::types::BoxProvenance::Custom { .. } => "Custom".to_string(),
    }
}

pub(crate) fn wallet_box_to_entry(wb: ergo_state::wallet::types::WalletBox) -> WalletBoxEntry {
    WalletBoxEntry {
        box_id: hex::encode(wb.box_id),
        value: wb.value,
        creation_height: wb.creation_height,
        status: box_status_str(&wb.status),
        provenance: box_provenance_str(&wb.provenance),
    }
}

pub(crate) fn wallet_tx_to_entry(
    wt: ergo_state::wallet::types::WalletTransaction,
) -> WalletTransactionEntry {
    WalletTransactionEntry {
        tx_id: hex::encode(wt.tx_id),
        block_height: wt.block_height,
        block_id: hex::encode(wt.block_id),
        wallet_outputs: wt.wallet_outputs.iter().map(hex::encode).collect(),
        wallet_inputs: wt.wallet_inputs.iter().map(hex::encode).collect(),
        // Wallet rows carry no scan tagging; empty is omitted from the wire,
        // keeping the existing wallet listing shape unchanged.
        scan_ids: Vec::new(),
    }
}

pub(crate) fn paginate_boxes(
    all: Vec<ergo_state::wallet::types::WalletBox>,
    page: Page,
) -> WalletBoxesPage {
    let total = all.len() as u32;
    let offset = page.offset as usize;
    let limit = page.limit as usize;
    let items = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(wallet_box_to_entry)
        .collect();
    WalletBoxesPage { total, items }
}

pub(crate) fn paginate_transactions(
    all: Vec<ergo_state::wallet::types::WalletTransaction>,
    page: Page,
) -> WalletTransactionsPage {
    let total = all.len() as u32;
    let offset = page.offset as usize;
    let limit = page.limit as usize;
    let items = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(wallet_tx_to_entry)
        .collect();
    WalletTransactionsPage { total, items }
}

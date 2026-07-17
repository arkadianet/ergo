//! Mempool-transaction projection: mempool entries → the API DTO list,
//! one entry per pooled transaction with its priority/fee/age fields.

use std::time::Instant;

use ergo_api::types::{
    ApiMempoolTransaction, ApiMempoolTransactions, ApiTxSource, ApiWeightFunction,
};
use ergo_mempool::types::TxSource;
use ergo_mempool::Mempool;

pub(super) fn project_mempool_transactions(
    mempool: &Mempool,
    weight_function: ApiWeightFunction,
    snapshot_built_at: Instant,
    now_unix_ms: u64,
) -> ApiMempoolTransactions {
    let transactions: Vec<ApiMempoolTransaction> = mempool
        .iter_transactions()
        .map(|entry| {
            let first_seen_age_ms = snapshot_built_at
                .saturating_duration_since(entry.created_at)
                .as_millis() as u64;
            let last_checked_age_ms = snapshot_built_at
                .saturating_duration_since(entry.last_checked_at)
                .as_millis() as u64;
            let source = match &entry.source {
                TxSource::Peer(peer) => ApiTxSource::Peer {
                    addr: peer.to_string(),
                },
                TxSource::Api => ApiTxSource::Api,
                TxSource::Wallet => ApiTxSource::Wallet,
                TxSource::DemotedFromBlock => ApiTxSource::DemotedFromBlock,
            };
            ApiMempoolTransaction {
                tx_id: hex::encode(entry.tx_id.as_bytes()),
                fee_nano_erg: entry.fee,
                fee_per_byte_nano_erg: if entry.size_bytes > 0 {
                    entry.fee / entry.size_bytes as u64
                } else {
                    0
                },
                size_bytes: entry.size_bytes,
                validation_cost_units: entry.cost,
                priority_weight: entry.weight,
                source,
                input_count: entry.inputs.len() as u32,
                output_count: entry.outputs.len() as u32,
                parents_in_pool: entry.parents_in_pool.len() as u32,
                first_seen_unix_ms: now_unix_ms.saturating_sub(first_seen_age_ms),
                first_seen_age_ms,
                last_checked_age_ms,
            }
        })
        .collect();
    ApiMempoolTransactions {
        transactions,
        weight_function,
    }
}

// =====================================================================
// Fee-stats helpers
// =====================================================================
//
// `poolHistogram` / `getFee` / `waitTime` all depend on a per-tx
// fee-per-byte ranking of the current pool. The helpers below build
// that ranking from a snapshot's `pool_full_txs` in a single pass.
// `bins` and `maxtime` are caller-supplied (OpenAPI defaults
// `10` / `60000`), so they aren't constants here.

use super::parse_pool_tx;

/// Long-range estimates lose accuracy; cap forecasts at one day.
pub(super) const MAX_ESTIMATE_WAIT_MS: u64 = 86_400_000;
/// Scalar compatibility endpoints have no nullable result; this sentinel
/// denotes unknown wait. The operator fee-estimate endpoint reports null.
pub(super) const UNKNOWN_WAIT_MS: u64 = u64::MAX;

/// Server-side cap on the `bins` query parameter for
/// `/transactions/poolHistogram`. Larger requests are silently
/// clamped (caller still gets a valid histogram, just shorter
/// than asked). OpenAPI sets no maximum, but unbounded allocation
/// on a path that's reachable without auth is a DoS surface.
/// 4096 is well beyond any operator-tooling visualization need
/// (Scala node defaults to 10).
pub(super) const MAX_HISTOGRAM_BINS: usize = 4096;

#[derive(Clone, Copy)]
pub(super) struct PoolFeeEntry {
    pub(super) fee: u64,
    pub(super) fee_per_byte: u64,
    pub(super) size_bytes: u64,
    pub(super) cost_units: u64,
}

pub(super) struct PoolFeeRankingCache {
    pub snapshot: std::sync::Weak<crate::snapshot::NodeSnapshot>,
    pub ranked: std::sync::Arc<[PoolFeeEntry]>,
}

/// Build a fee-per-byte descending ranking of every pool tx in the
/// snapshot. Parse-failures and zero-fee txs are dropped (a tx
/// with no fee output cannot land via the normal admission path —
/// Scala mempool rejects them upstream).
///
/// Tie-break: pool entries with equal `fee_per_byte` retain the
/// order `pool_full_txs` gives us, which is `Mempool::iter_transactions`
/// in relay-priority order (`ergo-mempool::pool::iter_transactions`).
/// Under the default `cost`-based weighting that means
/// weight-then-tx-id ordering, NOT insertion order. The exact
/// tie-break only matters for the rank-position assignment when
/// many pool txs sit at the same fee/byte tier — the histogram and
/// fee-suggestion results are insensitive to it because the
/// downstream capacity projection aggregates bytes and observed admission
/// costs rather than assuming a constant transaction count.
pub(super) fn rank_pool_by_fee_per_byte(
    pool: &[(ergo_primitives::digest::Digest32, std::sync::Arc<[u8]>)],
    costs: &std::collections::HashMap<&str, u64>,
) -> Vec<PoolFeeEntry> {
    let mut entries: Vec<PoolFeeEntry> = pool
        .iter()
        .filter_map(|(id, bytes)| {
            let tx = parse_pool_tx(bytes)?;
            let fee: u64 = tx
                .output_candidates
                .iter()
                .filter(|c| {
                    c.ergo_tree_bytes() == ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES
                })
                .fold(0u64, |total, output| total.saturating_add(output.value));
            if fee == 0 {
                return None;
            }
            let size = bytes.len() as u64;
            if size == 0 {
                return None;
            }
            Some(PoolFeeEntry {
                fee,
                fee_per_byte: fee / size,
                size_bytes: size,
                cost_units: costs
                    .get(hex::encode(id.as_bytes()).as_str())
                    .copied()
                    .unwrap_or(0),
            })
        })
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.fee_per_byte));
    entries
}

#[derive(Debug, Clone)]
pub(super) struct FeeCapacityModel {
    pub interval_ms: u64,
    pub bytes_per_block: u64,
    pub cost_per_block: u64,
    pub median_fee_rate: Option<u64>,
    pub sample_blocks: u32,
    pub confirmed_transactions: u32,
}

fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

impl FeeCapacityModel {
    /// Canonical newest-first contiguous samples. Removed forks and missing
    /// sections cannot silently remain in the estimation window.
    pub fn from_blocks(
        blocks: &[ergo_api::types::ApiRecentBlock],
        max_bytes: u64,
        max_cost: u64,
    ) -> Option<Self> {
        if blocks.len() < 4 || max_bytes == 0 || max_cost == 0 {
            return None;
        }
        if !blocks
            .windows(2)
            .all(|pair| pair[0].height.checked_sub(1) == Some(pair[1].height))
        {
            return None;
        }
        let mut intervals: Vec<_> = blocks
            .windows(2)
            .filter_map(|pair| pair[0].ts_unix_ms.checked_sub(pair[1].ts_unix_ms))
            .filter(|interval| (1_000..=1_800_000).contains(interval))
            .collect();
        if intervals.len() < 3 {
            return None;
        }
        let interval_ms = median(&mut intervals)?;
        let mut overheads = Vec::new();
        let mut rates = Vec::new();
        let mut confirmed_transactions = 0u32;
        for block in blocks {
            let sample = block.fee_observation.as_ref()?;
            if sample.fee_paying_size_bytes > sample.transactions_size_bytes {
                return None;
            }
            overheads.push(
                sample
                    .transactions_size_bytes
                    .saturating_sub(sample.fee_paying_size_bytes),
            );
            confirmed_transactions =
                confirmed_transactions.saturating_add(sample.fee_paying_transactions);
            if let Some(rate) = sample.median_fee_per_byte_nano_erg {
                rates.push(rate);
            }
        }
        if confirmed_transactions < 3 {
            return None;
        }
        let overhead = median(&mut overheads)?;
        let bytes_per_block = max_bytes.checked_sub(overhead)?.max(1);
        let cost_per_block = max_cost
            .saturating_sub(ergo_mining::tx_selection::block_cost_safety_gap(max_cost))
            .max(1);
        Some(Self {
            interval_ms,
            bytes_per_block,
            cost_per_block,
            median_fee_rate: median(&mut rates),
            sample_blocks: blocks.len() as u32,
            confirmed_transactions,
        })
    }

    pub fn wait_ms(&self, bytes: u64, cost: u64) -> (u64, bool) {
        let blocks = bytes
            .div_ceil(self.bytes_per_block)
            .max(cost.div_ceil(self.cost_per_block))
            .max(1);
        let wait = blocks.saturating_mul(self.interval_ms);
        (wait.min(MAX_ESTIMATE_WAIT_MS), wait > MAX_ESTIMATE_WAIT_MS)
    }

    pub fn recommendation(
        &self,
        ranked: &[PoolFeeEntry],
        target_ms: u64,
        size: u32,
        cost: u64,
        floor: u64,
    ) -> u64 {
        let blocks = (target_ms / self.interval_ms).max(1);
        let byte_budget = self.bytes_per_block.saturating_mul(blocks);
        let cost_budget = self.cost_per_block.saturating_mul(blocks);
        let mut bytes = u64::from(size);
        let mut costs = cost;
        let mut threshold = 0;
        // Bid just above the first transaction that cannot fit ahead of us in
        // the target budget. A short/empty pool needs no congestion premium.
        for entry in ranked {
            bytes = bytes.saturating_add(entry.size_bytes);
            costs = costs.saturating_add(entry.cost_units);
            if bytes > byte_budget || costs > cost_budget {
                threshold = entry.fee_per_byte.saturating_add(1);
                break;
            }
        }
        threshold.saturating_mul(u64::from(size)).max(floor)
    }

    pub fn wait_for_fee(
        &self,
        ranked: &[PoolFeeEntry],
        fee: u64,
        size: u32,
        cost: u64,
    ) -> (u64, bool) {
        let rate = fee / u64::from(size.max(1));
        let (bytes, costs) = ranked
            .iter()
            .take_while(|entry| entry.fee_per_byte >= rate)
            .fold((u64::from(size), cost), |(bytes, cost), entry| {
                (
                    bytes.saturating_add(entry.size_bytes),
                    cost.saturating_add(entry.cost_units),
                )
            });
        self.wait_ms(bytes, costs)
    }
}

pub(super) fn bin_for_wait_ms(wait_ms: u64, bins: usize, maxtime_ms: u64) -> usize {
    if maxtime_ms == 0 || wait_ms >= maxtime_ms {
        return bins;
    }
    // Bin formula straight from the OpenAPI spec:
    //   bin_i = [i*maxtime/bins, (i+1)*maxtime/bins)
    // Inverted to find the bin for a given wait:
    //   i = wait * bins / maxtime
    // Compute as `wait * bins` BEFORE dividing by `maxtime` so the
    // formula is exact for non-divisible (`maxtime % bins != 0`)
    // cases. `u64::MAX * u64::MAX` overflows u64; widen to u128 to
    // keep the spec result correct on any 64-bit input.
    let widened = (wait_ms as u128) * (bins as u128) / (maxtime_ms as u128);
    // The pre-check `wait_ms < maxtime_ms` guarantees `widened < bins`
    // when bins fits in usize, but clamp anyway to keep the index
    // safe under hypothetical input combinations the type system
    // can't rule out (e.g. `bins == usize::MAX` on a 32-bit target).
    let idx = widened.min(usize::MAX as u128) as usize;
    idx.min(bins.saturating_sub(1))
}

#[cfg(test)]
mod bin_for_wait_ms_tests {
    use super::*;

    /// Pin the bin formula for the non-divisible case
    /// (`maxtime % bins != 0`). For `bins=3, maxtime=100`, the
    /// OpenAPI bin definition is
    /// `[0,33.33), [33.33,66.66), [66.66,100)`. Pre-dividing
    /// `maxtime/bins = 33` and then `wait/33` for `wait=66` would
    /// return 2 (wrong); `wait*bins/maxtime` returns 1 (correct).
    #[test]
    fn bin_formula_handles_non_divisible_maxtime() {
        // Edges and interior of each bin under bins=3 / maxtime=100.
        assert_eq!(bin_for_wait_ms(0, 3, 100), 0);
        assert_eq!(bin_for_wait_ms(33, 3, 100), 0); // 33 * 3 / 100 = 0
        assert_eq!(bin_for_wait_ms(34, 3, 100), 1); // 34 * 3 / 100 = 1
        assert_eq!(bin_for_wait_ms(66, 3, 100), 1); // 66 * 3 / 100 = 1 (NOT 2)
        assert_eq!(bin_for_wait_ms(67, 3, 100), 2); // 67 * 3 / 100 = 2
        assert_eq!(bin_for_wait_ms(99, 3, 100), 2);
        // Overflow bin: wait >= maxtime
        assert_eq!(bin_for_wait_ms(100, 3, 100), 3);
        assert_eq!(bin_for_wait_ms(200, 3, 100), 3);
        // maxtime=0 short-circuits to overflow bin
        assert_eq!(bin_for_wait_ms(0, 3, 0), 3);
    }

    /// Pin the OpenAPI defaults (bins=10, maxtime=60000ms = 60s).
    /// Each bin is exactly 6000 ms wide; no rounding wrinkle.
    #[test]
    fn bin_formula_default_window_is_evenly_divisible() {
        assert_eq!(bin_for_wait_ms(0, 10, 60_000), 0);
        assert_eq!(bin_for_wait_ms(5_999, 10, 60_000), 0);
        assert_eq!(bin_for_wait_ms(6_000, 10, 60_000), 1);
        assert_eq!(bin_for_wait_ms(59_999, 10, 60_000), 9);
        assert_eq!(bin_for_wait_ms(60_000, 10, 60_000), 10); // overflow
    }

    /// Adversarial case where `wait_ms * bins` would overflow u64.
    /// A u64 `saturating_mul` would clamp to `u64::MAX` and produce
    /// wrong bin indices for these inputs; the u128 widening
    /// computes the spec-exact result.
    ///
    /// Test case: `wait = u64::MAX - 2`, `maxtime = u64::MAX - 1`,
    /// `bins = 3`. Spec formula `floor(wait * bins / maxtime)` =
    /// `floor(((u64::MAX - 2) * 3) / (u64::MAX - 1))`. With u128
    /// widening: numerator ≈ 3 * (u64::MAX - 2), divided by
    /// (u64::MAX - 1) gives 2 (the correct bin). A u64
    /// `saturating_mul` would give 1.
    #[test]
    fn bin_formula_handles_overflow_via_u128_widening() {
        let big_wait = u64::MAX - 2;
        let big_max = u64::MAX - 1;
        assert_eq!(bin_for_wait_ms(big_wait, 3, big_max), 2);
        // Sanity: smaller variant that does NOT overflow u64.
        // wait = 998, max = 1000, bins = 3 → floor(998*3/1000) = 2.
        assert_eq!(bin_for_wait_ms(998, 3, 1000), 2);
    }
}

#[cfg(test)]
mod observed_capacity_tests {
    use super::*;
    use ergo_api::types::{ApiBlockFeeObservation, ApiRecentBlock};

    fn samples(interval: u64, rate: u64) -> Vec<ApiRecentBlock> {
        (0..8)
            .map(|offset| ApiRecentBlock {
                height: 100 - offset,
                header_id: format!("{offset:064x}"),
                ts_unix_ms: 10_000_000 - u64::from(offset) * interval,
                txs: 4,
                size_bytes: 1200,
                delivered_by: None,
                miner_pk: None,
                miner_address: None,
                fee_observation: Some(ApiBlockFeeObservation {
                    transactions_size_bytes: 1100,
                    fee_paying_transactions: 2,
                    fee_paying_size_bytes: 1000,
                    median_fee_per_byte_nano_erg: Some(rate),
                }),
            })
            .collect()
    }

    #[test]
    fn observed_intervals_and_byte_cost_budgets_replace_fixed_transaction_counts() {
        let model = FeeCapacityModel::from_blocks(&samples(30_000, 5), 1100, 10_000).unwrap();
        assert_eq!(model.interval_ms, 30_000);
        assert_eq!(model.bytes_per_block, 1000);
        assert_eq!(model.confirmed_transactions, 16);
        assert_eq!(model.wait_ms(1001, 0).0, 60_000);
        assert_eq!(model.wait_ms(1, model.cost_per_block + 1).0, 60_000);
        let ranked = vec![PoolFeeEntry {
            fee: 20_000,
            fee_per_byte: 20,
            size_bytes: 950,
            cost_units: 1,
        }];
        assert_eq!(model.recommendation(&ranked, 30_000, 100, 0, 1000), 2100);
        assert_eq!(model.recommendation(&ranked, 60_000, 100, 0, 1000), 1000);
        assert_eq!(
            model.wait_for_fee(&ranked, 2000, 100, 0).0,
            60_000,
            "equal fee-rate txs queue ahead"
        );
        assert_eq!(model.wait_for_fee(&ranked, 2100, 100, 0).0, 30_000);
        assert_eq!(
            model.wait_ms(u64::MAX, u64::MAX),
            (MAX_ESTIMATE_WAIT_MS, true)
        );
    }

    #[test]
    fn insufficient_or_gapped_observations_are_unknown_and_reorg_samples_replace_old_rates() {
        let mut blocks = samples(120_000, 500);
        assert!(FeeCapacityModel::from_blocks(&blocks[..3], 1100, 10_000).is_none());
        blocks[3].height -= 1;
        assert!(FeeCapacityModel::from_blocks(&blocks, 1100, 10_000).is_none());
        let mut blocks = samples(120_000, 500);
        for block in &mut blocks {
            block
                .fee_observation
                .as_mut()
                .unwrap()
                .fee_paying_transactions = 0;
        }
        assert!(FeeCapacityModel::from_blocks(&blocks, 1100, 10_000).is_none());
        let previous = FeeCapacityModel::from_blocks(&samples(120_000, 500), 1100, 10_000).unwrap();
        let replacement = FeeCapacityModel::from_blocks(&samples(60_000, 2), 1100, 10_000).unwrap();
        assert_eq!(previous.median_fee_rate, Some(500));
        assert_eq!(replacement.median_fee_rate, Some(2));
        assert_eq!(replacement.interval_ms, 60_000);
    }
}

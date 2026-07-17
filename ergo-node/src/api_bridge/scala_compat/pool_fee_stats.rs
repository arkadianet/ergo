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

/// `[proposed]` Assumed block time used to convert fee-rank to a
/// wait estimate. Ergo's mainnet target is 120 s; constant because
/// per-block-time observability is not on the snapshot. Operators
/// on testnet/devnet with different timing will see proportionally
/// scaled estimates — acceptable for a hint API.
pub(super) const BLOCK_TIME_MS: u64 = 120_000;

/// `[proposed]` Assumed transactions-per-block divisor for the
/// fee-rank → wait-time conversion. Mainnet block size ~512 KB; a
/// typical tx is ~1 KB → roughly 500 txs/fully-packed block. Real
/// fill rate varies wildly — stand-in until the snapshot carries
/// recent-block-fill data.
pub(super) const TX_PER_BLOCK: u64 = 500;

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
/// downstream `(rank / TX_PER_BLOCK) * BLOCK_TIME_MS` bucketing
/// rounds away the individual positions.
pub(super) fn rank_pool_by_fee_per_byte(
    pool: &[(ergo_primitives::digest::Digest32, std::sync::Arc<[u8]>)],
) -> Vec<PoolFeeEntry> {
    let mut entries: Vec<PoolFeeEntry> = pool
        .iter()
        .filter_map(|(_, bytes)| {
            let tx = parse_pool_tx(bytes)?;
            let fee: u64 = tx
                .output_candidates
                .iter()
                .filter(|c| {
                    c.ergo_tree_bytes() == ergo_mempool::validator::MAINNET_FEE_PROPOSITION_BYTES
                })
                .map(|c| c.value)
                .sum();
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
            })
        })
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.fee_per_byte));
    entries
}

pub(super) fn estimate_wait_ms_from_rank(rank: u64) -> u64 {
    (rank / TX_PER_BLOCK).saturating_mul(BLOCK_TIME_MS)
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

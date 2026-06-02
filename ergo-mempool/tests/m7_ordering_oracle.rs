//! Priority ordering oracle for the mempool weight functions.
//!
//! These tests verify that `OrderedPool::iter_prioritized()` returns
//! transactions in descending-weight order for each supported weight
//! function. MockValidator is used so no UTXO state is needed — only
//! the weight arithmetic and pool ordering are under test.
//!
//! Weight formulas verified here:
//!   ByCost : fee * SCALE / max(cost, 1)
//!   BySize : fee * SCALE / max(size_bytes, 1)
//!   ByMin  : fee * SCALE / max(max(cost, size_bytes), 1)
//!
//! Tie-breaking: equal weight → ascending tx_id byte order (the pool
//! uses `neg_weight` as primary key, `tx_id.bytes` as secondary).

use std::time::Instant;

use ergo_mempool::admission::{MockPlan, MockValidator, TipContext, Validated};
use ergo_mempool::types::{TipPointer, TxSource};
use ergo_mempool::weight::{ByCost, ByMin, BySize, SCALE};
use ergo_mempool::{AdmissionOutcome, Mempool, MempoolConfig, RejectReason};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::UtxoView;

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn id(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn tip_ctx<'a>(
    tx_ctx: &'a TransactionContext,
    params: &'a ProtocolParams,
    utxo: &'a dyn UtxoView,
) -> TipContext<'a> {
    TipContext {
        tip: TipPointer {
            height: 999,
            header_id: id(0xFF),
        },
        best_header_height: 999,
        best_full_block_height: 999,
        utxo,
        tx_context: tx_ctx,
        params,
        last_headers: &[],
    }
}

fn tx_ctx() -> TransactionContext {
    TransactionContext {
        height: 1000,
        miner_pubkey: [0u8; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    }
}

/// Build a MockValidator for a single non-conflicting tx. Each tx gets
/// unique input/output box IDs so no two txs in one pool will conflict.
fn make_tx(bytes: &'static [u8], tx_slot: u8, fee: u64, cost: u64, size: u32) -> MockValidator {
    let tx_id = id(tx_slot);
    // input and output IDs are in the 0x80–0xBF range to avoid
    // clashing with the tx_id (0x01–0x0F range).
    let input_id = id(0x80 + tx_slot);
    let output_id = id(0xA0 + tx_slot);
    MockValidator::new().plan(
        bytes.to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id,
                input_box_ids: vec![input_id],
                output_box_ids: vec![output_id],
                outputs: vec![],
                fee,
                size_bytes: size,
                consumed_cost: cost,
            }),
            charge: cost,
            peek_fee: None,
            peek_tx_id: None,
        },
    )
}

fn admit_all(mempool: &mut Mempool, txs: &[(&'static [u8], MockValidator)], ctx: &TipContext<'_>) {
    for (bytes, v) in txs {
        let (out, _) = mempool.process(bytes, TxSource::Api, Instant::now(), ctx, v);
        assert!(
            matches!(out, AdmissionOutcome::Admitted { .. }),
            "expected Admitted, got {out:?} for {:?}",
            std::str::from_utf8(bytes).unwrap_or("?")
        );
    }
}

// ─── ByCost ─────────────────────────────────────────────────────────────────

// ----- happy path -----

#[test]
fn bycost_pool_order_is_descending_fee_over_cost() {
    // Three txs with the same fee but different costs.
    //   tx_b: cost=25_000  → weight = 10M * 1024 / 25_000  = 409  (highest)
    //   tx_a: cost=100_000 → weight = 10M * 1024 / 100_000 = 102
    //   tx_c: cost=400_000 → weight = 10M * 1024 / 400_000 = 25   (lowest)
    const FEE: u64 = 10_000_000;
    const SIZE: u32 = 100;
    let va = make_tx(b"ord_cost_a", 1, FEE, 100_000, SIZE);
    let vb = make_tx(b"ord_cost_b", 2, FEE, 25_000, SIZE);
    let vc = make_tx(b"ord_cost_c", 3, FEE, 400_000, SIZE);

    let cfg = MempoolConfig {
        max_pool_size: 100,
        max_pool_bytes: 1 << 20,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(ByCost));
    let utxo = EmptyUtxo;
    let tc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&tc, &params, &utxo);

    admit_all(
        &mut mempool,
        &[
            (b"ord_cost_a", va),
            (b"ord_cost_b", vb),
            (b"ord_cost_c", vc),
        ],
        &ctx,
    );

    let ids: Vec<Digest32> = mempool.iter_transactions().map(|e| e.tx_id).collect();
    assert_eq!(ids, vec![id(2), id(1), id(3)], "expected b > a > c order");

    // Verify weights match the formula.
    let ws: Vec<u64> = mempool.iter_transactions().map(|e| e.weight).collect();
    assert_eq!(ws[0], FEE * SCALE / 25_000, "b weight");
    assert_eq!(ws[1], FEE * SCALE / 100_000, "a weight");
    assert_eq!(ws[2], FEE * SCALE / 400_000, "c weight");
    assert!(ws[0] > ws[1] && ws[1] > ws[2], "strictly descending");
}

// ─── BySize ──────────────────────────────────────────────────────────────────

#[test]
fn bysize_pool_order_is_descending_fee_over_size() {
    // Three txs with the same fee but different byte sizes.
    //   tx_b: size=250  → weight = 10M * 1024 / 250  = 40960 (highest)
    //   tx_a: size=1000 → weight = 10M * 1024 / 1000 = 10240
    //   tx_c: size=4000 → weight = 10M * 1024 / 4000 = 2560  (lowest)
    const FEE: u64 = 10_000_000;
    const COST: u64 = 50_000;
    let va = make_tx(b"ord_size_a", 1, FEE, COST, 1000);
    let vb = make_tx(b"ord_size_b", 2, FEE, COST, 250);
    let vc = make_tx(b"ord_size_c", 3, FEE, COST, 4000);

    let cfg = MempoolConfig {
        max_pool_size: 100,
        max_pool_bytes: 1 << 20,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(BySize));
    let utxo = EmptyUtxo;
    let tc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&tc, &params, &utxo);

    admit_all(
        &mut mempool,
        &[
            (b"ord_size_a", va),
            (b"ord_size_b", vb),
            (b"ord_size_c", vc),
        ],
        &ctx,
    );

    let ids: Vec<Digest32> = mempool.iter_transactions().map(|e| e.tx_id).collect();
    assert_eq!(ids, vec![id(2), id(1), id(3)], "expected b > a > c order");

    let ws: Vec<u64> = mempool.iter_transactions().map(|e| e.weight).collect();
    assert_eq!(ws[0], FEE * SCALE / 250, "b weight");
    assert_eq!(ws[1], FEE * SCALE / 1000, "a weight");
    assert_eq!(ws[2], FEE * SCALE / 4000, "c weight");
    assert!(ws[0] > ws[1] && ws[1] > ws[2]);
}

// ─── ByMin ───────────────────────────────────────────────────────────────────

#[test]
fn bymin_pool_order_uses_dominant_resource() {
    // ByMin uses max(cost, size) as the denominator, so whichever axis
    // is larger dominates. Two txs with the same max(cost,size) = 100k
    // but flipped distributions, plus a third that pays double fee.
    //
    //   tx_a: fee=10M, cost=100_000, size=50_000  → max=100k → weight=102
    //   tx_b: fee=10M, cost=50_000,  size=100_000 → max=100k → weight=102 (tie)
    //   tx_c: fee=20M, cost=100_000, size=100_000 → max=100k → weight=204 (highest)
    //
    // Tie between a and b: both have weight=102. Broken by tx_id bytes
    // ascending (id(1) < id(2)), so a precedes b in the priority queue
    // (pool stores neg_weight; for equal neg_weight, smaller tx_id sorts
    // first, meaning a comes before b in the output).
    const SCALE_U: u64 = SCALE;
    let va = make_tx(b"ord_min_a", 1, 10_000_000, 100_000, 50_000);
    let vb = make_tx(b"ord_min_b", 2, 10_000_000, 50_000, 100_000);
    let vc = make_tx(b"ord_min_c", 3, 20_000_000, 100_000, 100_000);

    let cfg = MempoolConfig {
        max_pool_size: 100,
        max_pool_bytes: 1 << 22,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(ByMin));
    let utxo = EmptyUtxo;
    let tc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&tc, &params, &utxo);

    admit_all(
        &mut mempool,
        &[(b"ord_min_a", va), (b"ord_min_b", vb), (b"ord_min_c", vc)],
        &ctx,
    );

    let entries: Vec<_> = mempool.iter_transactions().collect();
    assert_eq!(entries.len(), 3);

    // c has the highest weight.
    assert_eq!(entries[0].tx_id, id(3), "c must be first");
    assert_eq!(entries[0].weight, 20_000_000 * SCALE_U / 100_000);

    // a and b are tied; a (id=1) sorts before b (id=2) by tiebreak.
    assert_eq!(entries[1].tx_id, id(1), "a before b (tie → tx_id tiebreak)");
    assert_eq!(entries[2].tx_id, id(2));
    assert_eq!(entries[1].weight, entries[2].weight, "a and b tied");
    assert_eq!(entries[1].weight, 10_000_000 * SCALE_U / 100_000);

    assert!(entries[0].weight > entries[1].weight, "c > tie pair");
}

// ─── Eviction targets lowest weight ─────────────────────────────────────────

#[test]
fn eviction_removes_lowest_weight_tx() {
    // Pool capacity: 2. Admit a (weight low), b (weight mid).
    // Admit c (weight high) → c evicts a (the current minimum).
    // Final pool: b and c, ordered c > b.
    //
    //   tx_a: fee=10M, cost=200_000 → weight = 10M*1024/200k = 51 (lowest)
    //   tx_b: fee=10M, cost=100_000 → weight = 10M*1024/100k = 102
    //   tx_c: fee=20M, cost=100_000 → weight = 20M*1024/100k = 204 (highest)
    let va = make_tx(b"evict_a", 1, 10_000_000, 200_000, 20);
    let vb = make_tx(b"evict_b", 2, 10_000_000, 100_000, 20);
    let vc = make_tx(b"evict_c", 3, 20_000_000, 100_000, 20);

    let cfg = MempoolConfig {
        max_pool_size: 2,
        max_pool_bytes: 1 << 20,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(ByCost));
    let utxo = EmptyUtxo;
    let tc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&tc, &params, &utxo);

    // Admit a and b — pool is now full.
    let (out_a, _) = mempool.process(b"evict_a", TxSource::Api, Instant::now(), &ctx, &va);
    assert!(matches!(out_a, AdmissionOutcome::Admitted { .. }));
    let (out_b, _) = mempool.process(b"evict_b", TxSource::Api, Instant::now(), &ctx, &vb);
    assert!(matches!(out_b, AdmissionOutcome::Admitted { .. }));
    assert_eq!(mempool.size(), 2);

    // c is heavier than the minimum (a). Admission evicts a.
    let (out_c, actions) = mempool.process(b"evict_c", TxSource::Api, Instant::now(), &ctx, &vc);
    assert!(
        matches!(out_c, AdmissionOutcome::Admitted { .. }),
        "c should be admitted (heavier than minimum): {out_c:?}"
    );
    assert_eq!(mempool.size(), 2, "pool stays at capacity");
    assert!(!actions.is_empty(), "eviction actions emitted");

    assert!(
        !mempool.contains(&id(1)),
        "a (lowest weight) must have been evicted"
    );
    assert!(mempool.contains(&id(2)), "b must still be present");
    assert!(mempool.contains(&id(3)), "c must be present");

    // Verify final ordering: c > b.
    let ids: Vec<Digest32> = mempool.iter_transactions().map(|e| e.tx_id).collect();
    assert_eq!(ids, vec![id(3), id(2)], "c > b");
}

// ─── Lighter-than-minimum rejection ─────────────────────────────────────────

#[test]
fn pool_full_rejects_tx_lighter_than_minimum() {
    // Pool capacity: 2. Admit a (weight mid) and b (weight high).
    // Try to admit c (weight lower than a) — should be rejected PoolFull,
    // NOT evict a.
    //
    //   tx_a: weight=102, tx_b: weight=204, tx_c: weight=51 (lighter than a)
    let va = make_tx(b"light_a", 1, 10_000_000, 100_000, 20);
    let vb = make_tx(b"light_b", 2, 20_000_000, 100_000, 20);
    let vc = make_tx(b"light_c", 3, 10_000_000, 200_000, 20);

    let cfg = MempoolConfig {
        max_pool_size: 2,
        max_pool_bytes: 1 << 20,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(ByCost));
    let utxo = EmptyUtxo;
    let tc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&tc, &params, &utxo);

    let (out_a, _) = mempool.process(b"light_a", TxSource::Api, Instant::now(), &ctx, &va);
    assert!(matches!(out_a, AdmissionOutcome::Admitted { .. }));
    let (out_b, _) = mempool.process(b"light_b", TxSource::Api, Instant::now(), &ctx, &vb);
    assert!(matches!(out_b, AdmissionOutcome::Admitted { .. }));

    let (out_c, _) = mempool.process(b"light_c", TxSource::Api, Instant::now(), &ctx, &vc);
    assert!(
        matches!(
            out_c,
            AdmissionOutcome::Rejected {
                reason: RejectReason::PoolFull
            }
        ),
        "c lighter than minimum must be rejected: {out_c:?}"
    );
    assert_eq!(mempool.size(), 2, "pool must be unchanged");
    assert!(mempool.contains(&id(1)), "a must still be present");
    assert!(mempool.contains(&id(2)), "b must still be present");
}

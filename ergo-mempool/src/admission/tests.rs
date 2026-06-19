use super::*;
use crate::unresolved::UnresolvedCache;
use crate::weight::ByCost;
use ergo_primitives::digest::Digest32;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

// ----- helpers -----

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn id(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
}

fn peer() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)
}

fn ctx() -> TipContextOwned {
    TipContextOwned {
        tip: TipPointer {
            height: 1000,
            header_id: id(0xFF),
        },
        best_header_height: 1000,
        best_full_block_height: 1000,
        tx_context: dummy_tx_context(1000),
        params: ProtocolParams::mainnet_default(),
    }
}

// Owned helper so tests don't juggle lifetimes. Carries dummy
// protocol-params + tx-context + headers — MockValidator ignores
// them anyway.
struct TipContextOwned {
    tip: TipPointer,
    best_header_height: u32,
    best_full_block_height: u32,
    tx_context: TransactionContext,
    params: ProtocolParams,
}

impl TipContextOwned {
    fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> TipContext<'a> {
        TipContext {
            tip: self.tip,
            best_header_height: self.best_header_height,
            best_full_block_height: self.best_full_block_height,
            utxo,
            tx_context: &self.tx_context,
            params: &self.params,
            last_headers: &[],
            reemission: None,
        }
    }
}

fn dummy_tx_context(height: u32) -> TransactionContext {
    TransactionContext {
        height,
        miner_pubkey: [0u8; 33],
        pre_header_timestamp: 0,
        activated_script_version: 2,
        pre_header_version: 3,
        pre_header_parent_id: [0u8; 32],
        pre_header_n_bits: 0,
        pre_header_votes: [0u8; 3],
    }
}

fn default_config() -> MempoolConfig {
    MempoolConfig::default()
}

fn fresh() -> (OrderedPool, CostBudgets, InvalidationCache, UnresolvedCache) {
    (
        OrderedPool::with_capacity(32),
        CostBudgets::new(1_000_000, 100_000),
        InvalidationCache::new(32, Duration::from_secs(60), Duration::from_secs(1)),
        UnresolvedCache::new(32, Duration::from_secs(60)),
    )
}

fn successful_validated(tx_id: Digest32, bytes: &[u8], fee: u64) -> Validated {
    Validated {
        tx_id,
        input_box_ids: vec![id(0xA0)],
        output_box_ids: vec![id(0xB0)],
        outputs: vec![],
        fee,
        size_bytes: bytes.len() as u32,
        consumed_cost: 10_000,
    }
}

fn validator_accepting(bytes: &[u8], tx_id: Digest32, fee: u64) -> MockValidator {
    MockValidator::new().plan(
        bytes.to_vec(),
        MockPlan {
            result: Ok(successful_validated(tx_id, bytes, fee)),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    )
}

// ----- happy path / scenario tests -----
//
// Each `#[test]` exercises one admission path end-to-end through
// `admit_transaction`: IBD gating, budget exhaustion, size cap,
// unresolved-cache routing, and the per-stage cost/penalty contracts.
// Tests with `_rejects`, `_errors`, or `_charges` in the name pin
// negative-path identity (cost charge, penalty assignment, source
// distinction) the same way as positive paths.

#[test]
fn ibd_gate_drops_silently() {
    let utxo = EmptyUtxo;
    let c = TipContextOwned {
        tip: TipPointer {
            height: 100,
            header_id: id(0),
        },
        best_header_height: 200,
        best_full_block_height: 100, // gap = 100 >> lag (10)
        tx_context: dummy_tx_context(100),
        params: ProtocolParams::mainnet_default(),
    };
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::IbdGated
        }
    ));
    // No penalty: IBD drops are silent.
    assert!(!actions
        .iter()
        .any(|a| matches!(a, MempoolAction::Penalize { .. })));
}

#[test]
fn pre_admission_budget_exhausted_short_circuits() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    b.charge(Some(peer()), 200_000); // blow the peer budget
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new(); // never called
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::PeerBudgetExhausted
        }
    ));
}

#[test]
fn size_cap_rejects_with_penalty() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_tx_size_bytes = 8;
    let w = ByCost;
    let v = MockValidator::new();
    let big = vec![0u8; 100];
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(&big, TxSource::Peer(peer()), Instant::now(), &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::SizeLimit
        }
    ));
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::Penalize {
            kind: PenaltyKind::Misbehavior,
            ..
        }
    )));
}

#[test]
fn unresolved_cache_short_circuits() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new();
    let now = Instant::now();
    unr.insert(b"bytes", now);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"bytes", TxSource::Peer(peer()), now, &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::RecentlyUnresolved
        }
    ));
}

#[test]
fn deserialize_error_charges_cost_and_penalizes() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    // No plan for these bytes → validator returns Deserialize.
    let v = MockValidator::new();
    let now = Instant::now();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(b"bad", TxSource::Peer(peer()), now, &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::Deserialize
        }
    ));
    // MockValidator charges 0 when there's no plan; no partial-charge here.
    // The penalty should still fire.
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::Penalize {
            kind: PenaltyKind::Misbehavior,
            ..
        }
    )));
}

#[test]
fn validation_failure_charges_partial_cost() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge: 25_000,
            // Pass the min-fee gate so full validation runs and
            // the partial-cost-on-failure path is exercised.
            peek_fee: Some(5_000_000),
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(out, AdmissionOutcome::Rejected { .. }));
    assert_eq!(
        b.peer_consumed(&peer()),
        25_000,
        "partial cost charged even on validation failure"
    );
}

#[test]
fn below_min_fee_short_circuits_before_validation() {
    // Item 3 of the code-review fixes: below-min-fee rejections
    // must NOT run full validation (no input resolution, no
    // script eval, no cost charged). Proved via MockValidator
    // call counters.
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config(); // default min_relay_fee = 1_000_000
    let w = ByCost;
    // peek_fee below the 1M threshold. The plan's result would be
    // Ok if reached, but reaching it is the bug we're guarding.
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(1),
                input_box_ids: vec![id(0xA0)],
                output_box_ids: vec![id(0xB0)],
                outputs: vec![],
                fee: 10,
                size_bytes: 5,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: Some(10), // well under min_relay_fee
            peek_tx_id: None,
        },
    );
    let before_budget = b.global_consumed();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::BelowMinFee
        }
    ));
    // Observe event carries the REAL tx_id from peek_fee, not a
    // zeroed placeholder — observability is preserved across the
    // gate (reviewer finding 1).
    let observed_id = actions.iter().find_map(|a| match a {
        MempoolAction::Observe {
            event: ObservedEvent::DroppedBelowMinFee { tx_id, .. },
        } => Some(*tx_id),
        _ => None,
    });
    assert_eq!(
        observed_id,
        Some(id(1)),
        "DroppedBelowMinFee event must carry the real tx_id from peek_fee"
    );
    // peek_fee called exactly once; validate NEVER called.
    assert_eq!(
        v.peek_fee_call_count(),
        1,
        "peek_fee fires once per admission"
    );
    assert_eq!(
        v.validate_call_count(),
        0,
        "validate must not run when peek_fee gate rejects below-min-fee"
    );
    // Zero side effects on budget, invalidation cache, unresolved cache.
    assert_eq!(
        b.global_consumed(),
        before_budget,
        "no cost charged when rejected by min-fee gate"
    );
    assert!(inv.is_empty(), "invalidation cache untouched");
    // Unresolved cache also untouched — the bytes weren't tried
    // against a UtxoView, so no unresolved-input signal exists.
}

#[test]
fn peek_fee_deserialize_failure_penalizes_peer() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    // No plan for these bytes → peek_fee returns Deserialize.
    let v = MockValidator::new();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(b"bad", TxSource::Peer(peer()), Instant::now(), &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::Deserialize
        }
    ));
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::Penalize {
            kind: PenaltyKind::Misbehavior,
            ..
        }
    )));
    // validate not called: deserialize is terminal.
    assert_eq!(v.validate_call_count(), 0);
}

#[test]
fn unresolved_input_seeds_unresolved_cache() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::UnresolvedInput),
            charge: 0,
            // Pass the min-fee gate so we reach the validator
            // and the unresolved cache gets seeded.
            peek_fee: Some(5_000_000),
            peek_tx_id: None,
        },
    );
    let now = Instant::now();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"bytes", TxSource::Peer(peer()), now, &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::UnresolvedInput
        }
    ));
    assert!(
        unr.contains(b"bytes", now),
        "unresolved cache should be seeded so the next try drops earlier"
    );
    assert!(
        inv.is_empty(),
        "unresolved input routes to the unresolved cache, not invalidation"
    );
}

#[test]
fn happy_path_admits_and_broadcasts() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    assert_eq!(pool.len(), 1);
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::BroadcastInv { except: Some(p), .. } if *p == peer()
    )));
    pool.check_invariants();
}

#[test]
fn duplicate_tx_rejected_idempotently() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"bytes", TxSource::Api, Instant::now(), &mut cx, &v);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out2, _) = process(b"bytes", TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(matches!(
        out2,
        AdmissionOutcome::Rejected {
            reason: RejectReason::Duplicate
        }
    ));
    assert_eq!(pool.len(), 1);
}

#[test]
fn below_min_fee_drops_without_penalty() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 100); // well below 1e6
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::BelowMinFee
        }
    ));
    assert!(!actions
        .iter()
        .any(|a| matches!(a, MempoolAction::Penalize { .. })));
}

#[test]
fn blacklisted_id_does_not_block_admission_scala_parity() {
    // Scala's `ErgoMemPool.process` never consults `invalidatedTxIds`;
    // the set only filters Inv fetches at the network layer. Bytes
    // that arrive anyway and validate must be admitted — including a
    // tx whose id was blacklisted by an earlier failure (corrected
    // proofs, reorg-demoted block txs).
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);
    let now = Instant::now();
    inv.insert(id(1), InvalidationReason::ValidationFailed, now);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(b"bytes", TxSource::Peer(peer()), now, &mut cx, &v);
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    assert!(pool.contains(&id(1)));
    assert!(!actions
        .iter()
        .any(|a| matches!(a, MempoolAction::Penalize { .. })));
    // The cache entry stays: it keeps filtering Inv fetches even
    // though admission ignored it.
    assert!(inv.contains(&id(1)));
}

#[test]
fn validation_failure_blacklists_by_canonical_tx_id() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    // Fee passes the min-fee gate; full validation rejects the scripts.
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge: 10_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(id(7)),
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::ValidationFailed { .. }
        }
    ));
    // The cache entry must be keyed by the canonical tx_id from peek —
    // the key the step-5 record_hit and the Inv-skip gate look up —
    // not by a hash of the wire bytes (which, including proofs, never
    // equals the proof-excluded tx_id).
    assert!(
        inv.contains(&id(7)),
        "invalidation cache keyed by canonical tx_id"
    );
    let bytes_hash = ergo_primitives::digest::blake2b256(b"bytes");
    assert!(!inv.contains(&bytes_hash), "no bytes-hash proxy entry");
}

#[test]
fn failed_then_corrected_resubmission_is_accepted() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let t0 = Instant::now();
    // First submission: validation fails → tx_id lands in the cache.
    let v_fail = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge: 10_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(id(7)),
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"bytes", TxSource::Peer(peer()), t0, &mut cx, &v_fail);
    assert!(inv.contains(&id(7)), "failure blacklists the canonical id");
    // Resubmission that now validates (e.g. corrected proofs — same
    // proof-excluded tx_id) must be ADMITTED: Scala's process never
    // consults invalidatedTxIds, so a blacklisted-but-now-valid tx is
    // accepted. The cache continues to filter Inv fetches only.
    let v_ok = validator_accepting(b"bytes", id(7), 5_000_000);
    let t1 = t0 + Duration::from_secs(5);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"bytes", TxSource::Peer(peer()), t1, &mut cx, &v_ok);
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    assert!(pool.contains(&id(7)));
    assert!(inv.contains(&id(7)), "fetch-filter entry remains");
}

#[test]
fn parse_class_failures_do_not_blacklist() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    // NonCanonical: tx parsed (peek produced an id) but bytes are not
    // the canonical encoding. Blacklisting the id would also damn the
    // canonical re-encoding of the same tx — Scala skips
    // invalidatedTxIds for parse-class failures too.
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::NonCanonical),
            charge: 1_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(id(8)),
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"bytes",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::NonCanonical
        }
    ));
    assert!(inv.is_empty(), "parse-class failure must not blacklist");

    // Deserialize from validate (the validator-disagreement arm —
    // peek parsed the bytes but validate could not): same rule.
    let v2 = MockValidator::new().plan(
        b"bytes2".to_vec(),
        MockPlan {
            result: Err(ValidationErr::Deserialize),
            charge: 1_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(id(13)),
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"bytes2",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v2,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::Deserialize
        }
    ));
    assert!(inv.is_empty(), "deserialize failure must not blacklist");
}

#[test]
fn double_spend_loser_rejected_cost_still_charged() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    // Seed pool with a heavy tx spending box id 0xA0.
    let v1 = validator_accepting(b"fat_tx", id(10), 10_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"fat_tx", TxSource::Api, Instant::now(), &mut cx, &v1);
    // New tx with much lower fee claiming the same input.
    let v2 = MockValidator::new().plan(
        b"thin_tx".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(11),
                input_box_ids: vec![id(0xA0)],
                output_box_ids: vec![id(0xC0)],
                outputs: vec![],
                fee: 2_000_000,
                size_bytes: 7,
                consumed_cost: 15_000,
            }),
            charge: 15_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let before_cost = b.global_consumed();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(
        b"thin_tx",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v2,
    );
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::DoubleSpendLoser
        }
    ));
    assert!(pool.contains(&id(10)), "losing tx leaves pool unchanged");
    assert_eq!(pool.len(), 1);
    assert_eq!(b.global_consumed() - before_cost, 15_000);
}

#[test]
fn double_spend_winner_evicts_and_emits_revoke() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v1 = validator_accepting(b"thin_tx", id(10), 2_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"thin_tx", TxSource::Api, Instant::now(), &mut cx, &v1);
    let v2 = MockValidator::new().plan(
        b"fat_tx".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(11),
                input_box_ids: vec![id(0xA0)],
                output_box_ids: vec![id(0xC0)],
                outputs: vec![],
                fee: 20_000_000,
                size_bytes: 6,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(
        b"fat_tx",
        TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v2,
    );
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    assert!(!pool.contains(&id(10)));
    assert!(pool.contains(&id(11)));
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&id(10))
    )));
    pool.check_invariants();
}

#[test]
fn pool_full_rejects_lighter_tx_without_mutation() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1;
    let w = ByCost;
    let seed = validator_accepting(b"seed", id(1), 100_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"seed", TxSource::Api, Instant::now(), &mut cx, &seed);
    assert_eq!(pool.len(), 1);
    let cheap = MockValidator::new().plan(
        b"cheap".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(2),
                input_box_ids: vec![id(0xD0)],
                output_box_ids: vec![id(0xD1)],
                outputs: vec![],
                fee: 1_000_000,
                size_bytes: 5,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"cheap", TxSource::Api, Instant::now(), &mut cx, &cheap);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::PoolFull
        }
    ));
    assert!(pool.contains(&id(1)));
    assert!(!pool.contains(&id(2)));
}

#[test]
fn pool_full_evicts_lowest_when_new_is_heavier() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1;
    let w = ByCost;
    let cheap = validator_accepting(b"cheap", id(1), 2_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"cheap", TxSource::Api, Instant::now(), &mut cx, &cheap);
    let heavy = MockValidator::new().plan(
        b"heavy".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(2),
                input_box_ids: vec![id(0xD0)],
                output_box_ids: vec![id(0xD1)],
                outputs: vec![],
                fee: 100_000_000,
                size_bytes: 5,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = process(b"heavy", TxSource::Api, Instant::now(), &mut cx, &heavy);
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&id(2)));
    assert!(actions.iter().any(|a| matches!(
        a,
        MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&id(1))
    )));
}

// Helper: build a MockValidator for a tx with custom input/output box
// IDs so byte-budget tests don't accidentally trigger the double-spend
// path (which shares input id(0xA0) with validator_accepting).
fn validator_no_conflict(
    bytes: &'static [u8],
    tx_id: Digest32,
    fee: u64,
    input: Digest32,
    output: Digest32,
) -> MockValidator {
    MockValidator::new().plan(
        bytes.to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id,
                input_box_ids: vec![input],
                output_box_ids: vec![output],
                outputs: vec![],
                fee,
                size_bytes: bytes.len() as u32,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    )
}

#[test]
fn byte_budget_rejects_lighter_tx() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1_000; // count limit must not trigger
    cfg.max_pool_bytes = 8; // less than 5 + 5 = 10
    let w = ByCost;

    let v1 = validator_no_conflict(b"aaaaa", id(1), 2_000_000, id(0xE0), id(0xE1));
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out1, _) = process(b"aaaaa", TxSource::Api, Instant::now(), &mut cx, &v1);
    assert!(
        matches!(out1, AdmissionOutcome::Admitted { .. }),
        "tx1 should be admitted: {out1:?}"
    );
    assert_eq!(pool.total_bytes(), 5);

    let v2 = validator_no_conflict(b"bbbbb", id(2), 1_000_000, id(0xF0), id(0xF1));
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out2, _) = process(b"bbbbb", TxSource::Api, Instant::now(), &mut cx, &v2);
    assert!(
        matches!(
            out2,
            AdmissionOutcome::Rejected {
                reason: RejectReason::PoolFull
            }
        ),
        "lighter tx should be rejected by byte budget: {out2:?}"
    );
    assert_eq!(pool.len(), 1, "lighter tx must not enter pool");
    assert_eq!(
        pool.total_bytes(),
        5,
        "pool bytes must not grow on rejection"
    );
}

#[test]
fn byte_budget_evicts_lowest_when_new_is_heavier() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1_000;
    cfg.max_pool_bytes = 8;
    let w = ByCost;

    let v1 = validator_no_conflict(b"aaaaa", id(1), 2_000_000, id(0xE0), id(0xE1));
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let _ = process(b"aaaaa", TxSource::Api, Instant::now(), &mut cx, &v1);

    let v2 = validator_no_conflict(b"bbbbb", id(2), 100_000_000, id(0xF0), id(0xF1));
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out2, actions) = process(b"bbbbb", TxSource::Api, Instant::now(), &mut cx, &v2);
    assert!(
        matches!(out2, AdmissionOutcome::Admitted { .. }),
        "heavier tx should be admitted: {out2:?}"
    );
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(&id(2)));
    assert!(!pool.contains(&id(1)), "lighter tx must be evicted");
    assert!(
        actions.iter().any(
            |a| matches!(a, MempoolAction::RevokeBroadcast { tx_ids } if tx_ids.contains(&id(1)))
        ),
        "eviction must emit RevokeBroadcast for tx1"
    );
}

#[test]
fn byte_budget_evicts_multiple_until_both_fit() {
    // Setup: 4 txs × 3 bytes = 12 bytes filling max_pool_bytes = 12.
    // Admitting a 6-byte tx requires bytes_after = 12+6 = 18 > 12,
    // which forces TWO evictions (remove tx1 → 9+6=15 still over,
    // remove tx2 → 6+6=12 ≤ 12) before the new tx can be inserted.
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1_000;
    cfg.max_pool_bytes = 12;
    let w = ByCost;

    for (bytes, tx_id, fee, inp, out) in [
        (b"aaa" as &[u8], id(1), 1_000_000u64, id(0xA0), id(0xA1)),
        (b"bbb", id(2), 2_000_000, id(0xB0), id(0xB1)),
        (b"ccc", id(3), 3_000_000, id(0xC0), id(0xC1)),
        (b"ddd", id(4), 4_000_000, id(0xD0), id(0xD1)),
    ] {
        let v = MockValidator::new().plan(
            bytes.to_vec(),
            MockPlan {
                result: Ok(Validated {
                    tx_id,
                    input_box_ids: vec![inp],
                    output_box_ids: vec![out],
                    outputs: vec![],
                    fee,
                    size_bytes: 3,
                    consumed_cost: 10_000,
                }),
                charge: 10_000,
                peek_fee: None,
                peek_tx_id: None,
            },
        );
        let tip = c.view(&utxo);
        let mut cx = AdmissionCtx {
            tip_ctx: &tip,
            config: &cfg,
            pool: &mut pool,
            budgets: &mut b,
            invalidated: &mut inv,
            unresolved: &mut unr,
            weight_fn: &w,
        };
        let (out_res, _) = process(bytes, TxSource::Api, Instant::now(), &mut cx, &v);
        assert!(
            matches!(out_res, AdmissionOutcome::Admitted { .. }),
            "setup tx {tx_id:?} failed: {out_res:?}"
        );
    }
    assert_eq!(
        pool.total_bytes(),
        12,
        "pool should be exactly full before final tx"
    );
    assert_eq!(pool.len(), 4);

    // New heaviest tx (fee=100M, 6 bytes). bytes_after = 12+6 = 18 > 12.
    // Eviction loop: remove id(1) → 9+6=15>12, then id(2) → 6+6=12≤12.
    let v5 = MockValidator::new().plan(
        b"eeeeee".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(5),
                input_box_ids: vec![id(0xE0)],
                output_box_ids: vec![id(0xE1)],
                outputs: vec![],
                fee: 100_000_000,
                size_bytes: 6,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out5, _) = process(b"eeeeee", TxSource::Api, Instant::now(), &mut cx, &v5);
    assert!(
        matches!(out5, AdmissionOutcome::Admitted { .. }),
        "heavy tx should be admitted: {out5:?}"
    );
    assert!(
        pool.total_bytes() <= cfg.max_pool_bytes,
        "byte budget violated after multi-eviction: {} > {}",
        pool.total_bytes(),
        cfg.max_pool_bytes,
    );
    assert!(!pool.contains(&id(1)), "tx1 (lightest) must be evicted");
    assert!(
        !pool.contains(&id(2)),
        "tx2 must be evicted for bytes to fit"
    );
    assert!(pool.contains(&id(5)), "new heavy tx must be in pool");
}

#[test]
fn byte_budget_rejects_tx_larger_than_cap() {
    // A tx whose own size exceeds max_pool_bytes can never fit,
    // regardless of evictions. Must be rejected immediately.
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let mut cfg = default_config();
    cfg.max_pool_size = 1_000;
    cfg.max_pool_bytes = 3; // smaller than the 5-byte tx
    let w = ByCost;

    let v = validator_no_conflict(b"aaaaa", id(1), 100_000_000, id(0xE0), id(0xE1));
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"aaaaa", TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(
        matches!(
            out,
            AdmissionOutcome::Rejected {
                reason: RejectReason::PoolFull
            }
        ),
        "tx larger than byte cap must be rejected: {out:?}"
    );
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.total_bytes(), 0);
}

#[test]
fn global_budget_exhausted_blocks_new_peers() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, _, mut inv, mut unr) = fresh();
    let mut b = CostBudgets::new(10_000, 100_000); // tight global cap
    let cfg = default_config();
    // Pre-fill global budget so any peer is blocked.
    b.charge(None, 10_000);
    let w = ByCost;
    let v = MockValidator::new();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"x", TxSource::Peer(peer()), Instant::now(), &mut cx, &v);
    assert!(matches!(
        out,
        AdmissionOutcome::Rejected {
            reason: RejectReason::GlobalBudgetExhausted
        }
    ));
}

#[test]
fn pool_output_map_feeds_overlay_for_child_tx() {
    // Seed the pool with a parent that declares an output box.
    // Build a real ErgoBox for that output so output_map() can
    // carry it into the overlay for a subsequent child admission.
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::AdditionalRegisters;

    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;

    let tree_bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).unwrap();
    let parent_output = ErgoBox {
        candidate: ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
            .unwrap(),
        transaction_id: id(1).into(),
        index: 0,
    };
    // Manually seed the pool: the parent entry's output_boxes
    // carries the materialized ErgoBox so output_map() picks it up.
    let parent_entry = Entry::new(
        id(1),
        Arc::from(vec![1u8; 50].into_boxed_slice()),
        vec![id(0x10)],
        vec![id(0xBB)],
        vec![],
        5_000_000,
        500,
        50,
        100_000,
        TxSource::Api,
    )
    .with_output_boxes(vec![parent_output]);
    pool.insert(parent_entry).unwrap();

    // Check output_map materializes the parent output.
    let map = pool.output_map();
    assert!(
        map.contains_key(&id(0xBB)),
        "output_map must expose pool-created output box for overlay"
    );

    // Admit a child that "spends" that output — MockValidator
    // returns success regardless of the overlay (it's a mock), but
    // admission must compute parents_in_pool from output_map.
    let child = MockValidator::new().plan(
        b"child".to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(2),
                input_box_ids: vec![id(0xBB)],
                output_box_ids: vec![id(0xCC)],
                outputs: vec![],
                fee: 3_000_000,
                size_bytes: 5,
                consumed_cost: 12_000,
            }),
            charge: 12_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"child", TxSource::Api, Instant::now(), &mut cx, &child);
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
    // The child entry must list tx 1 as its in-pool parent.
    let child_entry = pool.get(&id(2)).unwrap();
    assert_eq!(child_entry.parents_in_pool, vec![id(1)]);
    pool.check_invariants();
}

#[test]
fn api_source_bypasses_per_peer_budget() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    // Fill a random peer's budget; Api source must still admit.
    b.charge(Some(peer()), 200_000);
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"bytes", TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(matches!(out, AdmissionOutcome::Admitted { .. }));
}

// ── Mempool::check anti-DoS mutation parity ─────────────────────
//
// Per mempool invariant #7, the check path must update the same
// anti-DoS state that process updates — otherwise /transactions/
// checkBytes becomes a free script-evaluation oracle for attackers.
// The only thing check skips is the OrderedPool commit. These three
// tests pin that contract by hitting each of the three caches
// through admission::check and asserting the same observable state
// the process equivalents already assert, plus pool.len() == 0.

#[test]
fn check_seeds_invalidation_cache_on_validation_failure() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge: 25_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(id(9)),
        },
    );
    let now = Instant::now();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = check(b"bytes", &TxSource::Api, now, &mut cx, &v);
    assert!(matches!(out, CheckOutcome::Rejected { .. }));
    // The cache is keyed on the canonical tx_id from the step-3.5
    // peek — same as process. Looking it up here pins the key
    // derivation.
    assert!(
        inv.contains(&id(9)),
        "check must seed the invalidation cache on script failure (parity with process)",
    );
    assert_eq!(pool.len(), 0, "check must never insert into the pool");
}

#[test]
fn check_seeds_unresolved_cache_on_unresolved_input() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::UnresolvedInput),
            charge: 0,
            peek_fee: Some(5_000_000),
            peek_tx_id: None,
        },
    );
    let now = Instant::now();
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = check(b"bytes", &TxSource::Api, now, &mut cx, &v);
    assert!(matches!(
        out,
        CheckOutcome::Rejected {
            reason: RejectReason::UnresolvedInput
        }
    ));
    assert!(
        unr.contains(b"bytes", now),
        "check must seed the unresolved-bytes cache (parity with process)",
    );
    assert!(
        inv.is_empty(),
        "unresolved input routes to the unresolved cache, not invalidation"
    );
    assert_eq!(pool.len(), 0, "check must never insert into the pool");
}

#[test]
fn check_charges_global_cost_budget_on_validation_failure() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = MockValidator::new().plan(
        b"bytes".to_vec(),
        MockPlan {
            result: Err(ValidationErr::ScriptFailed),
            charge: 25_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: None,
        },
    );
    // Use a peer source so we can also assert per-peer charges
    // (Api source skips per-peer budgets — only peer-sourced
    // submissions count against the per-peer cap).
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = check(
        b"bytes",
        &TxSource::Peer(peer()),
        Instant::now(),
        &mut cx,
        &v,
    );
    assert!(matches!(out, CheckOutcome::Rejected { .. }));
    assert_eq!(
        b.global_consumed(),
        25_000,
        "check must charge the global budget by the validator's reported cost",
    );
    assert_eq!(
        b.peer_consumed(&peer()),
        25_000,
        "check must charge the per-peer budget for Peer-sourced submissions",
    );
    assert_eq!(pool.len(), 0, "check must never insert into the pool");
}

// ── CheckOnly behavioral contract ────────────────────────────────
//
// For an admissible tx, check returns WouldAdmit but never mutates
// the pool and never emits a BroadcastInv. A subsequent process
// call on the same bytes admits and emits exactly one Inv. Together
// these prove `/transactions/checkBytes` cannot leak Inv frames
// and is repeatable from the operator's perspective.

#[test]
fn check_admits_without_mutating_pool_or_emitting_inv() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);
    let pool_len_before = pool.len();
    let pool_bytes_before = pool.total_bytes();

    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, actions) = check(b"bytes", &TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(matches!(out, CheckOutcome::WouldAdmit { .. }));
    assert_eq!(pool.len(), pool_len_before, "check must not insert");
    assert_eq!(
        pool.total_bytes(),
        pool_bytes_before,
        "check must not change pool byte count",
    );
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, MempoolAction::BroadcastInv { .. })),
        "check must never emit BroadcastInv",
    );
}

#[test]
fn check_then_process_same_bytes_admits_with_exactly_one_inv() {
    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;
    let v = validator_accepting(b"bytes", id(1), 5_000_000);

    // First: check — should be WouldAdmit, no Inv, no pool growth.
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out1, actions1) = check(b"bytes", &TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(matches!(out1, CheckOutcome::WouldAdmit { .. }));
    assert_eq!(pool.len(), 0);
    assert!(!actions1
        .iter()
        .any(|a| matches!(a, MempoolAction::BroadcastInv { .. })),);

    // Then: process the same bytes — should admit with one Inv.
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out2, actions2) = process(b"bytes", TxSource::Api, Instant::now(), &mut cx, &v);
    assert!(matches!(out2, AdmissionOutcome::Admitted { .. }));
    assert_eq!(pool.len(), 1, "process must commit after a prior check");
    let inv_count = actions2
        .iter()
        .filter(|a| matches!(a, MempoolAction::BroadcastInv { .. }))
        .count();
    assert_eq!(
        inv_count, 1,
        "process must emit exactly one BroadcastInv even after a prior check",
    );
}

// ── Pool-overlay differential — data inputs ──────────────────────
//
// Regular inputs see pool outputs via PoolUtxoOverlay; data inputs
// see only the committed UTXO via CommittedOnly. A child tx that
// tries to use a parent's pool-only output as a *data input* must
// be rejected with UnresolvedDataInput, even though the same id
// would resolve fine if used as a regular input.
//
// MockValidator ignores its views, so we wire a tiny custom
// validator that actually consults `data_input_view` for the box
// we care about. This is the only way to pin the overlay vs
// CommittedOnly distinction at the unit level.

#[test]
fn data_input_does_not_resolve_through_pool_overlay() {
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_box::ErgoBoxCandidate;
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::AdditionalRegisters;

    // ── Custom validator: reports UnresolvedDataInput when the
    // planned data-input id is missing from data_input_view, else
    // returns a successful Validated payload. Lets us probe what
    // admission actually exposes via the data view.
    struct DataInputProbe {
        bytes: Vec<u8>,
        tx_id: TxId,
        data_input_id: Digest32,
    }
    impl Validator for DataInputProbe {
        fn peek_fee(&self, tx_bytes: &[u8]) -> Result<PeekedTx, ValidationErr> {
            if tx_bytes != self.bytes {
                return Err(ValidationErr::Deserialize);
            }
            Ok(PeekedTx {
                tx_id: self.tx_id,
                fee: 5_000_000,
            })
        }
        fn validate(
            &self,
            tx_bytes: &[u8],
            _input_view: &dyn UtxoView,
            data_input_view: &dyn UtxoView,
            cx: &mut ergo_validation::TxValidationCtx<'_>,
        ) -> Result<Validated, ValidationErr> {
            if tx_bytes != self.bytes {
                return Err(ValidationErr::Deserialize);
            }
            let _ = cx.cost.add(JitCost::from_block_cost(8_000).unwrap());
            if data_input_view.get_box(&self.data_input_id).is_none() {
                return Err(ValidationErr::UnresolvedDataInput);
            }
            Ok(Validated {
                tx_id: self.tx_id,
                input_box_ids: vec![],
                output_box_ids: vec![id(0xCC)],
                outputs: vec![],
                fee: 5_000_000,
                size_bytes: tx_bytes.len() as u32,
                consumed_cost: 8_000,
            })
        }
    }

    let utxo = EmptyUtxo;
    let c = ctx();
    let (mut pool, mut b, mut inv, mut unr) = fresh();
    let cfg = default_config();
    let w = ByCost;

    // Seed the pool with a parent that materializes output id 0xBB.
    // committed UTXO (EmptyUtxo) does not know about it.
    let tree_bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&tree_bytes);
    let tree = read_ergo_tree(&mut r).unwrap();
    let parent_output = ErgoBox {
        candidate: ErgoBoxCandidate::new(1_000_000, tree, 0, vec![], AdditionalRegisters::empty())
            .unwrap(),
        transaction_id: id(1).into(),
        index: 0,
    };
    let parent_entry = Entry::new(
        id(1),
        Arc::from(vec![1u8; 50].into_boxed_slice()),
        vec![id(0x10)],
        vec![id(0xBB)],
        vec![],
        5_000_000,
        500,
        50,
        100_000,
        TxSource::Api,
    )
    .with_output_boxes(vec![parent_output]);
    pool.insert(parent_entry).unwrap();
    assert!(
        pool.output_map().contains_key(&id(0xBB)),
        "sanity: pool overlay must hold the parent output",
    );

    // Child probes 0xBB as a data input. Admission feeds the
    // CommittedOnly view to the validator's data_input_view —
    // pool outputs must not be visible there.
    let child = DataInputProbe {
        bytes: b"child".to_vec(),
        tx_id: id(2),
        data_input_id: id(0xBB),
    };
    let tip = c.view(&utxo);
    let mut cx = AdmissionCtx {
        tip_ctx: &tip,
        config: &cfg,
        pool: &mut pool,
        budgets: &mut b,
        invalidated: &mut inv,
        unresolved: &mut unr,
        weight_fn: &w,
    };
    let (out, _) = process(b"child", TxSource::Api, Instant::now(), &mut cx, &child);
    assert!(
        matches!(
            out,
            AdmissionOutcome::Rejected {
                reason: RejectReason::UnresolvedDataInput
            }
        ),
        "data inputs must NOT resolve through the pool overlay; got {:?}",
        out,
    );
    assert_eq!(
        pool.len(),
        1,
        "rejection must not touch the pool — only the parent stays",
    );
}

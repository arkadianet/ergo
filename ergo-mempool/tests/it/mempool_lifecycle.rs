//! End-to-end `Mempool` struct lifecycle: admit → confirm → demote →
//! revalidate. Exercises the public method-wrapper surface.

use std::sync::Arc;
use std::time::Instant;

use ergo_mempool::admission::{MockPlan, MockValidator, TipContext, Validated};
use ergo_mempool::types::{AppliedTx, DemotedTx, TipPointer, TxDiff, TxSource};
use ergo_mempool::weight::ByCost;
use ergo_mempool::{AdmissionOutcome, Mempool, MempoolConfig};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::{ProtocolParams, TransactionContext, UtxoView};

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn digest(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
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

struct Ctx {
    tx_context: TransactionContext,
    params: ProtocolParams,
}

impl Ctx {
    fn new() -> Self {
        Self {
            tx_context: dummy_tx_context(1000),
            params: ProtocolParams::mainnet_default(),
        }
    }
    fn view<'a>(&'a self, utxo: &'a dyn UtxoView) -> TipContext<'a> {
        TipContext {
            tip: TipPointer {
                height: 1000,
                header_id: digest(0xFF),
            },
            best_header_height: 1000,
            best_full_block_height: 1000,
            utxo,
            tx_context: &self.tx_context,
            params: &self.params,
            last_headers: &[],
            reemission: None,
        }
    }
}

#[test]
fn admit_then_confirm_then_demote_full_lifecycle() {
    let cfg = MempoolConfig::default();
    let mut mempool = Mempool::new(cfg, Box::new(ByCost));
    let utxo = EmptyUtxo;
    let ctx = Ctx::new();

    // ── Admit tx A ──
    let tx_bytes = b"tx_a_bytes".to_vec();
    let validator = MockValidator::new().plan(
        tx_bytes.clone(),
        MockPlan {
            result: Ok(Validated {
                tx_id: digest(0xA0),
                input_box_ids: vec![digest(0x10)],
                output_box_ids: vec![digest(0x20)],
                outputs: vec![],
                fee: 5_000_000,
                size_bytes: tx_bytes.len() as u32,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let (outcome, _) = mempool.process(
        &tx_bytes,
        TxSource::Api,
        Instant::now(),
        &ctx.view(&utxo),
        &validator,
    );
    assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
    assert_eq!(mempool.size(), 1);

    // ── Apply a block that confirms tx A ──
    let diff = TxDiff {
        new_tip: TipPointer {
            height: 1001,
            header_id: digest(0x01),
        },
        applied: vec![AppliedTx {
            tx_id: digest(0xA0),
            spent_inputs: vec![digest(0x10)],
        }],
        demoted: vec![],
        applied_spent_inputs: std::iter::once(digest(0x10)).collect(),
    };
    let actions = mempool.on_tip_change(&diff);
    assert_eq!(mempool.size(), 0, "confirmed tx removed");
    assert_eq!(
        mempool.tip().map(|t| t.height),
        Some(1001),
        "tip pointer advanced"
    );
    assert!(!actions.is_empty());

    // ── Reorg: A demoted, new chain had nothing matching. ──
    let diff2 = TxDiff {
        new_tip: TipPointer {
            height: 1002,
            header_id: digest(0x02),
        },
        applied: vec![],
        demoted: vec![DemotedTx {
            tx_id: digest(0xA0),
            bytes: Arc::from(tx_bytes.clone().into_boxed_slice()),
        }],
        applied_spent_inputs: std::collections::HashSet::new(),
    };
    mempool.on_tip_change(&diff2);
    assert_eq!(mempool.revalidation_pending(), 1);

    // ── Drain revalidation queue: validator re-accepts A. ──
    mempool.tick_revalidation(Instant::now(), &ctx.view(&utxo), &validator);
    assert_eq!(mempool.size(), 1, "A re-admitted from revalidation queue");
    assert!(mempool.contains(&digest(0xA0)));
    assert_eq!(mempool.revalidation_pending(), 0);
}

#[test]
fn mempool_process_peer_budget_exhaustion_survives_method_call() {
    // Sanity: the method-wrapper surface threads budgets correctly.
    let cfg = MempoolConfig {
        per_peer_cost_budget: 5_000,
        ..Default::default()
    };
    let mut mempool = Mempool::new(cfg, Box::new(ByCost));
    let utxo = EmptyUtxo;
    let ctx = Ctx::new();
    let peer = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000);

    // First tx charges 10_000 to this peer — exceeds the 5_000 cap
    // AFTER the charge. That's fine for admission 1, but admission 2
    // from the same peer hits pre-admission exhaustion.
    let tx_a = b"a".to_vec();
    let v = MockValidator::new().plan(
        tx_a.clone(),
        MockPlan {
            result: Ok(Validated {
                tx_id: digest(1),
                input_box_ids: vec![digest(0xA)],
                output_box_ids: vec![digest(0xB)],
                outputs: vec![],
                fee: 5_000_000,
                size_bytes: 1,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let (out1, _) = mempool.process(
        &tx_a,
        TxSource::Peer(peer),
        Instant::now(),
        &ctx.view(&utxo),
        &v,
    );
    assert!(matches!(out1, AdmissionOutcome::Admitted { .. }));

    // Second tx from same peer: pre-admission budget gate fires.
    let tx_b = b"b".to_vec();
    let v2 = MockValidator::new().plan(
        tx_b.clone(),
        MockPlan {
            result: Ok(Validated {
                tx_id: digest(2),
                input_box_ids: vec![digest(0xC)],
                output_box_ids: vec![digest(0xD)],
                outputs: vec![],
                fee: 5_000_000,
                size_bytes: 1,
                consumed_cost: 10_000,
            }),
            charge: 10_000,
            peek_fee: None,
            peek_tx_id: None,
        },
    );
    let (out2, _) = mempool.process(
        &tx_b,
        TxSource::Peer(peer),
        Instant::now(),
        &ctx.view(&utxo),
        &v2,
    );
    assert!(matches!(out2, AdmissionOutcome::Rejected { .. }));

    // Peer disconnect forgets the per-peer counter; the same peer can
    // admit again on reconnect.
    mempool.on_peer_disconnected(&peer);
    let (out3, _) = mempool.process(
        &tx_b,
        TxSource::Peer(peer),
        Instant::now(),
        &ctx.view(&utxo),
        &v2,
    );
    assert!(matches!(out3, AdmissionOutcome::Admitted { .. }));
}

#[test]
fn failed_admission_populates_is_invalidated_inv_filter() {
    // The invalidation cache's only consumer is `Mempool::is_invalidated`,
    // the Inv fetch filter in ergo-node messaging — mirroring Scala's
    // ErgoNodeViewSynchronizer filter over `invalidatedTxIds`. Pin that
    // a validation failure makes the tx visible there under the same
    // key Inv announcements carry: the canonical proof-excluded tx_id.
    let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let utxo = EmptyUtxo;
    let ctx = Ctx::new();
    let peer = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000);

    let tx = b"bad".to_vec();
    let v = MockValidator::new().plan(
        tx.clone(),
        MockPlan {
            result: Err(ergo_mempool::admission::ValidationErr::ScriptFailed),
            charge: 10_000,
            peek_fee: Some(5_000_000),
            peek_tx_id: Some(digest(7)),
        },
    );
    assert!(!mempool.is_invalidated(&digest(7)));
    let (out, _) = mempool.process(
        &tx,
        TxSource::Peer(peer),
        Instant::now(),
        &ctx.view(&utxo),
        &v,
    );
    assert!(matches!(out, AdmissionOutcome::Rejected { .. }));
    assert!(
        mempool.is_invalidated(&digest(7)),
        "Inv filter must see the canonical tx_id after a validation failure"
    );
    assert!(!mempool.is_invalidated(&digest(8)));
}

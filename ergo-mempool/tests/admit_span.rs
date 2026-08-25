//! Span-emission contract for `Mempool::process` and `Mempool::check`.
//!
//! Both APIs are wrapped in `#[tracing::instrument]` (spans `admit` and
//! `admit_check` respectively). The span carries `source` and `bytes` at
//! entry; `tx_id` starts as `tracing::field::Empty` and is recorded by
//! `admission::check` once `peek_fee` returns the canonical id.
//!
//! These tests guard against silent regression — if someone deletes the
//! `#[instrument]` macro or removes the `Span::current().record(...)`
//! call in admission, the span output goes missing and the assertions
//! fire. We install a per-test fmt subscriber configured with
//! `FmtSpan::NEW` so span creation lands in the captured buffer even when
//! no event fires inside the span body.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ergo_mempool::admission::{MockPlan, MockValidator, TipContext, Validated};
use ergo_mempool::types::{TipPointer, TxSource};
use ergo_mempool::weight::ByCost;
use ergo_mempool::{AdmissionOutcome, Mempool, MempoolConfig};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::UtxoView;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::MakeWriter;

// ----- capture harness -----

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `body` with a per-test fmt subscriber that captures all
/// span-creation events at TRACE level into a buffer. Returns the
/// formatted log output.
fn capture_spans<R>(body: impl FnOnce() -> R) -> (R, String) {
    let buf = SharedBuf::new();
    // CLOSE-event format dumps the span's final field values, so a
    // field recorded mid-span via `Span::current().record(...)` (e.g.
    // tx_id after peek_fee) shows up in the captured output. NEW
    // alone would only see the entry-time fields.
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .with_ansi(false)
        .with_writer(buf.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, body);
    (result, buf.snapshot())
}

// ----- fixture helpers -----

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn id(b: u8) -> Digest32 {
    Digest32::from_bytes([b; 32])
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

fn tip_ctx<'a>(
    tx_ctx: &'a TransactionContext,
    params: &'a ProtocolParams,
    utxo: &'a dyn UtxoView,
) -> TipContext<'a> {
    TipContext {
        tip: TipPointer {
            height: 1000,
            header_id: id(0xFF),
        },
        best_header_height: 1000,
        best_full_block_height: 1000,
        utxo,
        tx_context: tx_ctx,
        params,
        last_headers: &[],
        reemission: None,
    }
}

fn validator_accepting(bytes: &'static [u8], tx_id_byte: u8, fee: u64) -> MockValidator {
    let tx_id = id(tx_id_byte);
    MockValidator::new().plan(
        bytes.to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id,
                input_box_ids: vec![id(0xA0)],
                output_box_ids: vec![id(0xB0)],
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

// ----- happy path -----

#[test]
fn admit_emits_span_with_resolved_tx_id() {
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);

    let (out, output) = capture_spans(|| {
        let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        let v = validator_accepting(b"span_test_bytes", 0x42, 1_000_000);
        let (o, _actions) =
            mempool.process(b"span_test_bytes", TxSource::Api, Instant::now(), &ctx, &v);
        o
    });
    assert!(
        matches!(out, AdmissionOutcome::Admitted { .. }),
        "got {out:?}"
    );

    assert!(
        output.contains("admit"),
        "missing admit span name in:\n{output}"
    );
    assert!(
        output.contains("source=Api"),
        "missing source=Api in:\n{output}"
    );
    assert!(
        output.contains("bytes=15"),
        "missing bytes=15 (len of \"span_test_bytes\") in:\n{output}"
    );
    let expected_tx_id_hex = hex::encode([0x42u8; 32]);
    assert!(
        output.contains(&expected_tx_id_hex),
        "missing recorded tx_id={expected_tx_id_hex} in:\n{output}"
    );
}

#[test]
fn admit_check_emits_span_with_resolved_tx_id() {
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);

    let ((), output) = capture_spans(|| {
        let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        let v = validator_accepting(b"check_only_bytes", 0x77, 2_000_000);
        let _ = mempool.check(b"check_only_bytes", TxSource::Api, Instant::now(), &ctx, &v);
    });

    assert!(
        output.contains("admit_check"),
        "missing admit_check span in:\n{output}"
    );
    assert!(output.contains("source=Api"));
    let expected_tx_id_hex = hex::encode([0x77u8; 32]);
    assert!(
        output.contains(&expected_tx_id_hex),
        "missing recorded tx_id={expected_tx_id_hex} in:\n{output}"
    );
}

// ----- error paths -----

#[test]
fn admit_pre_parse_reject_omits_tx_id() {
    // Reject before peek_fee runs (size cap) → tx_id stays Empty.
    // The fmt formatter renders an Empty field with no value, so a
    // recorded 32-byte hex id should NOT appear in the output.
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);

    let (out, output) = capture_spans(|| {
        let cfg = MempoolConfig {
            max_tx_size_bytes: 1,
            ..MempoolConfig::default()
        };
        let mut mempool = Mempool::new(cfg, Box::new(ByCost));
        let v = MockValidator::new();
        let (o, _) = mempool.process(b"too_long_to_fit", TxSource::Api, Instant::now(), &ctx, &v);
        o
    });
    assert!(matches!(out, AdmissionOutcome::Rejected { .. }));

    assert!(
        output.contains("admit"),
        "span should still fire on early reject:\n{output}"
    );
    assert!(output.contains("source=Api"));
    let zero_hex = hex::encode([0u8; 32]);
    assert!(
        !output.contains(&zero_hex),
        "tx_id should be Empty on size-cap reject, got recorded id in:\n{output}"
    );
}

// ----- family-admit tracing: defer to the commit decision -----
//
// `admit_family_atomic` stages parent + child on a pool clone and only
// swaps the clone in on full success. The admit/eviction/broadcast
// tracing for the parent must be DEFERRED to the commit decision: if the
// child later fails the family rolls back and the parent never lands, so
// a `mempool_tx_admitted` (or `mempool_tx_evicted`/`_replaced`) logged at
// parent-admit time would be a phantom event for a tx that didn't land.

/// A `MockPlan` that admits `bytes` as `tx_id_byte`, spending `input` and
/// creating `output`, with the given `fee`.
fn family_plan(
    bytes: &'static [u8],
    tx_id_byte: u8,
    input: u8,
    output: u8,
    fee: u64,
) -> (Vec<u8>, MockPlan) {
    (
        bytes.to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: id(tx_id_byte),
                input_box_ids: vec![id(input)],
                output_box_ids: vec![id(output)],
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

/// Seed a standalone low-weight pool entry the parent admission will
/// displace (double-spend replacement), so the parent's clone-admit emits
/// an eviction/replacement that must NOT be traced on the rollback path.
fn seed_victim(mp: &mut Mempool, tx_id_byte: u8, input: u8, output: u8, weight: u64) {
    let tx_id = id(tx_id_byte);
    let entry = ergo_mempool::Entry::new(
        tx_id,
        std::sync::Arc::from(vec![tx_id_byte; 20].into_boxed_slice()),
        vec![id(input)],
        vec![id(output)],
        vec![],
        1_000_000,
        weight,
        20,
        10_000,
        TxSource::Api,
    );
    mp.pool_mut().insert(entry).unwrap();
}

#[test]
fn family_child_fail_emits_no_phantom_parent_admit() {
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);

    let (out, output) = capture_spans(|| {
        let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        // Pre-existing low-weight victim spending box 0xA0; the heavier
        // parent double-spends it ⇒ its clone-admit would evict/replace
        // the victim (an eviction trace we must NOT emit on rollback).
        seed_victim(&mut mempool, 0x10, 0xA0, 0xF0, 100);

        // Parent admits on the clone (heavier double-spend of 0xA0).
        // Child has NO plan ⇒ the mock rejects it ⇒ half-family rollback.
        let (pb, pp) = family_plan(b"family_parent", 0x01, 0xA0, 0xB0, 50_000_000);
        let v = MockValidator::new().plan(pb, pp);

        mempool.admit_family_atomic(
            b"family_parent",
            Some(b"family_child"),
            TxSource::RentCollector,
            Instant::now(),
            &ctx,
            &v,
        )
    });

    // The family failed: nothing landed.
    assert!(out.tx_ids.is_empty(), "no ids on a failed family");
    assert!(
        out.broadcast_actions.is_empty(),
        "no actions on a failed family"
    );

    // The CHILD's rejection IS a real event worth logging.
    assert!(
        output.contains("mempool_tx_rejected"),
        "the child rejection must be traced, in:\n{output}"
    );
    // The parent's admit is PHANTOM — it never landed in the live pool.
    assert!(
        !output.contains("mempool_tx_admitted"),
        "no phantom parent admit may be traced on rollback, in:\n{output}"
    );
    // Neither may the parent's clone-side eviction/replacement of the victim.
    assert!(
        !output.contains("mempool_tx_evicted"),
        "no phantom eviction may be traced on rollback, in:\n{output}"
    );
    assert!(
        !output.contains("mempool_tx_replaced"),
        "no phantom replacement may be traced on rollback, in:\n{output}"
    );
}

#[test]
fn family_full_success_emits_admit_for_both() {
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);

    let (out, output) = capture_spans(|| {
        let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        // Parent admits; child spends the parent's output (a real CPFP edge).
        let (pb, pp) = family_plan(b"family_parent", 0x01, 0xA0, 0xB0, 1_000_000);
        let (cb, cp) = family_plan(b"family_child", 0x02, 0xB0, 0xC0, 5_000_000);
        let v = MockValidator::new().plan(pb, pp).plan(cb, cp);

        mempool.admit_family_atomic(
            b"family_parent",
            Some(b"family_child"),
            TxSource::RentCollector,
            Instant::now(),
            &ctx,
            &v,
        )
    });

    assert_eq!(
        out.tx_ids,
        vec![id(0x01), id(0x02)],
        "parent-first id order"
    );
    // Both family members must be traced as admitted on full success.
    assert!(
        output.contains("mempool_tx_admitted"),
        "an admit must be traced on full success, in:\n{output}"
    );
    let parent_hex = hex::encode([0x01u8; 32]);
    let child_hex = hex::encode([0x02u8; 32]);
    assert!(
        output.contains(&parent_hex),
        "parent admit trace (tx_id={parent_hex}) missing, in:\n{output}"
    );
    assert!(
        output.contains(&child_hex),
        "child admit trace (tx_id={child_hex}) missing, in:\n{output}"
    );
}

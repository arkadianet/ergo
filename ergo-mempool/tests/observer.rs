//! `MempoolObserver` wiring: fires from the same call sites as the
//! `mempool_tx_admitted` / `mempool_tx_evicted` tracing events, and ONLY
//! for real state transitions — never for `Mempool::check`'s check-only /
//! would-admit path.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use ergo_mempool::admission::{MockPlan, MockValidator, TipContext, Validated};
use ergo_mempool::types::{AppliedTx, TipPointer, TxDiff, TxSource};
use ergo_mempool::weight::ByCost;
use ergo_mempool::{AdmissionOutcome, CheckOutcome, Mempool, MempoolConfig, MempoolObserver, TxId};
use ergo_primitives::digest::Digest32;
use ergo_ser::ergo_box::ErgoBox;
use ergo_validation::context::{ProtocolParams, TransactionContext};
use ergo_validation::UtxoView;

// ----- fixture helpers -----

struct EmptyUtxo;
impl UtxoView for EmptyUtxo {
    fn get_box(&self, _: &Digest32) -> Option<ErgoBox> {
        None
    }
}

fn digest(b: u8) -> Digest32 {
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
            header_id: digest(0xFF),
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
    MockValidator::new().plan(
        bytes.to_vec(),
        MockPlan {
            result: Ok(Validated {
                tx_id: digest(tx_id_byte),
                input_box_ids: vec![digest(0xA0)],
                output_box_ids: vec![digest(0xB0)],
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

/// Records every `on_admitted` / `on_evicted` call for assertion. Mirrors
/// the shape a real observer (e.g. `ergo-node`'s `RealtimeMempoolObserver`)
/// would receive.
#[derive(Default)]
struct MockObserver {
    admitted: Mutex<Vec<(TxId, u64, u32)>>,
    evicted: Mutex<Vec<(TxId, String)>>,
}

impl MempoolObserver for MockObserver {
    fn on_admitted(&self, tx_id: TxId, fee: u64, size_bytes: u32) {
        self.admitted.lock().unwrap().push((tx_id, fee, size_bytes));
    }
    fn on_evicted(&self, tx_id: TxId, reason: &str) {
        self.evicted
            .lock()
            .unwrap()
            .push((tx_id, reason.to_string()));
    }
}

// ----- happy path -----

#[test]
fn process_admits_calls_observer_on_admitted_once() {
    let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let observer = Arc::new(MockObserver::default());
    mempool.set_observer(Some(observer.clone()));

    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);
    let validator = validator_accepting(b"observer_admit_tx", 0x11, 2_000_000);

    let (outcome, _actions) = mempool.process(
        b"observer_admit_tx",
        TxSource::Api,
        Instant::now(),
        &ctx,
        &validator,
    );
    assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));

    let admitted = observer.admitted.lock().unwrap();
    assert_eq!(admitted.len(), 1, "expected exactly one on_admitted call");
    assert_eq!(
        admitted[0],
        (digest(0x11), 2_000_000, "observer_admit_tx".len() as u32)
    );
    assert!(observer.evicted.lock().unwrap().is_empty());
}

#[test]
fn on_tip_change_confirming_a_pooled_tx_calls_observer_on_evicted() {
    let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let observer = Arc::new(MockObserver::default());
    mempool.set_observer(Some(observer.clone()));

    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);
    let validator = validator_accepting(b"observer_evict_tx", 0x22, 3_000_000);

    let (outcome, _) = mempool.process(
        b"observer_evict_tx",
        TxSource::Api,
        Instant::now(),
        &ctx,
        &validator,
    );
    assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
    observer.admitted.lock().unwrap().clear(); // isolate this test's assertion to the eviction

    // A block confirms the pooled tx — removed from the pool via the same
    // `ObservedEvent::Evicted` action the `mempool_tx_evicted` tracing event
    // fires for (reason `Confirmed`).
    let diff = TxDiff {
        new_tip: TipPointer {
            height: 1001,
            header_id: digest(0x01),
        },
        applied: vec![AppliedTx {
            tx_id: digest(0x22),
            spent_inputs: vec![digest(0xA0)],
        }],
        demoted: vec![],
        applied_spent_inputs: std::iter::once(digest(0xA0)).collect(),
    };
    mempool.on_tip_change(&diff);
    assert_eq!(mempool.size(), 0);

    let evicted = observer.evicted.lock().unwrap();
    assert_eq!(evicted.len(), 1, "expected exactly one on_evicted call");
    assert_eq!(evicted[0].0, digest(0x22));
}

// ----- error paths -----

#[test]
fn check_would_admit_never_calls_observer() {
    let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let observer = Arc::new(MockObserver::default());
    mempool.set_observer(Some(observer.clone()));

    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);
    let validator = validator_accepting(b"observer_check_only_tx", 0x33, 4_000_000);

    let (outcome, _actions) = mempool.check(
        b"observer_check_only_tx",
        TxSource::Api,
        Instant::now(),
        &ctx,
        &validator,
    );
    assert!(matches!(outcome, CheckOutcome::WouldAdmit { .. }));
    assert_eq!(mempool.size(), 0, "check must never insert into the pool");
    assert!(
        observer.admitted.lock().unwrap().is_empty(),
        "check-only outcomes must never fire the observer"
    );
    assert!(observer.evicted.lock().unwrap().is_empty());
}

#[test]
fn no_observer_set_is_a_safe_no_op() {
    // Default `Mempool::new` has no observer wired — every pre-A2 caller
    // and test keeps working unchanged.
    let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
    let utxo = EmptyUtxo;
    let txc = tx_ctx();
    let params = ProtocolParams::mainnet_default();
    let ctx = tip_ctx(&txc, &params, &utxo);
    let validator = validator_accepting(b"observer_none_tx", 0x44, 1_000_000);

    let (outcome, _actions) = mempool.process(
        b"observer_none_tx",
        TxSource::Api,
        Instant::now(),
        &ctx,
        &validator,
    );
    assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
}

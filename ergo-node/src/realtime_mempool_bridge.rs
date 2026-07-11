//! Bridges `ergo_mempool::MempoolObserver` to `ergo_api`'s realtime WS bus.
//!
//! `ergo-mempool` never depends on `ergo-api` — this adapter is the one-way
//! seam that lets admission/eviction/confirmation fire on the realtime bus
//! without the mempool crate ever learning `ergo-api` exists.
//! `RealtimeBus::publish` is synchronous and never blocks on a slow WS
//! client (drop-and-flag under the bus's never-block policy), so this stays
//! safe to call inline from the mempool's admission hot path (no `.await`,
//! no lock contention with the WS fan-out).
//!
//! Events describe **this node's pool under this node's policy / tip**.

use std::sync::Arc;

use ergo_api::v1::realtime::{RealtimeBus, RealtimeEventBody};
use ergo_mempool::{MempoolObserver, TxId};
use ergo_primitives::digest::Digest32;

use crate::snapshot::unix_now_ms;

/// Publishes mempool admit/evict/confirm telemetry onto the shared realtime bus.
pub struct RealtimeMempoolObserver {
    bus: Arc<RealtimeBus>,
}

impl RealtimeMempoolObserver {
    pub fn new(bus: Arc<RealtimeBus>) -> Self {
        Self { bus }
    }
}

impl MempoolObserver for RealtimeMempoolObserver {
    fn on_admitted(&self, tx_id: TxId, fee: u64, size_bytes: u32) {
        self.bus.publish(RealtimeEventBody::tx_accepted(
            unix_now_ms(),
            hex::encode(tx_id.as_bytes()),
            Some(fee),
            Some(u64::from(size_bytes)),
        ));
    }

    fn on_evicted(&self, tx_id: TxId, reason: &str) {
        self.bus.publish(RealtimeEventBody::tx_dropped(
            unix_now_ms(),
            hex::encode(tx_id.as_bytes()),
            reason.to_string(),
            None,
            None,
        ));
    }

    fn on_confirmed(&self, tx_id: TxId, height: u32, header_id: Digest32) {
        self.bus.publish(RealtimeEventBody::tx_confirmed(
            unix_now_ms(),
            hex::encode(tx_id.as_bytes()),
            height,
            hex::encode(header_id.as_bytes()),
        ));
    }

    fn on_replaced(&self, loser_id: TxId, winner_id: TxId) {
        self.bus.publish(RealtimeEventBody::tx_dropped(
            unix_now_ms(),
            hex::encode(loser_id.as_bytes()),
            "Replaced".to_string(),
            None,
            Some(hex::encode(winner_id.as_bytes())),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_api::v1::realtime::RealtimeHandle;
    use ergo_mempool::admission::{MockPlan, MockValidator, TipContext, Validated};
    use ergo_mempool::types::{TipPointer, TxSource};
    use ergo_mempool::weight::ByCost;
    use ergo_mempool::{AdmissionOutcome, Mempool, MempoolConfig};
    use ergo_primitives::digest::Digest32;
    use ergo_ser::ergo_box::ErgoBox;
    use ergo_validation::context::{ProtocolParams, TransactionContext};
    use ergo_validation::UtxoView;

    // ----- fixture helpers (mirrors ergo-mempool/tests/admit_span.rs) -----

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
        MockValidator::new().plan(
            bytes.to_vec(),
            MockPlan {
                result: Ok(Validated {
                    tx_id: id(tx_id_byte),
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

    /// Integration-style: real `Mempool` + real `RealtimeBus`, wired through
    /// `RealtimeMempoolObserver`. Admitting one tx must publish exactly one
    /// `tx_accepted` on the live `mempool` channel.
    #[test]
    fn admitted_tx_publishes_one_tx_accepted_on_mempool_channel() {
        let handle = RealtimeHandle::blocks_and_mempool();
        let sub = handle.bus.subscribe();
        sub.filter.write().unwrap().insert("mempool".to_string());

        let mut mempool = Mempool::new(MempoolConfig::default(), Box::new(ByCost));
        mempool.set_observer(Some(Arc::new(RealtimeMempoolObserver::new(
            handle.bus.clone(),
        ))));

        let utxo = EmptyUtxo;
        let txc = tx_ctx();
        let params = ProtocolParams::mainnet_default();
        let ctx = tip_ctx(&txc, &params, &utxo);
        let validator = validator_accepting(b"observer_bridge_tx", 0x9, 1_500_000);

        let (outcome, _actions) = mempool.process(
            b"observer_bridge_tx",
            TxSource::Api,
            std::time::Instant::now(),
            &ctx,
            &validator,
        );
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "got {outcome:?}"
        );

        let mut sub = sub;
        let event = sub
            .rx
            .try_recv()
            .expect("tx_accepted should have been published on admission");
        assert_eq!(event.event, "tx_accepted");
        assert_eq!(event.routes, vec!["mempool".to_string()]);
        assert!(!event.confirmed, "mempool events are tentative");
        assert_eq!(
            event.data["tx_id"],
            serde_json::json!(hex::encode(id(0x9).as_bytes()))
        );
        assert!(
            sub.rx.try_recv().is_err(),
            "exactly one tx_accepted expected, got a second event"
        );
    }

    #[test]
    fn confirmed_tx_publishes_tx_confirmed_on_mempool_channel() {
        let handle = RealtimeHandle::blocks_and_mempool();
        let mut sub = handle.bus.subscribe();
        sub.filter.write().unwrap().insert("mempool".to_string());

        let obs = RealtimeMempoolObserver::new(handle.bus.clone());
        let tx = id(0x11);
        let header = id(0x22);
        obs.on_confirmed(tx, 1_234, header);

        let event = sub
            .rx
            .try_recv()
            .expect("tx_confirmed should have been published");
        assert_eq!(event.event, "tx_confirmed");
        assert!(event.confirmed);
        assert_eq!(
            event.data["tx_id"],
            serde_json::json!(hex::encode(tx.as_bytes()))
        );
        assert_eq!(event.data["height"], serde_json::json!(1_234));
        assert_eq!(
            event.data["header_id"],
            serde_json::json!(hex::encode(header.as_bytes()))
        );
        assert!(
            event.routes.iter().any(|r| r == "mempool"),
            "routes={:?}",
            event.routes
        );
    }

    #[test]
    fn replaced_tx_publishes_tx_dropped_with_winner_id() {
        let handle = RealtimeHandle::blocks_and_mempool();
        let mut sub = handle.bus.subscribe();
        sub.filter.write().unwrap().insert("mempool".to_string());

        let obs = RealtimeMempoolObserver::new(handle.bus.clone());
        let loser = id(0x33);
        let winner = id(0x44);
        obs.on_replaced(loser, winner);

        let event = sub
            .rx
            .try_recv()
            .expect("tx_dropped should have been published for replacement");
        assert_eq!(event.event, "tx_dropped");
        assert!(!event.confirmed);
        assert_eq!(
            event.data["tx_id"],
            serde_json::json!(hex::encode(loser.as_bytes()))
        );
        assert_eq!(event.data["reason"], serde_json::json!("Replaced"));
        assert_eq!(
            event.data["winner_id"],
            serde_json::json!(hex::encode(winner.as_bytes()))
        );
        assert!(
            event.routes.iter().any(|r| r == "mempool"),
            "routes={:?}",
            event.routes
        );
    }
}

//! Post-commit extra-index changes projected onto the shared realtime bus.
//! Capturing is optional; publication starts only after successful API bind
//! and durable webhook cursor restoration. Subscriber queues are never awaited.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use ergo_api::v1::realtime::bus::RESUME_WINDOW;
use ergo_api::v1::realtime::{ChannelClass, IndexedBoxEventKind, RealtimeBus, RealtimeEventBody};
use ergo_indexer::{BlockChanges, BoxChange, BoxChangeKind, IndexerObserver};
use ergo_primitives::digest::Digest32;
use ergo_ser::address::NetworkPrefix;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OriginalKey {
    header: Digest32,
    kind: BoxChangeKind,
    box_id: Digest32,
    token_id: Option<Digest32>,
    tx_id: Digest32,
}

impl OriginalKey {
    fn new(header: Digest32, change: &BoxChange, token_id: Option<Digest32>) -> Self {
        Self {
            header,
            kind: match change.kind {
                BoxChangeKind::Created | BoxChangeKind::Reverted => BoxChangeKind::Created,
                BoxChangeKind::Spent | BoxChangeKind::Unspent => BoxChangeKind::Spent,
            },
            box_id: change.box_id,
            token_id,
            tx_id: change.tx_id,
        }
    }
}

#[derive(Default)]
struct Originals {
    entries: HashMap<OriginalKey, u64>,
    order: VecDeque<(OriginalKey, u64)>,
}

impl Originals {
    fn prune(&mut self, current_seq: u64) {
        while self
            .order
            .front()
            .is_some_and(|(_, seq)| *seq <= current_seq.saturating_sub(RESUME_WINDOW as u64))
            || self.order.len() > RESUME_WINDOW
        {
            let (key, seq) = self.order.pop_front().expect("nonempty original queue");
            if self.entries.get(&key) == Some(&seq) {
                self.entries.remove(&key);
            }
        }
    }

    fn remember(&mut self, key: OriginalKey, seq: u64) {
        self.entries.insert(key, seq);
        self.order.push_back((key, seq));
        self.prune(seq);
    }
}

/// Installed only for a healthy indexer when API configuration is enabled.
/// Boot-time catch-up before activation is deliberately not a replay feed.
pub struct RealtimeIndexerObserver {
    network: NetworkPrefix,
    bus: OnceLock<Arc<RealtimeBus>>,
    originals: Mutex<Originals>,
}

impl RealtimeIndexerObserver {
    pub fn new(network: NetworkPrefix) -> Self {
        Self {
            network,
            bus: OnceLock::new(),
            originals: Mutex::new(Originals::default()),
        }
    }

    /// Call after API bind and durable cursor bootstrap, before serving.
    /// Availability follows an installed writer observer, never a query handle.
    pub fn activate(&self, bus: Arc<RealtimeBus>) {
        if self.bus.set(bus.clone()).is_ok() {
            bus.enable_classes([
                ChannelClass::Address,
                ChannelClass::Box,
                ChannelClass::Token,
            ]);
        }
    }

    fn publish(
        bus: &RealtimeBus,
        originals: &mut Originals,
        key: OriginalKey,
        inverse: bool,
        mut body: RealtimeEventBody,
    ) {
        originals.prune(bus.latest_seq().saturating_add(1));
        if inverse {
            body.previous_seq = originals.entries.remove(&key);
        }
        let seq = bus.publish(body);
        if !inverse {
            originals.remember(key, seq);
        }
    }
}

impl IndexerObserver for RealtimeIndexerObserver {
    fn on_committed(&self, changes: BlockChanges) {
        let Some(bus) = self.bus.get() else {
            return;
        };
        let mut originals = self.originals.lock().unwrap_or_else(|e| e.into_inner());
        let unix_ms = crate::snapshot::unix_now_ms();
        let header_id = hex::encode(changes.header_id.as_bytes());
        for change in changes.boxes {
            let kind = match change.kind {
                BoxChangeKind::Created => IndexedBoxEventKind::Created,
                BoxChangeKind::Spent => IndexedBoxEventKind::Spent,
                BoxChangeKind::Reverted => IndexedBoxEventKind::Reverted,
                BoxChangeKind::Unspent => IndexedBoxEventKind::Unspent,
            };
            let body = match RealtimeEventBody::indexed_box(
                unix_ms,
                self.network,
                kind,
                &change.record,
                changes.height,
                header_id.clone(),
            ) {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(%error, box_id = %hex::encode(change.box_id.as_bytes()), "indexed realtime box projection failed");
                    continue;
                }
            };
            let address = body.data["address"].clone();
            let inverse = matches!(
                change.kind,
                BoxChangeKind::Reverted | BoxChangeKind::Unspent
            );
            Self::publish(
                bus,
                &mut originals,
                OriginalKey::new(changes.header_id, &change, None),
                inverse,
                body,
            );
            for token in &change.record.box_data.candidate.tokens {
                let token_id = hex::encode(token.token_id.as_bytes());
                let body = RealtimeEventBody {
                    emitted_at_unix_ms: unix_ms,
                    routes: vec![format!("token:{token_id}")],
                    event: if inverse {
                        "token_reverted"
                    } else {
                        "token_moved"
                    },
                    confirmed: !inverse,
                    height: Some(changes.height),
                    data: serde_json::json!({
                        "token_id":token_id, "amount":token.amount.to_string(),
                        "direction":if matches!(change.kind, BoxChangeKind::Created | BoxChangeKind::Unspent) { "in" } else { "out" },
                        "tx_id":hex::encode(change.tx_id.as_bytes()), "header_id":header_id,
                        "box_id":hex::encode(change.box_id.as_bytes()), "address":address,
                    }),
                    previous_seq: None,
                };
                Self::publish(
                    bus,
                    &mut originals,
                    OriginalKey::new(changes.header_id, &change, Some(token.token_id)),
                    inverse,
                    body,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_api::v1::realtime::bus::SUB_QUEUE_CAP;
    use ergo_indexer::{
        ChainTip, IndexerChainSource, IndexerFullBlock, IndexerHandle, IndexerQuery, IndexerStore,
        IndexerTask,
    };
    use ergo_ser::ergo_box::{ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::input::{ContextExtension, Input, SpendingProof};
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::{SigmaBoolean, SigmaValue};
    use ergo_ser::token::Token;
    use ergo_ser::transaction::{transaction_id, Transaction};
    use std::sync::atomic::{AtomicU32, Ordering};

    // ----- helpers -----

    fn id(byte: u8) -> Digest32 {
        Digest32::from_bytes([byte; 32])
    }

    fn candidate(height: u32, tokens: Vec<Token>) -> ErgoBoxCandidate {
        ErgoBoxCandidate::new(
            1_000_000,
            ErgoTree {
                version: 0,
                has_size: false,
                constant_segregation: false,
                reserved_header_bits: 0,
                constants: vec![],
                body: Expr::Const {
                    tpe: SigmaType::SSigmaProp,
                    val: SigmaValue::SigmaProp(SigmaBoolean::TrivialProp(true)),
                },
            },
            height,
            tokens,
            AdditionalRegisters::empty(),
        )
        .unwrap()
    }

    fn record() -> ergo_indexer::IndexedErgoBox {
        ergo_indexer::IndexedErgoBox {
            inclusion_height: 2,
            spending_tx_id: None,
            spending_height: None,
            spending_proof: None,
            box_data: ErgoBox {
                candidate: candidate(
                    2,
                    vec![Token {
                        token_id: id(7),
                        amount: 100,
                    }],
                ),
                transaction_id: id(3).into(),
                index: 0,
            },
            global_index: 1,
        }
    }

    fn changes(kind: BoxChangeKind, header: Digest32) -> BlockChanges {
        let mut record = record();
        if kind == BoxChangeKind::Spent {
            record.spending_tx_id = Some(id(4));
            record.spending_height = Some(3);
            record.spending_proof =
                Some(SpendingProof::new(vec![], ContextExtension::empty()).unwrap());
        }
        BlockChanges {
            header_id: header,
            height: 3,
            boxes: vec![BoxChange {
                box_id: record.box_data.box_id().unwrap(),
                tx_id: if matches!(kind, BoxChangeKind::Created | BoxChangeKind::Reverted) {
                    id(3)
                } else {
                    id(4)
                },
                kind,
                record,
            }],
        }
    }

    #[test]
    fn indexed_availability_and_events_stay_with_the_owning_node_services() {
        let first = ergo_api::ApiServices::new();
        let second = ergo_api::ApiServices::new();
        let observer = RealtimeIndexerObserver::new(NetworkPrefix::Mainnet);
        observer.activate(first.realtime.bus.clone());
        assert!(first.realtime.bus.is_live(ChannelClass::Address));
        assert!(!second.realtime.bus.is_live(ChannelClass::Address));
        observer.on_committed(changes(BoxChangeKind::Created, id(9)));
        assert!(first.realtime.bus.latest_seq() > 0);
        assert_eq!(second.realtime.bus.latest_seq(), 0);
        let restarted = ergo_api::ApiServices::new();
        assert!(!restarted.realtime.bus.is_live(ChannelClass::Address));
        assert_eq!(restarted.realtime.bus.latest_seq(), 0);
    }

    fn setup() -> (Arc<RealtimeBus>, RealtimeIndexerObserver) {
        let bus = Arc::new(RealtimeBus::blocks_and_mempool());
        let observer = RealtimeIndexerObserver::new(NetworkPrefix::Mainnet);
        observer.activate(bus.clone());
        (bus, observer)
    }

    fn all_events(bus: &RealtimeBus) -> Vec<Arc<ergo_api::v1::realtime::RealtimeEvent>> {
        bus.backfill(
            &[format!("token:{}", hex::encode(id(7).as_bytes()))].into(),
            0,
            RESUME_WINDOW,
        )
        .events
    }

    // ----- happy path -----

    #[test]
    fn inactive_observer_publishes_nothing_and_does_not_enable_classes() {
        let bus = Arc::new(RealtimeBus::blocks_and_mempool());
        let observer = RealtimeIndexerObserver::new(NetworkPrefix::Mainnet);
        observer.on_committed(changes(BoxChangeKind::Created, id(10)));
        assert_eq!(bus.latest_seq(), 0);
        assert!(!bus.is_live(ChannelClass::Address));
        observer.activate(bus.clone());
        assert!(bus.is_live(ChannelClass::Address));
        assert!(bus.is_live(ChannelClass::Box));
        assert!(bus.is_live(ChannelClass::Token));
        assert_eq!(bus.latest_seq(), 0);
    }

    #[test]
    fn mint_and_spend_payloads_use_canonical_box_and_decimal_token_amounts() {
        let (bus, observer) = setup();
        let mut sub = bus.subscribe();
        let body = RealtimeEventBody::indexed_box(
            0,
            NetworkPrefix::Mainnet,
            IndexedBoxEventKind::Created,
            &record(),
            3,
            hex::encode(id(10).as_bytes()),
        )
        .unwrap();
        *sub.filter.write().unwrap() = body.routes.clone().into_iter().collect();
        observer.on_committed(changes(BoxChangeKind::Created, id(10)));
        let created = sub.rx.try_recv().unwrap();
        assert_eq!(created.event, "box_created");
        assert_eq!(created.data, body.data);
        assert_eq!(created.data["value"], "1000000");
        assert_eq!(created.data["assets"][0]["amount"], "100");
        assert_eq!(created.routes.len(), 1);
        observer.on_committed(changes(BoxChangeKind::Spent, id(11)));
        let spent = sub.rx.try_recv().unwrap();
        assert_eq!(spent.event, "box_spent");
        assert_eq!(spent.routes.len(), 2);
        assert_eq!(spent.data["spent_by"], hex::encode(id(4).as_bytes()));
        let tokens = all_events(&bus);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].data["direction"], "in");
        assert_eq!(tokens[1].data["direction"], "out");
        assert_eq!(tokens[1].data["tx_id"], hex::encode(id(4).as_bytes()));
    }

    #[test]
    fn reorg_inverse_links_original_box_and_token_or_none_for_unseen_history() {
        let (bus, observer) = setup();
        observer.on_committed(changes(BoxChangeKind::Created, id(10)));
        observer.on_committed(changes(BoxChangeKind::Spent, id(11)));
        observer.on_committed(changes(BoxChangeKind::Unspent, id(11)));
        observer.on_committed(changes(BoxChangeKind::Reverted, id(10)));
        let key = format!(
            "box:{}",
            hex::encode(record().box_data.box_id().unwrap().as_bytes())
        );
        let boxes = bus.backfill(&[key].into(), 0, 100).events;
        assert_eq!(boxes.len(), 2);
        assert_eq!(boxes[1].event, "box_unspent");
        assert_eq!(boxes[1].previous_seq, Some(boxes[0].seq));
        assert!(boxes[1].data["spent_by"].is_null());
        assert_eq!(boxes[1].data["confirmations"], 0);
        let tokens = all_events(&bus);
        assert_eq!(tokens[2].event, "token_reverted");
        assert_eq!(tokens[2].previous_seq, Some(tokens[1].seq));
        assert_eq!(tokens[2].data["direction"], "in");
        assert_eq!(tokens[3].previous_seq, Some(tokens[0].seq));
        assert_eq!(tokens[3].data["direction"], "out");
        observer.on_committed(changes(BoxChangeKind::Reverted, id(12)));
        assert_eq!(all_events(&bus).last().unwrap().previous_seq, None);
    }

    struct Chain {
        blocks: Vec<IndexerFullBlock>,
        tip: AtomicU32,
    }
    impl IndexerChainSource for Chain {
        fn committed_tip(&self) -> Result<ChainTip, ergo_indexer::IndexerError> {
            let height = self.tip.load(Ordering::Relaxed);
            Ok(ChainTip {
                height,
                header_id: self.blocks[height as usize - 1].header_id,
            })
        }
        fn header_id_at(
            &self,
            height: u32,
        ) -> Result<Option<Digest32>, ergo_indexer::IndexerError> {
            if height > self.tip.load(Ordering::Relaxed) {
                return Ok(None);
            }
            Ok(height
                .checked_sub(1)
                .and_then(|index| self.blocks.get(index as usize))
                .map(|b| b.header_id))
        }
        fn full_block(
            &self,
            id: &Digest32,
        ) -> Result<Option<IndexerFullBlock>, ergo_indexer::IndexerError> {
            Ok(self.blocks.iter().find(|b| &b.header_id == id).cloned())
        }
    }

    #[test]
    fn real_indexer_commit_mint_spend_and_rollback_reach_shared_bus() {
        // Synthetic indexer inputs exercise the real writer/observer pipeline;
        // this test makes no new consensus/hash oracle claim.
        let seed = Transaction {
            inputs: vec![],
            data_inputs: vec![],
            output_candidates: vec![candidate(1, vec![])],
        };
        let seed_box = ErgoBox {
            candidate: seed.output_candidates[0].clone(),
            transaction_id: transaction_id(&seed).unwrap(),
            index: 0,
        };
        let token_id = seed_box.box_id().unwrap();
        let mint = Transaction {
            inputs: vec![Input {
                box_id: token_id,
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![candidate(
                2,
                vec![Token {
                    token_id,
                    amount: 100,
                }],
            )],
        };
        let minted = ErgoBox {
            candidate: mint.output_candidates[0].clone(),
            transaction_id: transaction_id(&mint).unwrap(),
            index: 0,
        };
        let spend = Transaction {
            inputs: vec![Input {
                box_id: minted.box_id().unwrap(),
                spending_proof: SpendingProof::new(vec![], ContextExtension::empty()).unwrap(),
            }],
            data_inputs: vec![],
            output_candidates: vec![candidate(
                3,
                vec![Token {
                    token_id,
                    amount: 100,
                }],
            )],
        };
        let chain = Arc::new(Chain {
            blocks: vec![seed, mint, spend]
                .into_iter()
                .enumerate()
                .map(|(i, tx)| IndexerFullBlock {
                    height: i as i32 + 1,
                    header_id: id(i as u8 + 10),
                    transactions: vec![tx],
                })
                .collect(),
            tip: AtomicU32::new(3),
        });
        let directory = tempfile::tempdir().unwrap();
        let (store, _) = IndexerStore::open(&directory.path().join("indexer.redb")).unwrap();
        let handle = IndexerHandle::with_store(store, 0);
        let (bus, observer) = setup();
        let mut task =
            IndexerTask::new(handle.clone(), chain.clone()).with_observer(Arc::new(observer));
        for _ in 0..3 {
            task.step();
        }
        assert_eq!(handle.indexed_height(), 3);
        let filter = [format!("token:{}", hex::encode(token_id.as_bytes()))].into();
        let forward = bus.backfill(&filter, 0, 100).events;
        assert_eq!(forward.len(), 3);
        assert_eq!(
            forward
                .iter()
                .map(|e| e.data["direction"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["in", "out", "in"]
        );
        chain.tip.store(1, Ordering::Relaxed);
        task.step();
        assert_eq!(handle.indexed_height(), 2);
        task.step();
        assert_eq!(handle.indexed_height(), 1);
        let inverses = bus
            .backfill(&filter, forward.last().unwrap().seq, 100)
            .events;
        assert_eq!(inverses.len(), 3);
        assert!(inverses.iter().all(|e| e.event == "token_reverted"));
        assert_eq!(
            inverses
                .iter()
                .map(|e| e.previous_seq.unwrap())
                .collect::<Vec<_>>(),
            forward.iter().rev().map(|e| e.seq).collect::<Vec<_>>()
        );
    }

    // ----- error paths -----

    #[test]
    fn slow_address_consumer_does_not_stall_indexer_observations() {
        let (bus, observer) = setup();
        let sub = bus.subscribe();
        let body = RealtimeEventBody::indexed_box(
            0,
            NetworkPrefix::Mainnet,
            IndexedBoxEventKind::Created,
            &record(),
            3,
            String::new(),
        )
        .unwrap();
        *sub.filter.write().unwrap() = body.routes.into_iter().collect();
        for _ in 0..SUB_QUEUE_CAP + 5 {
            observer.on_committed(changes(BoxChangeKind::Created, id(10)));
        }
        assert!(sub.lagged.load(Ordering::Acquire));
        assert_eq!(bus.latest_seq(), ((SUB_QUEUE_CAP + 5) * 2) as u64);
    }

    #[test]
    fn original_ledger_is_bounded_and_other_global_events_age_links_out() {
        let (bus, observer) = setup();
        for _ in 0..RESUME_WINDOW {
            observer.on_committed(changes(BoxChangeKind::Created, id(10)));
        }
        let originals = observer.originals.lock().unwrap();
        assert!(originals.order.len() <= RESUME_WINDOW);
        assert!(originals.entries.len() <= RESUME_WINDOW);
        drop(originals);
        for _ in 0..RESUME_WINDOW {
            bus.publish(RealtimeEventBody::block_applied(0, String::new(), 1, 0, 0));
        }
        observer.on_committed(changes(BoxChangeKind::Reverted, id(10)));
        assert_eq!(all_events(&bus).last().unwrap().previous_seq, None);
        assert!(observer.originals.lock().unwrap().entries.is_empty());
    }
}

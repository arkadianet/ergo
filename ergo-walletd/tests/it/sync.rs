use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ergo_wallet_service::wallet::scan::RescanBlock;
use ergo_wallet_service::{
    BlocksSinceResponse, ChainClient, ChainCursor, CommittedTip, RedbWalletStore, RescanState,
    WalletService, WalletStore,
};
use ergo_walletd::sync::{StandaloneSyncer, SyncConfig, SyncError};
use ergo_walletd::tip::CachedNodeTip;

use crate::support::{block, FakeChain, WriteSpy};

/// `batch` is the apply budget and `page` the HTTP page size. Tests that care
/// about paging pass both explicitly; tests that care about something else pass
/// a page at least as large as the apply budget so the apply budget stays the
/// only visible limit.
fn config(batch: u32, page: u32) -> SyncConfig {
    SyncConfig {
        batch,
        page,
        retry_delay: std::time::Duration::ZERO,
        max_retry_delay: std::time::Duration::ZERO,
    }
}

fn build_syncer(
    chain: Arc<dyn ChainClient>,
    store: Arc<RedbWalletStore>,
    batch: u32,
) -> StandaloneSyncer {
    build_syncer_with(chain, store, batch, batch)
}

fn build_syncer_with(
    chain: Arc<dyn ChainClient>,
    store: Arc<RedbWalletStore>,
    batch: u32,
    page: u32,
) -> StandaloneSyncer {
    let service = Arc::new(WalletService::new(store, chain.clone()));
    StandaloneSyncer::new(
        service,
        config(batch, page),
        Arc::new(CachedNodeTip::new(chain)),
    )
}

#[test]
fn forward_sync_uses_requested_cursor_and_limit_across_batches() {
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(7, [7; 32]));
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer(chain.clone(), store, 3);
    assert!(!syncer.sync_once().unwrap().completed);
    assert!(!syncer.sync_once().unwrap().completed);
    assert!(syncer.sync_once().unwrap().completed);
    assert_eq!(chain.requests(), vec![(0, 3), (3, 3), (6, 2)]);
}

/// The apply budget and the HTTP page size are separate knobs. A pass applies
/// up to `batch` blocks, but no single call may ask for more than `page`, so a
/// large apply budget cannot turn into one unbounded response body.
#[test]
fn page_size_bounds_every_request_while_the_batch_budget_still_applies() {
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(7, [7; 32]));
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer_with(chain.clone(), store, 8, 2);
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.blocks_processed, 7);
    let requests = chain.requests();
    assert_eq!(
        requests,
        vec![(0, 2), (2, 2), (4, 2), (6, 2)],
        "seven blocks at a two-block page: four requests, the last of which the \
         node answers with the single block it has left"
    );
    assert!(
        requests.iter().all(|(_, limit)| *limit <= 2),
        "no request may exceed the page budget: {requests:?}"
    );
    assert_eq!(
        syncer
            .service()
            .store()
            .read()
            .unwrap()
            .scan_cursor()
            .unwrap()
            .unwrap()
            .height,
        7
    );
}

/// The shipped default is a *page* of 1, not the apply budget: an unbounded
/// page grows with `sync_batch` until it hits the adapter's response cap.
///
/// The value is the largest page whose *worst legal* body provably fits the cap,
/// and this pins that arithmetic rather than asserting the constant alone:
/// consensus bounds one block's `BlockTransactions` section by the voted
/// `maxBlockSize`, the largest value `docs/configuration.md` shows an operator
/// voting for is 2 MiB, and the wire form hex-encodes every byte of it.
#[test]
fn the_default_page_is_the_bounded_constant_not_the_apply_budget() {
    const DOCUMENTED_MAX_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
    // Worst-case body for a page of N blocks: hex doubles every box byte, plus a
    // deliberately loose allowance for the JSON envelope. The real envelope is a
    // few hundred kilobytes, so this over-counts and cannot make the default look
    // safer than it is.
    const ENVELOPE_ALLOWANCE_PER_BLOCK: u64 = 1024 * 1024;
    let worst_case_body = |blocks: u64| -> u64 {
        blocks * (2 * DOCUMENTED_MAX_BLOCK_SIZE + ENVELOPE_ALLOWANCE_PER_BLOCK)
    };
    let cap = ergo_walletd::chain_http::MAX_RESPONSE_BODY_BYTES as u64;

    assert_eq!(SyncConfig::default().page, 1);
    assert_eq!(
        SyncConfig::default().page,
        ergo_walletd::sync::DEFAULT_BLOCKS_PER_PAGE
    );
    assert!(SyncConfig::default().page < SyncConfig::default().batch);
    assert!(
        worst_case_body(SyncConfig::default().page as u64) < cap,
        "one maxed-out block must fit the cap under a loose envelope: {} vs {cap}",
        worst_case_body(SyncConfig::default().page as u64)
    );
    assert!(
        worst_case_body(SyncConfig::default().page as u64 + 1) > cap,
        "a two-block page is not provably under the cap, so it cannot be the \
         default: {} vs {cap}",
        worst_case_body(SyncConfig::default().page as u64 + 1)
    );
}

/// An unbounded page is a configuration error, not a startup loop against the
/// node: a page of 0 asks for nothing, and a page above the node's own
/// `blocks-since` limit would be rejected on every request.
#[test]
fn an_out_of_range_page_fails_the_pass_without_calling_the_node() {
    for page in [0, 1025] {
        let dir = tempfile::tempdir().unwrap();
        let chain = FakeChain::new(CommittedTip::new(3, [3; 32]));
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let syncer = build_syncer_with(chain.clone(), store, 16, page);
        let error = syncer.sync_once().unwrap_err();
        assert!(matches!(error, SyncError::Protocol(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("page size must be between 1 and 1024"),
            "{error}"
        );
        assert!(chain.requests().is_empty(), "the node must not be called");
    }
}

/// A page that cannot fit the adapter's response cap cannot be retried smaller:
/// the daemon never shrinks a page, so the pass must fail closed on the first
/// response, with an error that names both the cap and the page, and leave a
/// durable `failed` state behind.
#[test]
fn an_oversized_page_is_a_bounded_terminal_error_rather_than_a_loop() {
    use ergo_wallet_service::{
        ChainClientError, ChainSnapshot, SubmitRequest, SubmitResponse, UtxoLookup,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AlwaysTooLarge {
        calls: AtomicUsize,
    }

    impl ChainClient for AlwaysTooLarge {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            Ok(CommittedTip::new(3, [3; 32]))
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn blocks_since(
            &self,
            _request: ergo_wallet_service::BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ChainClientError::Protocol(
                "a 2-block page does not fit the 8388608-byte response cap; the daemon does not \
                 retry with a smaller page, so a single block larger than the cap is terminal"
                    .to_string(),
            ))
        }

        fn lookup_utxo(
            &self,
            _box_id: [u8; 32],
            _expected_tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }

        fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            Err(ChainClientError::Unsupported)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let chain = Arc::new(AlwaysTooLarge {
        calls: AtomicUsize::new(0),
    });
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer_with(chain.clone(), store, 16, 2);
    let error = syncer.sync_once().unwrap_err();
    assert!(matches!(error, SyncError::Protocol(_)), "{error}");
    assert!(
        !error.retryable(),
        "a page over the cap is terminal: no retry can make it smaller"
    );
    assert_eq!(
        chain.calls.load(Ordering::SeqCst),
        1,
        "exactly one request, then the pass gives up"
    );
    assert!(matches!(
        syncer
            .service()
            .store()
            .read()
            .unwrap()
            .rescan_state()
            .unwrap(),
        RescanState::Failed { .. }
    ));
}

#[test]
fn ancestor_response_rewinds_to_the_returned_cursor_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(3, [30; 32]);
    let chain = FakeChain::with_responses(
        tip.clone(),
        [
            BlocksSinceResponse::Ancestor(ergo_wallet_service::AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: ChainCursor {
                    height: 1,
                    header_id: [1; 32],
                },
            }),
            BlocksSinceResponse::Forward(ergo_wallet_service::ForwardBlocksSince {
                tip: tip.clone(),
                blocks: vec![
                    ergo_wallet_service::ChainBlock {
                        block_id: [21; 32],
                        height: 2,
                        parent_id: [1; 32],
                        transactions: Vec::new(),
                    },
                    ergo_wallet_service::ChainBlock {
                        block_id: [30; 32],
                        height: 3,
                        parent_id: [21; 32],
                        transactions: Vec::new(),
                    },
                ],
            }),
        ],
    );
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    for height in 1..=3u32 {
        write
            .apply_rescan_block(
                height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                },
                None,
            )
            .unwrap();
    }
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 16);
    let report = syncer.sync_once().unwrap();
    assert_eq!(report.wallet_height, 3);
    assert_eq!(report.blocks_processed, 2);
    assert_eq!(chain.requests(), vec![(3, 1), (1, 3)]);
    let cursor = syncer
        .service()
        .store()
        .read()
        .unwrap()
        .scan_cursor()
        .unwrap()
        .unwrap();
    assert_eq!(cursor.height, 3);
    assert_eq!(cursor.header_id, Some([30; 32]));
}

#[test]
fn unavailable_ancestor_falls_back_to_a_full_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(3, [3; 32]);
    let chain = FakeChain::with_responses(
        tip.clone(),
        [
            BlocksSinceResponse::Ancestor(ergo_wallet_service::AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: ChainCursor {
                    height: 1,
                    header_id: [1; 32],
                },
            }),
            BlocksSinceResponse::Forward(ergo_wallet_service::ForwardBlocksSince {
                tip: tip.clone(),
                blocks: vec![block(1), block(2), block(3)],
            }),
        ],
    );
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.set_scan_cursor(3, Some(&[9; 32])).unwrap();
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 16);
    let report = syncer.sync_once().unwrap();
    assert!(report.completed);
    assert_eq!(chain.requests(), vec![(3, 1), (0, 4)]);
    assert!(!syncer
        .service()
        .store()
        .read()
        .unwrap()
        .scan_invalidated()
        .unwrap());
}

#[test]
fn pruned_sync_is_typed_and_persists_failed_state() {
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(9, [9; 32]);
    let chain = FakeChain::with_responses(
        tip.clone(),
        [BlocksSinceResponse::Pruned(
            ergo_wallet_service::PrunedBlocksSince {
                tip,
                minimum_height: 4,
            },
        )],
    );
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer(chain.clone(), store, 4);
    assert!(matches!(syncer.sync_once(), Err(SyncError::Pruned(4))));
    let read = syncer.service().store().read().unwrap();
    assert!(read.scan_invalidated().unwrap());
    assert!(matches!(
        read.rescan_state().unwrap(),
        RescanState::Failed { .. }
    ));
}

#[test]
fn conflict_is_retried_and_reconciled_instead_of_ending_sync() {
    use ergo_wallet_service::{
        ChainClientError, ChainSnapshot, SubmitRequest, SubmitResponse, UtxoLookup,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ConflictOnce {
        inner: Arc<FakeChain>,
        block_calls: AtomicUsize,
    }

    impl ChainClient for ConflictOnce {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            self.inner.committed_tip()
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            self.inner.snapshot()
        }

        fn blocks_since(
            &self,
            request: ergo_wallet_service::BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            if self.block_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(ChainClientError::Conflict);
            }
            self.inner.blocks_since(request)
        }

        fn lookup_utxo(
            &self,
            box_id: [u8; 32],
            tip: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            self.inner.lookup_utxo(box_id, tip)
        }

        fn submit(&self, request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            self.inner.submit(request)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let inner = FakeChain::new(CommittedTip::new(1, [1; 32]));
    let chain = Arc::new(ConflictOnce {
        inner: inner.clone(),
        block_calls: AtomicUsize::new(0),
    });
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer(chain.clone(), store, 1);
    assert!(syncer.sync_once().unwrap().completed);
    assert_eq!(chain.block_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn gap_and_duplicate_pages_fail_closed_and_record_failed_state() {
    for blocks in [vec![block(2)], vec![block(1), block(1)]] {
        let dir = tempfile::tempdir().unwrap();
        let tip = CommittedTip::new(2, [2; 32]);
        let chain = FakeChain::with_responses(
            tip.clone(),
            [BlocksSinceResponse::Forward(
                ergo_wallet_service::ForwardBlocksSince { tip, blocks },
            )],
        );
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let syncer = build_syncer(chain.clone(), store, 4);
        assert!(matches!(syncer.sync_once(), Err(SyncError::Protocol(_))));
        assert!(matches!(
            syncer
                .service()
                .store()
                .read()
                .unwrap()
                .rescan_state()
                .unwrap(),
            RescanState::Failed { .. }
        ));
    }
}

#[test]
fn post_commit_fault_is_terminal_then_resumes_from_the_durable_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(2, [2; 32]));
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer(chain.clone(), store, 1);
    syncer.inject_next_commit_failure();
    assert!(matches!(syncer.sync_once(), Err(SyncError::Protocol(_))));
    assert_eq!(
        syncer
            .service()
            .store()
            .read()
            .unwrap()
            .scan_cursor()
            .unwrap()
            .unwrap()
            .height,
        1
    );
    assert!(matches!(
        syncer
            .service()
            .store()
            .read()
            .unwrap()
            .rescan_state()
            .unwrap(),
        RescanState::Failed { .. }
    ));
    assert!(syncer.sync_once().unwrap().completed);
    assert_eq!(chain.requests(), vec![(0, 1), (1, 1)]);
}

/// A wallet at height H must reject a page whose first block is H+1 with a
/// parent that is not the wallet's cursor id, and must not apply any of it.
#[test]
fn parent_mismatch_on_the_first_page_block_is_a_terminal_protocol_error() {
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(3, [3; 32]);
    let mut page = block(2);
    page.parent_id = [0xEE; 32];
    let chain = FakeChain::with_responses(
        tip.clone(),
        [BlocksSinceResponse::Forward(
            ergo_wallet_service::ForwardBlocksSince {
                tip,
                blocks: vec![page, block(3)],
            },
        )],
    );
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    write
        .apply_rescan_block(
            1,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &RescanBlock {
                block_id: [1; 32],
                txs: Vec::new(),
            },
            None,
        )
        .unwrap();
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 16);
    let error = syncer.sync_once().unwrap_err();
    assert!(matches!(error, SyncError::Protocol(_)), "{error}");
    assert!(
        error.to_string().contains("parent mismatch"),
        "error should name the violated invariant: {error}"
    );
    let read = syncer.service().store().read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, 1);
    assert!(matches!(
        read.rescan_state().unwrap(),
        RescanState::Failed { .. }
    ));
}

/// More ancestor responses in one pass than the removed 8-response rebuild cap:
/// each rewind is followed by forward progress, so the sync must keep going
/// and still reach the tip.
#[test]
fn many_progressing_reorgs_in_one_pass_are_not_terminal() {
    const REORGS: u32 = 14;
    const CURSOR: u32 = 40;
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(100, [100; 32]);
    let mut responses = Vec::new();
    for index in 1..=REORGS {
        let ancestor = CURSOR - index;
        responses.push(BlocksSinceResponse::Ancestor(
            ergo_wallet_service::AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: ChainCursor {
                    height: ancestor,
                    header_id: [ancestor as u8; 32],
                },
            },
        ));
        responses.push(BlocksSinceResponse::Forward(
            ergo_wallet_service::ForwardBlocksSince {
                tip: tip.clone(),
                blocks: ((ancestor + 1)..=CURSOR).map(block).collect(),
            },
        ));
    }
    let chain = FakeChain::with_responses(tip.clone(), responses);
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    for height in 1..=CURSOR {
        write
            .apply_rescan_block(
                height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                },
                None,
            )
            .unwrap();
    }
    write.finish_rescan(0).unwrap();
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 1024);
    let report = syncer.sync_once().unwrap();
    assert!(report.completed, "{report:?}");
    assert_eq!(report.wallet_height, 100);
    assert!(
        chain.requests().len() >= REORGS as usize * 2,
        "every reorg should be followed by a forward request"
    );
    let read = syncer.service().store().read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, 100);
    assert!(!read.scan_invalidated().unwrap());
}

/// An ancestor that does not rewind the wallet is a protocol violation, and a
/// second reorg deeper than retained history (after the one full rebuild that
/// can recover) is terminal.
#[test]
fn non_decreasing_and_repeated_deeper_than_history_rewinds_are_terminal() {
    let dir = tempfile::tempdir().unwrap();
    // The node tip is ahead of the wallet, so the loop actually asks for a page
    // and sees the ancestor response.
    let tip = CommittedTip::new(4, [4; 32]);
    let chain = FakeChain::with_responses(
        tip.clone(),
        [BlocksSinceResponse::Ancestor(
            ergo_wallet_service::AncestorBlocksSince {
                tip: tip.clone(),
                ancestor: ChainCursor {
                    height: 4,
                    header_id: [4; 32],
                },
            },
        )],
    );
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    for height in 1..=3u32 {
        write
            .apply_rescan_block(
                height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                },
                None,
            )
            .unwrap();
    }
    write.finish_rescan(0).unwrap();
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 16);
    let error = syncer.sync_once().unwrap_err();
    assert!(matches!(error, SyncError::Protocol(_)), "{error}");
    assert!(
        error.to_string().contains("ahead of the wallet cursor"),
        "{error}"
    );

    // Deeper than retained history, twice. The genesis sentinel is the one
    // ancestor a rebuilt wallet can always rewind to, so a node that keeps
    // asking for a *different* height-0 identity can never converge: the first
    // answer triggers the single full rebuild, the second is terminal.
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(3, [3; 32]);
    let unusable = BlocksSinceResponse::Ancestor(ergo_wallet_service::AncestorBlocksSince {
        tip: tip.clone(),
        ancestor: ChainCursor {
            height: 0,
            header_id: [7; 32],
        },
    });
    let chain = FakeChain::with_responses(tip, [unusable.clone(), unusable]);
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let syncer = build_syncer(chain.clone(), store, 16);
    let error = syncer.sync_once().unwrap_err();
    assert!(matches!(error, SyncError::Protocol(_)), "{error}");
    assert!(
        error.to_string().contains("deeper than retained history"),
        "{error}"
    );
    assert!(matches!(
        syncer
            .service()
            .store()
            .read()
            .unwrap()
            .rescan_state()
            .unwrap(),
        RescanState::Failed { .. }
    ));
}

/// A node that answers "rewind to 3" forever makes no forward progress at all.
/// That is not a reorg, it is a non-converging node, and the only progress
/// guard is what stops it.
#[test]
fn rewinds_that_never_apply_a_block_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let tip = CommittedTip::new(5, [5; 32]);
    let responses = (0..200).map(|_| {
        BlocksSinceResponse::Ancestor(ergo_wallet_service::AncestorBlocksSince {
            tip: tip.clone(),
            ancestor: ChainCursor {
                height: 3,
                header_id: [3; 32],
            },
        })
    });
    let chain = FakeChain::with_responses(tip.clone(), responses);
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let mut write = store.begin_write().unwrap();
    write.prepare_rescan(0, true).unwrap();
    for height in 1..=4u32 {
        write
            .apply_rescan_block(
                height,
                &BTreeSet::new(),
                &BTreeMap::new(),
                &RescanBlock {
                    block_id: [height as u8; 32],
                    txs: Vec::new(),
                },
                None,
            )
            .unwrap();
    }
    write.finish_rescan(0).unwrap();
    write.commit().unwrap();
    let syncer = build_syncer(chain.clone(), store, 1024);
    let error = syncer.sync_once().unwrap_err();
    assert!(matches!(error, SyncError::Protocol(_)), "{error}");
    assert!(
        error.to_string().contains("without applying a block"),
        "{error}"
    );
    assert!(chain.requests().len() > 8, "must not stop at the old cap");
}

/// The sync loop publishes every tip it observes so a local read never has to
/// probe the node.
#[test]
fn sync_publishes_the_node_tip_for_local_reads() {
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(1, [1; 32]));
    let store = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let port: Arc<dyn ChainClient> = chain.clone();
    let tip = Arc::new(CachedNodeTip::new(port.clone()));
    let service = Arc::new(WalletService::new(store, port));
    let syncer = StandaloneSyncer::new(service, config(4, 4), tip.clone());
    assert!(syncer.sync_once().unwrap().completed);
    assert_eq!(tip.cached().map(|tip| tip.height), Some(1));
}

/// A caught-up daemon must not write `running` on every idle tick. The pass
/// publishes `running` only once it knows there is work, so an idle tick costs
/// the single `idle` write and nothing else — previously the unconditional
/// `running` publish made it two writes per `sync_interval`, forever, and a
/// reader could catch the store mid-tick reporting `syncing` for a wallet that
/// was already at the tip.
#[test]
fn a_caught_up_pass_writes_no_running_state() {
    const TIP: u32 = 2;
    let dir = tempfile::tempdir().unwrap();
    let chain = FakeChain::new(CommittedTip::new(TIP, [TIP as u8; 32]));
    let redb = Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
    let store: Arc<dyn WalletStore> = redb.clone();
    let spy = WriteSpy::new(store.clone());
    let port: Arc<dyn ChainClient> = chain.clone();
    let tip = Arc::new(CachedNodeTip::new(port.clone()));
    let service = Arc::new(WalletService::new(spy.clone(), port));
    let syncer = StandaloneSyncer::new(service, config(4, 4), tip);

    // The first pass has real work, so it publishes `running` — once, and only
    // because there is something to do. Genesis→tip over two blocks is six
    // writes: prepare_rescan, `running`, one per applied block, finish_rescan,
    // and `idle`. Drop the `running` publish and this is five.
    assert!(syncer.sync_once().unwrap().completed);
    assert_eq!(
        spy.writes(),
        6,
        "a working pass publishes `running` exactly once"
    );
    assert_eq!(chain.requests(), vec![(0, 3)]);
    let requests_before = chain.requests().len();

    // The next passes are idle: no work, so no `running` publish. Each costs the
    // single `idle` write that clears any stale running/failed state, and the
    // cost must not grow with the number of blocks or the number of ticks.
    for tick in 0..3 {
        let before = spy.writes();
        let report = syncer.sync_once().unwrap();
        assert!(report.completed, "tick {tick}");
        assert_eq!(report.blocks_processed, 0, "tick {tick}");
        assert_eq!(
            spy.writes() - before,
            1,
            "an idle tick writes exactly the `idle` state, nothing else (tick {tick})"
        );
    }
    assert_eq!(
        chain.requests().len(),
        requests_before,
        "an idle pass must not ask the node for anything"
    );

    let read = store.read().unwrap();
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, TIP);
    assert!(
        matches!(read.rescan_state().unwrap(), RescanState::Idle),
        "an idle pass still ends on `idle`, so a stale `running` cannot stick"
    );
}

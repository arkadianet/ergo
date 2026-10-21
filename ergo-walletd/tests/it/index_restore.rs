//! Where the wallet starts (issue #665): a new wallet at the tip, a restore
//! from the node's address index, and a key added to a wallet that already
//! has history. Each index-assisted result is compared with what a plain scan
//! of the same chain produces for the same keys.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use ergo_wallet_protocol::scala::admin_advanced::DeriveKeyRequest;
use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::address_index::{reward_script, SEED_MARGIN};
use ergo_wallet_service::{
    ChainClient, RescanState, Scan, ScanningPredicate, WalletInteraction, WalletStore,
};

use crate::sim_chain::{p2pk, Keys, Rig, SimChain, TxSpec};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn pay(to: &[u8], value: u64) -> TxSpec {
    TxSpec {
        inputs: Vec::new(),
        outputs: vec![(to.to_vec(), value)],
    }
}

/// A chain of 45 blocks with history for the wallet of [`PHRASE`]:
///
/// - external key 0 is paid at 5 and spends that box at 12, paying itself
///   change and key 3;
/// - key 3 is paid at 9 and spends that box at 27 to a stranger, keeping
///   change;
/// - key 1 earns a mining reward at 13 (still immature at the tip);
/// - key 25, beyond the gap limit of anything used, is paid at 26;
/// - key 0 is paid again at 40, inside the margin the index leaves to block
///   following.
///
/// Keys 2 and 4..24 are never used. With `account_one`, the first address of
/// account 1 also has history (paid at 6 and 14, the first box spent at 20),
/// which only `deriveKey` of that path would ever find.
fn busy_chain(keys: &Keys, account_one: bool) -> Arc<SimChain> {
    let chain = SimChain::new();
    let k = |index| p2pk(&keys.external(index));
    let stranger = p2pk(&Keys::from_phrase(OTHER).external(0));
    chain.push_empty(4);
    let a = chain.push_block(vec![TxSpec {
        inputs: Vec::new(),
        outputs: vec![(k(0), 1_000_000), (stranger.clone(), 5)],
    }]);
    let mut one = None;
    if account_one {
        one = Some(chain.push_block(vec![pay(&p2pk(&keys.account(1, 0)), 250_000)]));
    } else {
        chain.push_empty(1);
    }
    chain.push_empty(2);
    let b = chain.push_block(vec![pay(&k(3), 500_000)]);
    chain.push_empty(2);
    chain.push_block(vec![TxSpec {
        inputs: vec![a[0][0]],
        outputs: vec![(k(0), 600_000), (k(3), 400_000)],
    }]);
    chain.push_block(vec![pay(&reward_script(&keys.external(1)), 3_000)]);
    if account_one {
        chain.push_block(vec![pay(&p2pk(&keys.account(1, 0)), 40_000)]);
    } else {
        chain.push_empty(1);
    }
    chain.push_empty(5);
    if let Some(one) = &one {
        chain.push_block(vec![TxSpec {
            inputs: vec![one[0][0]],
            outputs: vec![
                (stranger.clone(), 200_000),
                (p2pk(&keys.account(1, 0)), 50_000),
            ],
        }]);
    } else {
        chain.push_empty(1);
    }
    chain.push_empty(5);
    chain.push_block(vec![pay(&k(25), 9_000)]);
    chain.push_block(vec![TxSpec {
        inputs: vec![b[0][0]],
        outputs: vec![(stranger, 400_000), (k(3), 100_000)],
    }]);
    chain.push_empty(12);
    chain.push_block(vec![pay(&k(0), 77_000)]);
    chain.push_empty(5);
    assert_eq!(chain.height(), 45);
    chain
}

fn path(account: u32, index: u32) -> String {
    format!("m/44'/429'/{account}'/0/{index}")
}

fn derive(path: String, fresh: bool) -> DeriveKeyRequest {
    DeriveKeyRequest {
        derivation_path: path,
        fresh,
    }
}

/// The wallet of [`PHRASE`] as a plain block scan sees it with keys 0..=3 and
/// optionally account 1 tracked: no index, every block read from genesis.
async fn scanned_baseline(account_one: bool) -> (crate::sim_chain::Summary, Rig) {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, account_one);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain);
    rig.restore_and_unlock(PHRASE).await;
    for index in 1..=3 {
        rig.host
            .derive_key(derive(path(0, index), true))
            .await
            .unwrap();
    }
    if account_one {
        rig.host.derive_key(derive(path(1, 0), true)).await.unwrap();
    }
    rig.sync();
    (rig.summary(), rig)
}

// ----- a new wallet starts at the tip -----

#[tokio::test]
async fn init_starts_at_the_tip_and_the_first_pass_reads_nothing_below_it() {
    let chain = SimChain::new();
    chain.push_empty(40);
    let rig = Rig::new(chain.clone());
    rig.host
        .init("test".to_string(), String::new(), 12)
        .await
        .unwrap();
    let tip = chain.tip();
    assert_eq!(rig.cursor(), Some((40, Some(tip.header_id))));
    assert!(!rig.invalidated());

    rig.host.unlock("test".to_string()).await.unwrap();
    assert_eq!(rig.cursor(), Some((40, Some(tip.header_id))));
    assert!(!rig.invalidated());
    let keys = rig.summary().keys;
    assert_eq!(keys.len(), 2);

    let report = rig.sync();
    assert_eq!(report.blocks_processed, 0);
    assert!(
        chain.blocks_since_log.lock().unwrap().is_empty(),
        "no block may be requested below the tip a new wallet started at: {:?}",
        chain.blocks_since_log.lock().unwrap()
    );
    assert_eq!(rig.read().rescan_state().unwrap(), RescanState::Idle);

    // Blocks after the start are followed from the start.
    let child = keys[1].1;
    chain.push_block(vec![pay(&p2pk(&child), 700)]);
    rig.sync();
    assert_eq!(rig.summary().confirmed, 700);
    assert_eq!(chain.blocks_since_log.lock().unwrap()[0].0, 40);
}

#[tokio::test]
async fn init_on_an_empty_chain_has_nothing_to_start_at() {
    // Genesis has no tip to anchor to: the wallet replays from the start, as
    // it did before, and the seed is still created.
    let rig = Rig::new(SimChain::new());
    rig.host
        .init("test".to_string(), String::new(), 12)
        .await
        .unwrap();
    assert_eq!(rig.cursor(), None);
    rig.host.unlock("test".to_string()).await.unwrap();
    assert!(rig.invalidated());
}

#[tokio::test(flavor = "multi_thread")]
async fn init_during_keyless_passes_is_not_a_sync_failure() {
    let chain = SimChain::new();
    chain.push_empty(30);
    let rig = Rig::new(chain.clone());
    let host = rig.host.clone();
    let syncer = rig.syncer.clone();
    let worker = std::thread::spawn(move || {
        let mut outcomes = Vec::new();
        for _ in 0..400 {
            outcomes.push(host.sync_once(&syncer));
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        outcomes
    });
    rig.host
        .init("test".to_string(), String::new(), 12)
        .await
        .unwrap();
    rig.host.unlock("test".to_string()).await.unwrap();
    let outcomes = worker.join().unwrap();
    assert!(
        outcomes.iter().all(|outcome| outcome.is_ok()),
        "a keyless pass must not fail when init lands: {:?}",
        outcomes.iter().find(|outcome| outcome.is_err())
    );
    let state = rig.read().rescan_state().unwrap();
    assert!(!matches!(state, RescanState::Failed { .. }), "{state:?}");
    assert_eq!(rig.cursor().map(|cursor| cursor.0), Some(30));
}

#[tokio::test]
async fn a_daemon_with_no_wallet_makes_no_block_requests() {
    let chain = SimChain::new();
    chain.push_empty(25);
    let rig = Rig::new(chain.clone());
    for _ in 0..5 {
        assert!(rig.host.sync_once(&rig.syncer).unwrap().is_none());
    }
    assert!(!rig.syncer.has_tracking().unwrap());
    assert_eq!(chain.calls.load(Ordering::SeqCst), 0);
    assert_eq!(rig.cursor(), None);
}

#[tokio::test]
async fn a_new_wallet_does_not_assume_a_later_key_is_fresh() {
    let chain = SimChain::new();
    chain.push_empty(12);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain);
    rig.host
        .init("test".to_string(), String::new(), 12)
        .await
        .unwrap();
    rig.host.unlock("test".to_string()).await.unwrap();
    assert!(!rig.invalidated());
    // Anyone could have used this seed elsewhere since: with no index to ask
    // and no declaration, the safe default stands.
    rig.host
        .derive_key(derive(path(1, 0), false))
        .await
        .unwrap();
    assert!(rig.invalidated());
}

// ----- restore -----

#[tokio::test]
async fn restore_without_an_index_rebuilds_from_zero() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    assert!(rig.invalidated());
    let report = rig.sync();
    assert_eq!(report.wallet_height, 45);
    assert!(!rig.invalidated());
    assert_eq!(chain.blocks_since_log.lock().unwrap()[0].0, 0);
    assert!(chain.block_at_log.lock().unwrap().is_empty());
    // Only the two default keys are known without an index: key 0's history.
    assert_eq!(rig.summary().keys.len(), 2);
    assert_eq!(rig.summary().confirmed, 600_000 + 77_000);
}

#[tokio::test]
async fn restore_with_an_index_matches_a_full_scan_baseline() {
    let (baseline, base_rig) = scanned_baseline(false).await;
    assert_eq!(baseline.keys.len(), 5, "master and external keys 0 to 3");
    assert!(baseline.immature > 0 && baseline.confirmed > 0);
    drop(base_rig);

    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    // Discovery found the used keys up to 3 through the index, and not 25.
    assert_eq!(rig.summary().keys.len(), 5);
    let report = rig.sync();
    assert_eq!(report.wallet_height, 45);
    assert!(!rig.invalidated());
    assert_eq!(rig.read().rescan_state().unwrap(), RescanState::Idle);
    assert_eq!(rig.summary(), baseline);

    // It read the blocks the index named plus the margin, not the chain.
    let safe = 45 - SEED_MARGIN;
    let log = chain.blocks_since_log.lock().unwrap().clone();
    assert!(
        log.iter().all(|(height, _)| *height >= safe),
        "block following must start at the seeded cursor, not at genesis: {log:?}"
    );
    let mut fetched = chain.block_at_log.lock().unwrap().clone();
    fetched.sort_unstable();
    fetched.dedup();
    assert_eq!(fetched, vec![5, 9, 12, 13, 27, safe]);
}

#[tokio::test]
async fn an_index_that_lags_leaves_the_rest_to_block_following() {
    let (baseline, _rig) = scanned_baseline(false).await;
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    // Indexed to 35: safe is 19, so the spend at 27 is read by the scan.
    chain.index_lag.store(10, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    assert_eq!(rig.summary(), baseline);
    assert!(chain
        .blocks_since_log
        .lock()
        .unwrap()
        .iter()
        .all(|(height, _)| *height >= 19));
}

#[tokio::test]
async fn an_index_that_disagrees_with_the_chain_is_not_trusted() {
    let (baseline, _rig) = scanned_baseline(false).await;
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    chain.index_lies.store(true, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    assert_eq!(chain.blocks_since_log.lock().unwrap()[0].0, 0);
    assert_eq!(rig.summary(), baseline);
    assert!(!rig.invalidated());
}

#[tokio::test]
async fn registered_scans_keep_the_wallet_on_the_block_scan() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    let scan = Scan {
        scan_id: 11,
        scan_name: "rule".to_string(),
        tracking_rule: ScanningPredicate::ContainsAsset {
            asset_id: [0xAB; 32],
        },
        wallet_interaction: WalletInteraction::Shared,
        remove_offchain: true,
    };
    let mut write = rig.store.begin_write().unwrap();
    write
        .put_scan(11, serde_json::to_vec(&scan).unwrap(), 11)
        .unwrap();
    write.commit().unwrap();
    rig.sync();
    assert_eq!(
        chain.blocks_since_log.lock().unwrap()[0].0,
        0,
        "a scan rule is something the index knows nothing about"
    );
    assert!(chain.block_at_log.lock().unwrap().is_empty());
}

// ----- a key added to a wallet with history -----

#[tokio::test]
async fn a_key_the_index_has_never_seen_is_added_without_a_rescan() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    let before = rig.summary();
    let log = chain.blocks_since_log.lock().unwrap().len();
    let fetched = chain.block_at_log.lock().unwrap().len();
    let history_calls = chain.history_calls.load(Ordering::SeqCst);

    rig.host
        .derive_key(derive(path(2, 0), false))
        .await
        .unwrap();

    assert!(!rig.invalidated(), "the other keys must stay usable");
    assert_eq!(rig.cursor().map(|cursor| cursor.0), Some(45));
    assert_eq!(rig.read().rescan_state().unwrap(), RescanState::Idle);
    let after = rig.summary();
    assert_eq!(after.boxes, before.boxes);
    assert_eq!(after.txs, before.txs);
    assert_eq!(after.keys.len(), before.keys.len() + 1);
    assert_eq!(chain.blocks_since_log.lock().unwrap().len(), log);
    assert_eq!(chain.block_at_log.lock().unwrap().len(), fetched);
    assert_eq!(chain.history_calls.load(Ordering::SeqCst), history_calls);

    // And it is tracked from here on.
    chain.push_block(vec![pay(&p2pk(&keys.account(2, 0)), 31_000)]);
    rig.sync();
    assert_eq!(rig.summary().confirmed, before.confirmed + 31_000);
}

#[tokio::test]
async fn a_key_with_history_is_backfilled_from_the_index_instead_of_rescanning() {
    let (baseline, _rig) = scanned_baseline(true).await;
    assert!(baseline.confirmed > 0);

    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, true);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    let before = rig.summary();
    let log = chain.blocks_since_log.lock().unwrap().len();

    rig.host
        .derive_key(derive(path(1, 0), false))
        .await
        .unwrap();

    assert!(!rig.invalidated());
    assert_eq!(
        chain.blocks_since_log.lock().unwrap().len(),
        log,
        "no rescan"
    );
    let after = rig.summary();
    assert!(after.confirmed > before.confirmed);
    // The old keys' boxes are exactly as they were.
    for entry in &before.boxes {
        assert!(after.boxes.contains(entry), "{entry} changed");
    }
    // And the whole wallet is what a scan with the key tracked produces,
    // including the transaction that touches only the new key.
    let mut expected = baseline;
    let mut got = after;
    // The baseline derived the keys in a different order; the paths decide.
    expected.keys.sort();
    got.keys.sort();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn a_backfill_reaches_blocks_the_index_has_not_indexed_yet() {
    let (baseline, _rig) = scanned_baseline(true).await;
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, true);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    // The index now trails the wallet by 30 blocks.
    chain.index_lag.store(30, Ordering::SeqCst);
    rig.host
        .derive_key(derive(path(1, 0), false))
        .await
        .unwrap();
    assert!(!rig.invalidated());
    let mut got = rig.summary();
    let mut expected = baseline;
    got.keys.sort();
    expected.keys.sort();
    assert_eq!(got, expected);
}

#[tokio::test]
async fn an_index_that_disagrees_falls_back_to_the_rescan_on_derive() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, true);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    chain.index_lies.store(true, Ordering::SeqCst);
    rig.host
        .derive_key(derive(path(1, 0), false))
        .await
        .unwrap();
    assert!(
        rig.invalidated(),
        "the safe default applies when the index cannot be trusted"
    );
    assert_eq!(rig.cursor(), Some((0, None)));
    rig.sync();
    assert!(!rig.invalidated());
    assert!(rig.summary().confirmed > 0);
}

#[tokio::test]
async fn without_an_index_a_derived_key_still_invalidates_by_default() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    assert!(!rig.invalidated());

    rig.host
        .derive_key(derive(path(2, 0), false))
        .await
        .unwrap();
    assert!(rig.invalidated());
    assert_eq!(rig.cursor(), Some((0, None)));

    // The daemon repairs it by replaying, as it always did.
    rig.sync();
    assert!(!rig.invalidated());
    assert_eq!(rig.cursor().map(|cursor| cursor.0), Some(45));
}

#[tokio::test]
async fn without_an_index_a_key_declared_fresh_is_tracked_with_no_rescan() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    let before = rig.summary();
    let log = chain.blocks_since_log.lock().unwrap().len();

    rig.host.derive_key(derive(path(2, 0), true)).await.unwrap();
    assert!(!rig.invalidated());
    assert_eq!(rig.cursor().map(|cursor| cursor.0), Some(45));
    assert_eq!(rig.summary().boxes, before.boxes);

    // deriveNextKey takes the same declaration.
    rig.host.derive_next_key_declaring(true).await.unwrap();
    assert!(!rig.invalidated());
    assert_eq!(chain.blocks_since_log.lock().unwrap().len(), log);

    chain.push_block(vec![pay(&p2pk(&keys.account(2, 0)), 12_000)]);
    rig.sync();
    assert_eq!(rig.summary().confirmed, before.confirmed + 12_000);
}

#[tokio::test]
async fn derive_next_key_consults_the_index_too() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    rig.sync();
    let log = chain.blocks_since_log.lock().unwrap().len();
    // Key 4 of the external chain was never used.
    let next = rig.host.derive_next_key().await.unwrap();
    assert!(
        next.derivation_path.ends_with("/4"),
        "{}",
        next.derivation_path
    );
    assert!(!rig.invalidated());
    assert_eq!(chain.blocks_since_log.lock().unwrap().len(), log);
}

// ----- the explicit partial restart -----

#[tokio::test]
async fn a_declared_start_restarts_an_invalidated_scan_where_the_caller_says() {
    let keys = Keys::from_phrase(PHRASE);
    let chain = busy_chain(&keys, false);
    chain.indexed.store(false, Ordering::SeqCst);
    let rig = Rig::new(chain.clone());
    rig.restore_and_unlock(PHRASE).await;
    assert!(rig.invalidated());

    assert!(matches!(
        rig.host.declare_history_start(0).await,
        Err(WalletAdminError::BadRequest(_))
    ));
    assert!(matches!(
        rig.host.declare_history_start(500).await,
        Err(WalletAdminError::BadRequest(_))
    ));

    // The caller states nothing happened before 38; key 0's payment at 40
    // is all there is to find.
    rig.host.declare_history_start(38).await.unwrap();
    assert!(!rig.invalidated());
    let chain_id = chain.block_at(37, chain.tip()).unwrap().block_id;
    assert_eq!(rig.cursor(), Some((37, Some(chain_id))));
    let coverage = rig.read().discovery_coverage().unwrap().unwrap();
    assert_eq!(coverage.anchor_height, 37);
    assert!(!coverage.history_complete);

    rig.sync();
    assert_eq!(rig.summary().confirmed, 77_000);
    assert_eq!(chain.blocks_since_log.lock().unwrap()[0].0, 37);
    assert!(!rig.invalidated());

    // A valid scan has no use for the declaration.
    assert!(matches!(
        rig.host.declare_history_start(10).await,
        Err(WalletAdminError::BadRequest(_))
    ));
}

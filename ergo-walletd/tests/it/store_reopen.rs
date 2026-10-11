use std::sync::Arc;

use ergo_wallet_service::CommittedTip;
use ergo_wallet_service::{RedbWalletStore, WalletService, WalletStore};
use ergo_walletd::config::Network;
use ergo_walletd::descriptor;
use ergo_walletd::sync::{StandaloneSyncer, SyncConfig};
use ergo_walletd::tip::CachedNodeTip;

use crate::support::FakeChain;

const KEY: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

#[test]
fn standalone_store_reopens_with_keys_cursor_and_completed_sync() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.redb");
    let chain = FakeChain::new(CommittedTip::new(2, [2; 32]));
    {
        let store = Arc::new(RedbWalletStore::open_standalone(&path).unwrap());
        let entries = descriptor::parse_text(
            &format!("keys=[{{path=\"m/44'/429'/0'/0/0\",public_key=\"{KEY}\"}}]"),
            Network::Mainnet,
        )
        .unwrap();
        assert_eq!(
            descriptor::import(store.as_ref(), &entries).unwrap().added,
            1
        );
        let port: Arc<dyn ergo_wallet_service::ChainClient> = chain.clone();
        let service = Arc::new(WalletService::new(store.clone(), port.clone()));
        let syncer = StandaloneSyncer::new(
            service,
            SyncConfig {
                batch: 1,
                ..SyncConfig::default()
            },
            Arc::new(CachedNodeTip::new(port)),
        );
        let first = syncer.sync_once().unwrap();
        assert!(!first.completed);
        let second = syncer.sync_once().unwrap();
        assert!(second.completed);
        assert_eq!(chain.requests(), vec![(0, 1), (1, 1)]);
    }
    let reopened = RedbWalletStore::open_standalone(&path).unwrap();
    let read = reopened.read().unwrap();
    assert_eq!(read.tracked_addresses_with_meta().unwrap().len(), 1);
    assert_eq!(read.scan_cursor().unwrap().unwrap().height, 2);
    assert!(!read.scan_invalidated().unwrap());
}

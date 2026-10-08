//! Chain capabilities for the daemon's seed lifecycle host.
//!
//! Lifecycle and key derivation need a wallet cursor and the authenticated
//! node tip. Spending needs a richer committed view than the Phase 2 HTTP
//! snapshot supplies: adopted validation settings, complete re-emission
//! rules, and a coherent mempool publication are still missing. This adapter
//! exposes only the lifecycle capabilities and refuses replay/signing.

use std::sync::Arc;

use ergo_wallet_service::engine::{ChainAccessError, WalletChainAccess};
use ergo_wallet_service::wallet::scan::{RescanBlock, RescanReadError};
use ergo_wallet_service::{ChainClient, ChainClientError, CommittedTip, WalletStore};

use crate::tip::PROBE_TIMEOUT;

/// Local cursor reads plus bounded, authenticated committed-tip reads.
///
/// The host calls this synchronous adapter from a blocking worker. Status
/// reads are entirely local; a key's `added_at_height` uses a fresh node
/// request rather than the display-only cached tip.
pub struct LifecycleChainAccess {
    store: Arc<dyn WalletStore>,
    chain: Arc<dyn ChainClient>,
}

impl LifecycleChainAccess {
    pub fn new(store: Arc<dyn WalletStore>, chain: Arc<dyn ChainClient>) -> Self {
        Self { store, chain }
    }

    fn node_tip(&self) -> Result<CommittedTip, ChainAccessError> {
        self.chain
            .committed_tip_within(PROBE_TIMEOUT)
            .map_err(map_chain_error)
    }
}

fn map_chain_error(error: ChainClientError) -> ChainAccessError {
    match error {
        ChainClientError::Unsupported => ChainAccessError::Unsupported,
        ChainClientError::StaleTip { expected, actual } => {
            ChainAccessError::StaleTip { expected, actual }
        }
        error => ChainAccessError::State(error.to_string()),
    }
}

impl WalletChainAccess for LifecycleChainAccess {
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        self.store
            .read()
            .and_then(|read| read.scan_cursor())
            .map(|cursor| cursor.map_or(0, |cursor| cursor.height))
            .map_err(|error| ChainAccessError::State(error.to_string()))
    }

    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        self.node_tip().map(|tip| tip.height)
    }

    fn is_pruned(&self) -> bool {
        // The current chain contract does not disclose pruning policy.
        // Restored wallets must remain incomplete until replay proves that
        // the available history covers them; unknown is never unpruned.
        true
    }

    fn read_block_at(&self, height: u32) -> Result<Option<RescanBlock>, RescanReadError> {
        Err(RescanReadError::Chain {
            height,
            source: ChainClientError::UnsupportedHistory {
                reason: "daemon lifecycle host does not expose engine block replay".into(),
            },
        })
    }

    fn read_block_at_supported(&self) -> Result<bool, RescanReadError> {
        // Override the genesis-only default: an empty chain does not make
        // this adapter an engine replay implementation.
        Ok(false)
    }

    fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
        self.node_tip().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ergo_wallet_service::{
        BlocksSinceRequest, BlocksSinceResponse, ChainSnapshot, RedbWalletStore, SubmitRequest,
        SubmitResponse, UtxoLookup,
    };

    use super::*;

    struct TipClient {
        bounded_calls: AtomicUsize,
        error: Option<ChainClientError>,
    }

    impl ChainClient for TipClient {
        fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
            panic!("lifecycle reads must use the bounded tip method")
        }

        fn committed_tip_within(
            &self,
            timeout: Duration,
        ) -> Result<CommittedTip, ChainClientError> {
            assert_eq!(timeout, PROBE_TIMEOUT);
            self.bounded_calls.fetch_add(1, Ordering::SeqCst);
            match &self.error {
                Some(error) => Err(error.clone()),
                None => Ok(CommittedTip::new(8, [0x88; 32])),
            }
        }

        fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
            panic!("lifecycle adapter must not synthesize a signing snapshot")
        }

        fn blocks_since(
            &self,
            _: BlocksSinceRequest,
        ) -> Result<BlocksSinceResponse, ChainClientError> {
            panic!("engine replay is unsupported")
        }

        fn lookup_utxo(
            &self,
            _: [u8; 32],
            _: CommittedTip,
        ) -> Result<UtxoLookup, ChainClientError> {
            panic!("spending is unsupported")
        }

        fn submit(&self, _: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
            panic!("spending is unsupported")
        }
    }

    #[test]
    fn local_cursor_reads_work_without_node_access_and_tip_reads_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let chain = Arc::new(TipClient {
            bounded_calls: AtomicUsize::new(0),
            error: None,
        });
        let access = LifecycleChainAccess::new(store.clone(), chain.clone());
        assert_eq!(access.wallet_scan_height().unwrap(), 0);
        let mut write = store.begin_write().unwrap();
        write.set_scan_cursor(4, Some(&[0x44; 32])).unwrap();
        write.commit().unwrap();
        assert_eq!(access.wallet_scan_height().unwrap(), 4);
        assert_eq!(chain.bounded_calls.load(Ordering::SeqCst), 0);
        assert_eq!(access.tip_height().unwrap(), 8);
        assert_eq!(
            access.committed_tip().unwrap(),
            Some(CommittedTip::new(8, [0x88; 32]))
        );
        assert_eq!(chain.bounded_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn unknown_pruning_and_missing_spend_capabilities_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let chain = Arc::new(TipClient {
            bounded_calls: AtomicUsize::new(0),
            error: None,
        });
        let access = LifecycleChainAccess::new(store, chain.clone());
        assert!(access.is_pruned());
        assert!(!access.read_block_at_supported().unwrap());
        assert!(matches!(
            access.read_block_at(1),
            Err(RescanReadError::Chain {
                height: 1,
                source: ChainClientError::UnsupportedHistory { .. }
            })
        ));
        assert!(matches!(
            access.signing_view(),
            Err(ChainAccessError::Unsupported)
        ));
        assert!(matches!(
            access.lookup_utxo(&[1; 32]),
            Err(ChainAccessError::Unsupported)
        ));
        assert_eq!(chain.bounded_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tip_failures_do_not_fall_back_to_wallet_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(RedbWalletStore::open_standalone(dir.path().join("wallet.redb")).unwrap());
        let chain = Arc::new(TipClient {
            bounded_calls: AtomicUsize::new(0),
            error: Some(ChainClientError::Timeout("node tip unavailable".into())),
        });
        let access = LifecycleChainAccess::new(store, chain);
        assert!(matches!(
            access.tip_height(),
            Err(ChainAccessError::State(detail)) if detail.contains("node tip unavailable")
        ));
    }
}

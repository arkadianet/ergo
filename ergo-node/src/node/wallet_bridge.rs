//! Node-side adapters for the standalone wallet daemon.
//!
//! The node hosts no wallet. These are the seams the daemon's chain API and
//! private mining queue are served through:
//!
//! - [`ChainStateAccessorImpl`]: `WalletChainAccess` over `ergo-state`'s
//!   committed chain;
//! - [`ChainSnapshot`]: the committed `SigningView`;
//! - the in-process chain client and API adapter (`chain_client`);
//! - [`StoredPrivateQueueBridge`]: the private mining queue API.

use std::sync::Arc;

use ergo_wallet_protocol::WalletAdminError;
use ergo_wallet_service::chain::CommittedTip;
use ergo_wallet_service::engine::{ChainAccessError, SigningView, WalletChainAccess};
use ergo_wallet_service::wallet::scan::{RescanBlock, RescanReadError};

pub mod chain_client;
pub mod chain_snapshot;
pub use chain_client::{
    ChainClientAdapter, InProcessChainClient, IntoChainSubmitter, NodeChainClient,
    WalletChainAdapter,
};
use chain_snapshot::chain_state_read_failed;
pub use chain_snapshot::ChainSnapshot;

mod stored_queue_api;
pub use stored_queue_api::StoredPrivateQueueBridge;

/// [`WalletChainAccess`] over the node's committed chain, for the chain API
/// the wallet daemon reads. It holds no wallet: `wallet_scan_height` is an
/// error.
///
/// - `tip_height` / `committed_tip`: the committed tip.
/// - `is_pruned`: static from config.
/// - `read_block_at`: delegates to `block_txs_for_wallet_at_height`.
/// - `signing_view` / `build_signing_context` / `build_signing_params` /
///   `lookup_utxo`: use the `ChainStoreReader` to read from committed state
///   without acquiring the action-loop's mutable `StateStore`.
pub struct ChainStateAccessorImpl {
    private_queue: Option<Arc<ergo_mining::private_queue::PrivateTransactionQueue>>,
    /// Lock-free reader for chain state (headers, UTXO, active params).
    reader: ergo_state::reader::ChainStoreReader,
    is_pruned: bool,
    /// EIP-27 re-emission rules (mainnet) or `None` (testnet). See
    /// [`WalletChainAccess::reemission_rules`].
    reemission: Option<ergo_validation::ReemissionRuleInputs>,
}

impl ChainStateAccessorImpl {
    pub fn chain_only(
        reader: ergo_state::reader::ChainStoreReader,
        is_pruned: bool,
        reemission: Option<ergo_validation::ReemissionRuleInputs>,
    ) -> Self {
        Self {
            private_queue: None,
            reader,
            is_pruned,
            reemission,
        }
    }

    pub fn with_private_queue(
        mut self,
        queue: Option<Arc<ergo_mining::private_queue::PrivateTransactionQueue>>,
    ) -> Self {
        self.private_queue = queue;
        self
    }

    /// The concrete committed [`ChainSnapshot`] behind
    /// [`WalletChainAccess::signing_view`].
    pub fn chain_snapshot(&self) -> Result<ChainSnapshot, ChainAccessError> {
        let committed = self
            .reader
            .committed_snapshot()
            .map_err(chain_state_read_failed)?
            .ok_or(ChainAccessError::NoCommittedState)?;
        ChainSnapshot::from_committed(committed, self.reemission.as_ref())
            .map_err(chain_state_read_failed)
    }
}

impl WalletChainAccess for ChainStateAccessorImpl {
    fn reserved_wallet_inputs(
        &self,
    ) -> Result<std::collections::BTreeSet<[u8; 32]>, WalletAdminError> {
        Ok(self
            .private_queue
            .as_ref()
            .map(|queue| queue.reserved_inputs())
            .unwrap_or_default())
    }
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
        Err(ChainAccessError::State(
            "the node hosts no wallet; its chain accessor has no wallet scan height".into(),
        ))
    }

    fn tip_height(&self) -> Result<u32, ChainAccessError> {
        Ok(self
            .reader
            .committed_tip()
            .map_err(|error| ChainAccessError::State(error.to_string()))?
            .map(|(height, _)| height)
            .unwrap_or(0))
    }

    fn is_pruned(&self) -> bool {
        self.is_pruned
    }

    fn reemission_rules(&self) -> Option<&ergo_validation::ReemissionRuleInputs> {
        self.reemission.as_ref()
    }

    fn read_block_at(&self, height: u32) -> Result<Option<RescanBlock>, RescanReadError> {
        use ergo_wallet_service::wallet::scan::RescanTx;
        use ergo_wallet_service::wallet::OwnedBlockOutput;

        let (block_id, owned) = match self.reader.wallet_block_txs_at_height(height)? {
            Some(pair) => pair,
            None => return Ok(None),
        };

        let txs = owned
            .into_iter()
            .map(|d| RescanTx {
                tx_id: d.tx_id,
                inputs: d.inputs,
                outputs: d
                    .outputs
                    .into_iter()
                    .map(|o| OwnedBlockOutput {
                        box_id: o.box_id,
                        output_index: o.output_index,
                        ergo_tree_bytes: o.ergo_tree_bytes,
                        value: o.value,
                        assets: o.assets,
                        miner_reward_pubkey: o.miner_reward_pubkey,
                        // Carried for the rescan scan-matcher + ScanTrackedBox.
                        box_bytes: o.box_bytes,
                    })
                    .collect(),
            })
            .collect();

        Ok(Some(RescanBlock { block_id, txs }))
    }

    fn signing_view(&self) -> Result<Box<dyn SigningView>, ChainAccessError> {
        Ok(Box::new(self.chain_snapshot()?))
    }

    fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
        Ok(self
            .reader
            .committed_tip()
            .map_err(chain_state_read_failed)?
            .map(|(height, header_id)| CommittedTip { height, header_id }))
    }

    fn build_signing_context(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainStateContext, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.state_context().clone())
    }

    fn build_signing_params(
        &self,
    ) -> Result<ergo_wallet::tx_context::BlockchainParameters, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.signing_params().clone())
    }

    fn build_protocol_params(&self) -> Result<ergo_validation::ProtocolParams, ChainAccessError> {
        self.chain_snapshot()
            .map(|snapshot| snapshot.protocol_params().clone())
    }

    fn lookup_utxo(
        &self,
        box_id: &[u8; 32],
    ) -> Result<Option<ergo_ser::ergo_box::ErgoBox>, ChainAccessError> {
        let Some(bytes) = self
            .reader
            .lookup_box(box_id)
            .map_err(chain_state_read_failed)?
        else {
            return Ok(None);
        };
        chain_snapshot::decode_utxo_box(box_id, &bytes)
            .map(Some)
            .map_err(chain_state_read_failed)
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;

    #[test]
    fn rescan_preflight_no_committed_chain_returns_genesis_tip() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let chain = ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db),
            false,
            None,
        );
        assert_eq!(chain.tip_height().unwrap(), 0);
    }

    #[test]
    fn chain_tip_no_committed_chain_returns_zero() {
        use tracing_subscriber::prelude::*;

        struct WarnCounter(Arc<std::sync::atomic::AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCounter {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if *event.metadata().level() == tracing::Level::WARN {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let chain = ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db),
            false,
            None,
        );
        let warnings = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(WarnCounter(warnings.clone()));
        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(chain.tip_height().unwrap(), 0);
        });
        assert_eq!(warnings.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn production_chain_access_propagates_database_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(redb::Database::create(dir.path().join("state.redb")).unwrap());
        let state_meta: redb::TableDefinition<u64, u64> =
            redb::TableDefinition::new("chain_state_meta");
        let chain_index: redb::TableDefinition<u64, u64> =
            redb::TableDefinition::new("chain_index");
        {
            let write = db.begin_write().unwrap();
            write.open_table(state_meta).unwrap().insert(1, 1).unwrap();
            write.open_table(chain_index).unwrap().insert(1, 1).unwrap();
            write.commit().unwrap();
        }
        let chain = ChainStateAccessorImpl::chain_only(
            ergo_state::reader::ChainStoreReader::new_from_db(db),
            false,
            None,
        );
        assert!(chain.tip_height().is_err());
        assert!(chain.read_block_at(1).is_err());
    }
}

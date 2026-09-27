//! Chain-access seam for the wallet engine: the signing/rescan contract.
//!
//! [`WalletChainAccess`] is everything the engine reads from the chain to
//! build, sign and self-verify a transaction, and to replay blocks during a
//! `/wallet/rescan`: the wallet scan height, the committed tip, block replay,
//! a committed [`SigningView`] (headers, signing context, cost and structural
//! parameters, EIP-27 rules, UTXO lookup) and the staleness check that ties a
//! signed transaction to the tip it was signed against.
//!
//! It is deliberately **separate** from [`crate::chain::ChainClient`]:
//! `ChainClient` is the daemon's versioned HTTP chain contract (snapshot,
//! blocks-since, UTXO lookup and submit as wire-shaped values), while
//! `WalletChainAccess` hands the engine fully decoded consensus inputs. The
//! embedded node implements `WalletChainAccess` over its committed
//! `ergo-state` store and builds its in-process `ChainClient` on top of the
//! same accessor; a daemon implementation can later be layered on
//! `ChainClient` without changing the engine. The two are intentionally not
//! merged yet.

use ergo_ser::ergo_box::ErgoBox;
use ergo_ser::header::Header;
use ergo_validation::{ActiveProtocolParameters, ProtocolParams, ReemissionRuleInputs};
use ergo_wallet::tx_context::{BlockchainParameters, BlockchainStateContext};
use ergo_wallet_protocol::WalletAdminError;
use thiserror::Error;

use crate::chain::CommittedTip;
use crate::wallet::scan::{RescanBlock, RescanReadError};
use crate::wallet::WalletStoreError;

/// Failure of a [`WalletChainAccess`] / [`SigningView`] read.
///
/// `State` carries a storage failure whose message the implementation
/// renders verbatim (the embedded node passes the exact text its storage
/// layer produced), so every error string the engine surfaces is the one the
/// implementation chose.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainAccessError {
    /// Storage failure; the message is rendered as-is.
    #[error("{0}")]
    State(String),
    #[error("no committed chain state")]
    NoCommittedState,
    #[error("chain snapshot is unsupported by this accessor")]
    Unsupported,
    #[error(
        "committed chain tip moved from ({expected_height}, {expected_id}) to ({actual_height}, {actual_id})",
        expected_height = expected.height,
        expected_id = expected.header_id_hex(),
        actual_height = actual.height,
        actual_id = actual.header_id_hex()
    )]
    StaleTip {
        expected: CommittedTip,
        actual: CommittedTip,
    },
}

/// Map a chain-access failure to the admin error surfaced to wallet callers:
/// a stale tip is the typed `409 stale_chain_tip`, everything else internal.
pub fn map_chain_error(error: ChainAccessError) -> WalletAdminError {
    let detail = error.to_string();
    match error {
        ChainAccessError::StaleTip { .. } => WalletAdminError::StaleChainTip(detail),
        _ => WalletAdminError::Internal(detail),
    }
}

/// One committed chain view used to sign and self-verify a transaction:
/// every read is answered from the same committed tip, so a signature and
/// its verification can never mix two tips.
pub trait SigningView: Send + Sync {
    /// The committed full-block tip this view was taken at.
    fn tip(&self) -> CommittedTip;
    /// The last (at most ten) applied headers, newest first.
    fn headers(&self) -> &[Header];
    /// Header ids matching [`Self::headers`], in the same order.
    fn header_ids(&self) -> &[[u8; 32]];
    /// Blockchain state context for sigma reduction (last headers,
    /// candidate pre-header, previous state digest).
    fn state_context(&self) -> &BlockchainStateContext;
    /// Active protocol parameters at the tip.
    fn active_params(&self) -> &ActiveProtocolParameters;
    /// Per-block cost parameters derived from the active parameters.
    fn signing_params(&self) -> &BlockchainParameters;
    /// Structural protocol parameters (min value per byte, box and
    /// collection caps) for pre-submit structural validation.
    fn protocol_params(&self) -> &ProtocolParams;
    /// EIP-27 re-emission rules for this network, `None` off EIP-27 nets.
    fn reemission_rules(&self) -> Option<&ReemissionRuleInputs>;
    /// Look up an unspent box at this view's tip. `Ok(None)` means absent.
    fn lookup_utxo(&self, box_id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError>;
}

/// Read-only chain access for the wallet engine. The engine uses it for:
/// (a) `walletHeight` in `/wallet/status`, (b) the pruning check in
/// `/wallet/restore`, (c) block fetch during `/wallet/rescan`, and (d) the
/// signing view + UTXO lookup for the send routes.
pub trait WalletChainAccess: Send + Sync {
    /// Current wallet scan height — populates `walletHeight`.
    fn wallet_scan_height(&self) -> Result<u32, ChainAccessError>;
    /// Best full-block tip height. Used as the rescan upper bound.
    fn tip_height(&self) -> Result<u32, ChainAccessError>;
    /// True if the node is configured with `blocks_to_keep != -1`.
    /// `/wallet/restore` refuses on pruned nodes per Scala parity.
    fn is_pruned(&self) -> bool;
    /// EIP-27 re-emission rule inputs for this network (`None` off EIP-27
    /// nets, e.g. testnet). The burn-aware builder and the self-verify
    /// EIP-27 gate read it here so a built spend can never violate
    /// consensus. Default `None` (test stubs / non-EIP-27 backends).
    fn reemission_rules(&self) -> Option<&ReemissionRuleInputs> {
        None
    }
    /// Fetch the block at `height` for rescan replay. `Ok(None)` means the
    /// requested block is unavailable (pruned or not yet downloaded).
    fn read_block_at(&self, height: u32) -> Result<Option<RescanBlock>, RescanReadError>;
    /// True when `read_block_at` can return real block data. Distinct from
    /// `is_pruned()` (which gates `/wallet/restore`) — this gates
    /// `/wallet/rescan`. When false, rescan is refused before touching any
    /// wallet state, preventing the destructive clear-then-skip sequence.
    /// Default impl treats a genesis-only tip as supported; otherwise it
    /// probes height one. Overrides may avoid the probe for efficiency.
    fn read_block_at_supported(&self) -> Result<bool, RescanReadError> {
        match self.tip_height() {
            Ok(0) => Ok(true),
            Ok(_) => Ok(self.read_block_at(1)?.is_some()),
            Err(error) => Err(RescanReadError::Storage {
                height: 0,
                source: WalletStoreError::decode(error.to_string()),
            }),
        }
    }

    /// A committed [`SigningView`] at the current tip.
    fn signing_view(&self) -> Result<Box<dyn SigningView>, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }

    /// The committed full-block tip, `None` before any block is committed.
    fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }

    /// Fail with [`ChainAccessError::StaleTip`] when the committed tip moved
    /// away from the tip `view` was taken at.
    fn ensure_view_current(&self, view: &dyn SigningView) -> Result<(), ChainAccessError> {
        let actual = self
            .committed_tip()?
            .ok_or(ChainAccessError::NoCommittedState)?;
        let expected = view.tip();
        if actual == expected {
            return Ok(());
        }
        Err(ChainAccessError::StaleTip { expected, actual })
    }

    /// Build the blockchain state context needed for signing: last ≤10
    /// applied headers + candidate pre-header + previous state digest.
    fn build_signing_context(&self) -> Result<BlockchainStateContext, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }

    /// Build per-block cost parameters from the active protocol parameters
    /// at the tip.
    fn build_signing_params(&self) -> Result<BlockchainParameters, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }

    /// Structural protocol parameters at the tip (min-value-per-byte,
    /// box/collection caps) for pre-submit structural validation. Mirrors
    /// the consensus validator's `ProtocolParams`; the wallet runs
    /// `ergo_validation::validate_structural` against these so it never
    /// submits a tx the node would reject (e.g. a dust output).
    fn build_protocol_params(&self) -> Result<ProtocolParams, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }

    /// Look up a full `ErgoBox` from the UTXO set by its 32-byte box ID.
    /// Returns `None` if the box is not present (spent or unknown).
    fn lookup_utxo(&self, _box_id: &[u8; 32]) -> Result<Option<ErgoBox>, ChainAccessError> {
        Err(ChainAccessError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TipOnly(Option<CommittedTip>);

    impl WalletChainAccess for TipOnly {
        fn wallet_scan_height(&self) -> Result<u32, ChainAccessError> {
            Ok(0)
        }

        fn tip_height(&self) -> Result<u32, ChainAccessError> {
            Err(ChainAccessError::State("tip read failed".to_string()))
        }

        fn is_pruned(&self) -> bool {
            false
        }

        fn read_block_at(&self, _height: u32) -> Result<Option<RescanBlock>, RescanReadError> {
            Ok(None)
        }

        fn committed_tip(&self) -> Result<Option<CommittedTip>, ChainAccessError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn map_chain_error_keeps_stale_tip_typed_and_messages_verbatim() {
        let stale = ChainAccessError::StaleTip {
            expected: CommittedTip::new(1, [0xaa; 32]),
            actual: CommittedTip::new(2, [0xbb; 32]),
        };
        let expected_detail = format!(
            "committed chain tip moved from (1, {}) to (2, {})",
            "aa".repeat(32),
            "bb".repeat(32)
        );
        assert!(matches!(
            map_chain_error(stale),
            WalletAdminError::StaleChainTip(detail) if detail == expected_detail
        ));
        assert!(matches!(
            map_chain_error(ChainAccessError::State("disk on fire".to_string())),
            WalletAdminError::Internal(detail) if detail == "disk on fire"
        ));
    }

    #[test]
    fn read_block_at_supported_reports_tip_failures_as_storage() {
        let error = TipOnly(None).read_block_at_supported().unwrap_err();
        assert!(matches!(
            error,
            RescanReadError::Storage { height: 0, ref source }
                if source.to_string().contains("tip read failed")
        ));
    }
}

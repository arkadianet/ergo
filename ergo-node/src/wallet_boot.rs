//! Node-runtime wallet session lifecycle: session ids, the wallet tasks
//! tracked per session (the writer task and its rescan jobs), and routing a
//! node shutdown, by session id, to that session's rescan coordinator.
//!
//! The rescan fence flags themselves are per-wallet state owned by
//! [`RescanCoordinator`]; this module only remembers which coordinator
//! belongs to which session so a node's shutdown cancels its own wallet's
//! rescan, even when another session has begun in the same process since
//! (parallel test nodes, an embedder running two nodes). The
//! unlock/hydrate/persist path lives in the wallet service
//! ([`ergo_wallet_service::engine::WalletBootService`]).

use std::sync::{Arc, Mutex};

use ergo_wallet_service::engine::RescanCoordinator;
use tokio::task::{JoinError, JoinHandle};

struct WalletTaskSession {
    closing: bool,
    handles: Vec<JoinHandle<()>>,
    /// The session's rescan coordinator; a shutdown of this session cancels
    /// its rescan through it.
    rescan: Option<Arc<RescanCoordinator>>,
}

struct WalletTaskState {
    sessions: Vec<(u64, WalletTaskSession)>,
}

static WALLET_TASKS: Mutex<WalletTaskState> = Mutex::new(WalletTaskState {
    sessions: Vec::new(),
});
static WALLET_SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn wallet_tasks() -> std::sync::MutexGuard<'static, WalletTaskState> {
    WALLET_TASKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Begin a new wallet session owned by `rescan`: allocate the session id,
/// register the session, and clear the shutdown/cancel requests a previous
/// session may have left on the coordinator.
pub(crate) fn begin_wallet_session(rescan: Arc<RescanCoordinator>) -> u64 {
    let mut tasks = wallet_tasks();
    let session_id = WALLET_SESSION_ID
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        .wrapping_add(1);
    match task_session_index(&tasks, session_id) {
        Some(index) => tasks.sessions[index].1.rescan = Some(rescan.clone()),
        None => tasks.sessions.push((
            session_id,
            WalletTaskSession {
                closing: false,
                handles: Vec::new(),
                rescan: Some(rescan.clone()),
            },
        )),
    }
    rescan.begin_session();
    session_id
}

pub(crate) fn wallet_session_id() -> u64 {
    WALLET_SESSION_ID.load(std::sync::atomic::Ordering::SeqCst)
}

fn task_session_index(state: &WalletTaskState, session_id: u64) -> Option<usize> {
    state.sessions.iter().position(|(id, _)| *id == session_id)
}

pub(crate) async fn track_wallet_task(
    session_id: u64,
    handle: JoinHandle<()>,
) -> Result<(), JoinError> {
    let late_handle = {
        let mut tasks = wallet_tasks();
        let index = match task_session_index(&tasks, session_id) {
            Some(index) => index,
            None => {
                tasks.sessions.push((
                    session_id,
                    WalletTaskSession {
                        closing: false,
                        handles: Vec::new(),
                        rescan: None,
                    },
                ));
                tasks.sessions.len() - 1
            }
        };
        let session = &mut tasks.sessions[index].1;
        if session.closing {
            Some(handle)
        } else {
            session.handles.push(handle);
            None
        }
    };
    match late_handle {
        Some(handle) => match handle.await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => {
                tracing::info!("wallet task cancelled during shutdown");
                Ok(())
            }
            Err(error) => Err(error),
        },
        None => Ok(()),
    }
}

async fn join_wallet_handles(handles: Vec<JoinHandle<()>>, first_error: &mut Option<JoinError>) {
    for handle in handles {
        if let Err(error) = handle.await {
            if error.is_cancelled() {
                tracing::info!("wallet task cancelled during shutdown");
            } else if first_error.is_none() {
                *first_error = Some(error);
            } else {
                tracing::error!(%error, "wallet task join failed");
            }
        }
    }
}

pub(crate) async fn await_wallet_tasks(session_id: u64) -> Result<(), JoinError> {
    {
        let mut tasks = wallet_tasks();
        let Some(index) = task_session_index(&tasks, session_id) else {
            return Ok(());
        };
        tasks.sessions[index].1.closing = true;
    }
    let mut first_error = None;
    loop {
        let handles = {
            let mut tasks = wallet_tasks();
            let Some(index) = task_session_index(&tasks, session_id) else {
                return first_error.map_or(Ok(()), Err);
            };
            std::mem::take(&mut tasks.sessions[index].1.handles)
        };
        join_wallet_handles(handles, &mut first_error).await;
        let empty = wallet_tasks()
            .sessions
            .iter()
            .find(|(id, _)| *id == session_id)
            .map(|(_, session)| session.handles.is_empty())
            .unwrap_or(true);
        if empty {
            return first_error.map_or(Ok(()), Err);
        }
    }
}

/// Node shutdown for `session_id`: ask that session's rescan coordinator to
/// refuse new rescans, cancel the running one, and fail closed if a rescan
/// task is active. Routed by id rather than to the latest session, so an
/// older node still cancels its own rescan after a newer session began; an
/// unknown id, or a session without a wallet, is a no-op.
pub(crate) fn request_rescan_shutdown_for(session_id: u64) {
    let tasks = wallet_tasks();
    if let Some(rescan) = task_session_index(&tasks, session_id)
        .and_then(|index| tasks.sessions[index].1.rescan.as_ref())
    {
        rescan.request_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_wallet_service::wallet::{RedbWalletStore, WalletStore};

    #[test]
    fn unlock_at_height_500_tracks_the_next_block_without_invalidation() {
        let dir = tempfile::tempdir().unwrap();
        let chain = ergo_state::store::StateStore::open(&dir.path().join("state.redb")).unwrap();
        let db = chain.db_arc();
        let meta = ergo_state::chain::ChainStateMeta {
            best_header_id: [5; 32],
            best_header_height: 500,
            best_header_score: vec![],
            best_full_block_id: [5; 32],
            best_full_block_height: 500,
            header_availability: ergo_state::chain::HeaderAvailability::Dense,
        };
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "chain_state_meta",
        ))
        .unwrap()
        .insert("chain_state", meta.serialize().as_slice())
        .unwrap();
        txn.open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
            .unwrap()
            .insert(500, [5u8; 32].as_slice())
            .unwrap();
        txn.commit().unwrap();
        let store = RedbWalletStore::new(db.clone());
        let mut storage = ergo_wallet::storage::SecretStorage::open(dir.path().join("wallet"));
        storage
            .init(ergo_wallet::mnemonic::MnemonicStrength::Words12, "pw", "")
            .unwrap();
        let mut state = ergo_wallet_service::state::WalletState::empty(false);
        ergo_wallet_service::engine::WalletBootService::unlock_and_sync(
            &mut storage,
            &mut state,
            &store,
            ergo_ser::address::NetworkPrefix::Mainnet,
            "pw",
        )
        .unwrap();
        assert_eq!(
            store.read().unwrap().scan_cursor().unwrap().unwrap().height,
            500
        );
        let txn = db.begin_write().unwrap();
        txn.open_table(redb::TableDefinition::<u64, &[u8]>::new("chain_index"))
            .unwrap()
            .insert(501, [6u8; 32].as_slice())
            .unwrap();
        txn.commit().unwrap();
        let mut write = store.begin_write().unwrap();
        write
            .apply_block(
                501,
                &[6; 32],
                &ergo_wallet_service::wallet::WalletApplyPayload {
                    tracked_p2pk_trees: state.tracked_p2pk_trees().clone(),
                    cached_pubkeys: state.cached_pubkeys().clone(),
                    block_txs_owned: vec![],
                    scan_matches: vec![],
                    has_registered_scans: false,
                    allow_non_contiguous_wallet: false,
                },
            )
            .unwrap();
        write.commit().unwrap();
        let read = store.read().unwrap();
        assert!(!read.scan_invalidated().unwrap());
        assert_eq!(
            read.scan_cursor().unwrap().unwrap(),
            ergo_wallet_service::wallet::WalletScanCursor {
                height: 501,
                header_id: Some([6; 32]),
            }
        );
    }

    #[tokio::test]
    async fn wallet_task_join_errors_are_reported() {
        let task = tokio::spawn(async {
            panic!("injected wallet task panic");
        });
        let mut first_error = None;
        join_wallet_handles(vec![task], &mut first_error).await;
        assert!(first_error.is_some());
    }
}

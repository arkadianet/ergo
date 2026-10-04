//! Single-writer dispatch for acknowledged operator peer actions.

use std::time::{Duration, Instant};

use ergo_api::operator_control::{OperatorControlError, PeerControl, PeerControlResult};

use super::peer_actions::{cleanup_disconnected_peer, flush_actions};
use super::NodeState;

pub(super) fn dispatch(state: &mut NodeState, request: crate::runtime_control::PeerControlRequest) {
    if request.reply.is_closed() || Instant::now() >= request.deadline {
        return;
    }
    let now = Instant::now();
    let result = match request.command {
        PeerControl::Ban { ip, duration_secs } => state
            .peer_manager
            .operator_ban(ip, Duration::from_secs(duration_secs), now)
            .map_err(|error| OperatorControlError::Storage(error.to_string()))
            .map(|()| {
                let ip = ergo_p2p::peer::canonical_ip(ip);
                let peers: Vec<_> = state
                    .registry
                    .peers
                    .keys()
                    .filter(|addr| ergo_p2p::peer::canonical_ip(addr.ip()) == ip)
                    .copied()
                    .collect();
                for peer in peers {
                    disconnect(state, peer, now);
                }
                PeerControlResult::default()
            }),
        PeerControl::Unban { ip } => state
            .peer_manager
            .operator_unban(ip)
            .map_err(|error| OperatorControlError::Storage(error.to_string()))
            .map(|()| PeerControlResult::default()),
        PeerControl::Disconnect { addr } => Ok(PeerControlResult {
            session_closed: Some(disconnect(state, addr, now)),
        }),
        PeerControl::Remove { addr } => state
            .peer_manager
            .operator_remove(addr)
            .map_err(|error| OperatorControlError::Storage(error.to_string()))
            .map(|()| PeerControlResult {
                session_closed: Some(disconnect(state, addr, now)),
            }),
    };
    if result.is_ok() {
        super::snapshot_emit::publish_snapshot(state, now);
    }
    let _ = request.reply.send(result);
}

fn disconnect(state: &mut NodeState, addr: std::net::SocketAddr, now: Instant) -> bool {
    let closed = state.registry.peers.contains_key(&addr);
    let actions = state.executor.on_peer_disconnected(
        &addr,
        &mut state.coordinator,
        &state.peer_manager,
        now,
    );
    state.peer_manager.disconnect(&addr);
    cleanup_disconnected_peer(state, &addr);
    flush_actions(state, actions);
    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disconnect_reports_whether_a_session_was_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::node::tests::make_state(&dir.path().join("state.redb"));
        let peer = "203.0.113.8:9030".parse().unwrap();
        let now = Instant::now();
        assert!(!disconnect(&mut state, peer, now));
        let (outbound_tx, _rx) = crate::peer_loop::outbound::channel(1);
        state.registry.peers.insert(
            peer,
            crate::node::PeerRuntime {
                sync_version: ergo_p2p::peer::SyncVersion::V2,
                outbound_tx,
            },
        );
        assert!(disconnect(&mut state, peer, now));
        assert!(!disconnect(&mut state, peer, now));
    }
}

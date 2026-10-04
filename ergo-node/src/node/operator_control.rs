//! Single-writer dispatch for acknowledged operator peer actions.

use std::time::{Duration, Instant};

use ergo_api::operator_control::{OperatorControlError, PeerControl};

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
            }),
        PeerControl::Unban { ip } => state
            .peer_manager
            .operator_unban(ip)
            .map_err(|error| OperatorControlError::Storage(error.to_string())),
        PeerControl::Disconnect { addr } => {
            disconnect(state, addr, now);
            Ok(())
        }
        PeerControl::Remove { addr } => state
            .peer_manager
            .operator_remove(addr)
            .map_err(|error| OperatorControlError::Storage(error.to_string()))
            .map(|()| disconnect(state, addr, now)),
    };
    if result.is_ok() {
        super::snapshot_emit::publish_snapshot(state, now);
    }
    let _ = request.reply.send(result);
}

fn disconnect(state: &mut NodeState, addr: std::net::SocketAddr, now: Instant) {
    let actions = state.executor.on_peer_disconnected(
        &addr,
        &mut state.coordinator,
        &state.peer_manager,
        now,
    );
    state.peer_manager.disconnect(&addr);
    cleanup_disconnected_peer(state, &addr);
    flush_actions(state, actions);
}

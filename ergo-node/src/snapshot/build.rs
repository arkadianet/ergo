//! Assemble a [`NodeSnapshot`](super::NodeSnapshot) from [`SnapshotParts`](super::SnapshotParts):
//! sync-state classification, per-peer DTO projection, and the
//! health-status overlay (rejecting / wedged / sync-derived).

use std::time::Instant;

use ergo_api::types::{
    hex32, ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiPeer,
    ApiStatus, ApiSyncStatus, ApiTip, HealthStatus, SyncStateLabel,
};
use ergo_p2p::peer::{ConnectionState, Direction, PeerInfo};
use ergo_ser::difficulty::decode_compact_bits;

use super::{NodeSnapshot, SnapshotParts};

/// Time threshold for `/health`'s stall detection. If the best full
/// block height has not advanced within this window AND we are not at
/// tip, `/health` returns 503.
const STALL_THRESHOLD_SECS: u64 = 120;

/// Tolerance for declaring "at tip": full-block tip within this many
/// blocks of the best known header tip.
const AT_TIP_GAP: u32 = 2;

pub(super) fn build_snapshot(
    p: SnapshotParts<'_>,
    info: ApiInfo,
    last_progress_age_ms: u64,
) -> NodeSnapshot {
    let gap = p
        .best_header_height
        .saturating_sub(p.best_full_block_height);
    let sync_state = classify(
        p.peer_count,
        p.headers_chain_synced,
        gap,
        last_progress_age_ms,
    );

    // n_bits is resolved by the publisher (carry-forward on read failure),
    // so `unwrap_or(0)` here only hits the pre-first-publish path.
    let best_header_n_bits = p.best_header_n_bits.unwrap_or(0);
    let best_full_block_n_bits = p.best_full_block_n_bits.unwrap_or(0);
    let best_header = ApiHeaderRef {
        height: p.best_header_height,
        header_id: hex32(&p.best_header_id),
        parent_id: hex32(&p.best_header_parent_id),
        timestamp_unix_ms: p.best_header_timestamp_ms,
        n_bits: best_header_n_bits,
        difficulty: decode_compact_bits(best_header_n_bits).to_string(),
    };
    let best_full_block = ApiFullBlockRef {
        height: p.best_full_block_height,
        header_id: hex32(&p.best_full_block_id),
        parent_id: hex32(&p.best_full_block_parent_id),
        timestamp_unix_ms: p.best_full_block_timestamp_ms,
        state_root_avl: hex::encode(p.state_digest),
        n_bits: best_full_block_n_bits,
        difficulty: decode_compact_bits(best_full_block_n_bits).to_string(),
    };

    // An outstanding block-apply rejection overrides the sync-derived
    // health below (a node refusing blocks its peers accept is not healthy,
    // however it looks on the sync axis).
    let rejecting = p.last_block_apply_error.is_some();
    // Terminal deep-fork wedge: strictly worse than Rejecting (nothing can
    // ever apply again without a resync), so it wins the overlay.
    let wedged = p.sync_wedged.is_some();
    let status = ApiStatus {
        sync_state,
        peer_count: p.peer_count,
        best_header_height: p.best_header_height,
        best_full_block_height: p.best_full_block_height,
        headers_ahead_of_full_blocks: gap,
        mempool_size: p.mempool_size,
        snapshot_age_ms: 0,
        bootstrap: p.bootstrap.clone(),
        last_block_apply_error: p.last_block_apply_error.clone(),
        block_apply_errors_total: p.block_apply_errors_total,
        sync_wedged: p.sync_wedged.clone(),
        shadow: p.shadow.clone(),
        mempool_tx_requested_total: p.mempool_tx_requested_total,
        mempool_peer_tx_admitted_total: p.mempool_peer_tx_admitted_total,
        mempool_peer_tx_rejected_total: p.mempool_peer_tx_rejected_total,
        reorgs_total: p.reorgs.total,
        last_reorg_depth: p.reorgs.reorgs.first().map(|r| r.depth),
        last_reorg_unix_ms: p.reorgs.reorgs.first().map(|r| r.unix_ms),
        // Filled live by SnapshotReadState::status() from ApplyPhaseMetrics.
        apply_in_progress: false,
        last_apply_duration_ms: 0,
        last_applied_height: 0,
        last_apply_age_ms: None,
    };

    let tip = ApiTip {
        best_header: best_header.clone(),
        best_full_block: best_full_block.clone(),
        headers_ahead_of_full_blocks: gap,
    };

    let sync = ApiSyncStatus {
        headers_chain_synced: p.headers_chain_synced,
        best_header_height: p.best_header_height,
        best_full_block_height: p.best_full_block_height,
        gap,
        download_window: p.download_window,
        pending_blocks: p.pending_blocks,
        recovery_done: p.recovery_done,
    };

    let peers = p
        .peers
        .iter()
        .map(|pi| project_peer(pi, p.snapshot_built_at, &p.peer_sync))
        .collect();

    let mempool = ApiMempoolSummary {
        size: p.mempool_size,
        total_bytes: p.mempool_total_bytes,
        capacity_count: p.mempool_capacity_count,
        capacity_bytes: p.mempool_capacity_bytes,
        revalidation_pending: p.mempool_revalidation_pending,
    };

    let health_status = if wedged {
        HealthStatus::Wedged
    } else if rejecting {
        HealthStatus::Rejecting
    } else {
        match sync_state {
            SyncStateLabel::Disconnected => HealthStatus::Disconnected,
            SyncStateLabel::Stalled => HealthStatus::Stalled,
            SyncStateLabel::Syncing | SyncStateLabel::AtTip => HealthStatus::Ok,
        }
    };
    let health = ApiHealth {
        status: health_status,
        behind: gap,
        last_progress_age_ms,
        peer_count: p.peer_count,
    };

    let _ = p.now_unix_ms;
    NodeSnapshot {
        info,
        status,
        tip,
        sync,
        peers,
        mempool,
        mempool_transactions: p.mempool_transactions,
        health,
        produced_at: p.snapshot_built_at,
        best_header_score: p.best_header_score,
        best_full_block_score: p.best_full_block_score,
        genesis_block_id: p.genesis_block_id,
        last_seen_message_unix_ms: p.last_seen_message_unix_ms,
        last_mempool_update_unix_ms: p.last_mempool_update_unix_ms,
        active_params: p.active_params,
        pool_outputs: p.pool_outputs,
        pool_inputs: p.pool_inputs,
        pool_full_txs: p.pool_full_txs,
        peer_sync: p.peer_sync,
        delivery_counts: p.delivery_counts,
        banned_ips: p.banned_ips,
        recent_blocks: p.recent_blocks,
        events: p.events,
        reorgs: p.reorgs,
        max_peer_height: p.max_peer_height,
        mining_enabled: p.mining_enabled,
        snapshot_manifests: p.snapshot_manifests,
    }
}

fn classify(
    peer_count: u32,
    headers_synced: bool,
    gap: u32,
    last_progress_age_ms: u64,
) -> SyncStateLabel {
    if peer_count == 0 {
        return SyncStateLabel::Disconnected;
    }
    let stalled = last_progress_age_ms / 1000 >= STALL_THRESHOLD_SECS && gap > AT_TIP_GAP;
    if stalled {
        return SyncStateLabel::Stalled;
    }
    if headers_synced && gap <= AT_TIP_GAP {
        SyncStateLabel::AtTip
    } else {
        SyncStateLabel::Syncing
    }
}

fn project_peer(
    pi: &PeerInfo,
    now: Instant,
    peer_sync: &std::collections::HashMap<std::net::SocketAddr, super::PeerSyncProjection>,
) -> ApiPeer {
    let addr = pi.addr.to_string();
    let direction = match pi.direction {
        Direction::Inbound => ergo_api::types::ApiPeerDirection::Inbound,
        Direction::Outbound => ergo_api::types::ApiPeerDirection::Outbound,
    };
    let state = match pi.state {
        ConnectionState::Connecting => ergo_api::types::ApiPeerState::Connecting,
        ConnectionState::Handshaking => ergo_api::types::ApiPeerState::Handshaking,
        ConnectionState::Active => ergo_api::types::ApiPeerState::Active,
        ConnectionState::Degraded => ergo_api::types::ApiPeerState::Degraded,
        ConnectionState::Disconnected => ergo_api::types::ApiPeerState::Disconnected,
    };
    let (agent, node_name, version) = match &pi.peer_spec {
        Some(spec) => (
            Some(spec.agent_name.clone()),
            Some(spec.node_name.clone()),
            Some(spec.version.to_string()),
        ),
        None => (None, None, None),
    };
    // Parsed-but-previously-dropped peer identity from the handshake
    // PeerSpec: the advertised REST URL feature and the declared public
    // address. Both are observability/identity only — never fed into sync
    // or scoring. Surfaced on the native peer DTO; the legacy
    // `/peers/connected` Scala-compat surface is intentionally left as-is.
    let (rest_api_url, declared_address) = match &pi.peer_spec {
        Some(spec) => (
            spec.features.iter().find_map(|f| match f {
                ergo_p2p::handshake::PeerFeature::RestApiUrl { url } => Some(url.clone()),
                _ => None,
            }),
            spec.declared_address
                .as_ref()
                .and_then(format_declared_address),
        ),
        None => (None, None),
    };
    let connected_seconds = now.saturating_duration_since(pi.connected_at).as_secs();
    let last_seen_seconds = now.saturating_duration_since(pi.last_seen).as_secs();
    // peer_height comes from the per-peer sync-info projection
    // populated by SyncCoordinator::on_sync_info. V1 SyncInfo
    // carries the height directly; V2 SyncInfo infers it from the
    // newest peer-header that overlaps our best chain. `None` until
    // we've processed a SyncInfo from this peer.
    let peer_height = peer_sync.get(&pi.addr).and_then(|s| s.peer_height);
    ApiPeer {
        addr,
        direction,
        state,
        score: pi.score.raw_score(),
        agent,
        node_name,
        version,
        sync_version: format!("{:?}", pi.sync_version),
        connected_seconds,
        last_seen_seconds,
        // Cumulative post-handshake framed bytes, counted at the per-peer
        // I/O task's transport boundary (ergo-p2p PeerInfo shared counters).
        bytes_in: Some(pi.bytes_in()),
        bytes_out: Some(pi.bytes_out()),
        peer_height,
        rest_api_url,
        declared_address,
    }
}

/// Format a handshake-declared address (`addr` bytes + wire `u32` port) as
/// an `ip:port` string, or `None` when the advertised value is malformed.
/// Handles the two valid Ergo declared-address byte widths — 4 (IPv4) and
/// 16 (IPv6); any other width yields `None` rather than a misparsed address.
///
/// `declared_address` is peer-influenced and untrusted: the wire port is a
/// `u32` (see `handshake.rs`), so a hostile/buggy peer can advertise a value
/// outside the valid `u16` port range (e.g. `65536`). Rather than silently
/// truncate it with `as u16` — which would fabricate a wrong `:0` — an
/// out-of-range port yields `None`: better to omit an untrusted address than
/// to surface one that was never real. `Scala`'s declared address is an
/// `InetSocketAddress`; the in-range case renders the same `host:port` shape.
fn format_declared_address(d: &ergo_p2p::handshake::DeclaredAddress) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let ip: std::net::IpAddr = match d.addr.len() {
        4 => {
            let b: [u8; 4] = d.addr[..4].try_into().expect("len checked == 4");
            std::net::IpAddr::V4(Ipv4Addr::from(b))
        }
        16 => {
            let b: [u8; 16] = d.addr[..16].try_into().expect("len checked == 16");
            std::net::IpAddr::V6(Ipv6Addr::from(b))
        }
        // Non-standard width: omit rather than fabricate a misparsed address.
        _ => return None,
    };
    // Reject (omit) a port outside the valid u16 range instead of truncating.
    let port = u16::try_from(d.port).ok()?;
    Some(std::net::SocketAddr::new(ip, port).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_peer_surfaces_byte_counters() {
        use std::collections::HashMap;
        // The snapshot must surface exactly the counters the per-peer I/O
        // task increments: project_peer reads the same Arc-backed PeerInfo
        // whose byte_counters() handle we bump here.
        let pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        let (cin, cout) = pi.byte_counters();
        cin.fetch_add(42, std::sync::atomic::Ordering::Relaxed);
        cout.fetch_add(7, std::sync::atomic::Ordering::Relaxed);

        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(api.bytes_in, Some(42));
        assert_eq!(api.bytes_out, Some(7));
    }

    /// `ApiPeer` surfaces the parsed-but-previously-dropped peer identity:
    /// the `RestApiUrl` handshake feature → `rest_api_url`, and the
    /// `PeerSpec.declared_address` → `declared_address` (`ip:port`). Both
    /// are `None` when the spec carries neither.
    #[test]
    fn project_peer_surfaces_rest_url_and_declared_address() {
        use ergo_p2p::handshake::{DeclaredAddress, PeerFeature, PeerSpec, Version};
        use std::collections::HashMap;

        let mut pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        pi.peer_spec = Some(PeerSpec {
            agent_name: "ergoref".into(),
            version: Version {
                major: 5,
                minor: 0,
                patch: 0,
            },
            node_name: "node".into(),
            declared_address: Some(DeclaredAddress {
                addr: vec![203, 0, 113, 9],
                port: 9030,
            }),
            features: vec![PeerFeature::RestApiUrl {
                url: "http://203.0.113.9:9053".into(),
            }],
        });

        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(
            api.rest_api_url.as_deref(),
            Some("http://203.0.113.9:9053"),
            "RestApiUrl feature must surface on rest_api_url",
        );
        assert_eq!(
            api.declared_address.as_deref(),
            Some("203.0.113.9:9030"),
            "declared address must surface as ip:port",
        );
    }

    /// With no peer_spec (pre-handshake) both new identity fields are
    /// `None` — the absent case the additive serde-skip relies on.
    #[test]
    fn project_peer_identity_fields_none_without_spec() {
        use std::collections::HashMap;
        let pi = ergo_p2p::peer::PeerInfo::new_outbound(
            "127.0.0.1:9030".parse().unwrap(),
            std::time::Instant::now(),
        );
        let api = project_peer(&pi, std::time::Instant::now(), &HashMap::new());
        assert_eq!(api.rest_api_url, None);
        assert_eq!(api.declared_address, None);
    }

    /// The declared port is a peer-advertised wire `u32`.
    /// An in-range port renders `ip:port`; an out-of-range port (> 65535,
    /// malformed/hostile) yields `None` rather than a silently-truncated
    /// `:0`. Fail-first against the old `as u16` cast, where `65536` wrapped
    /// to `0` and surfaced a fabricated `203.0.113.9:0`.
    #[test]
    fn format_declared_address_handles_port_range() {
        use ergo_p2p::handshake::DeclaredAddress;

        // In-range IPv4 → ip:port.
        let v4 = DeclaredAddress {
            addr: vec![203, 0, 113, 9],
            port: 9030,
        };
        assert_eq!(
            format_declared_address(&v4).as_deref(),
            Some("203.0.113.9:9030"),
        );

        // In-range IPv6 → bracketed [ip]:port (SocketAddr's V6 rendering).
        let v6 = DeclaredAddress {
            addr: vec![0; 16],
            port: 9030,
        };
        assert_eq!(format_declared_address(&v6).as_deref(), Some("[::]:9030"));

        // Max valid u16 port still renders.
        let max = DeclaredAddress {
            addr: vec![203, 0, 113, 9],
            port: 65535,
        };
        assert_eq!(
            format_declared_address(&max).as_deref(),
            Some("203.0.113.9:65535"),
        );

        // Out-of-range port (one past u16::MAX) → None, NOT a truncated `:0`.
        let bad = DeclaredAddress {
            addr: vec![203, 0, 113, 9],
            port: 65536,
        };
        assert_eq!(
            format_declared_address(&bad),
            None,
            "out-of-range declared port must be omitted, not truncated to :0",
        );

        // Non-standard address width also yields None (IPv4/IPv6 only).
        let weird = DeclaredAddress {
            addr: vec![1, 2, 3],
            port: 9030,
        };
        assert_eq!(format_declared_address(&weird), None);
    }

    /// The `/info` u64 difficulty narrowing: the captured Scala mainnet
    /// nBits decodes and fits u64 (oracle value, not self-derived).
    #[test]
    fn difficulty_u64_narrowing_for_scala_mainnet_n_bits() {
        assert_eq!(
            u64::try_from(decode_compact_bits(117_501_863)).unwrap_or(u64::MAX),
            263_500_538_576_896
        );
    }

    /// Difficulty above `u64::MAX` saturates rather than wrapping — the
    /// `/info` u64 is a Scala-surface cap; native `ApiTip` carries the
    /// full-precision String.
    #[test]
    fn difficulty_u64_narrowing_saturates_above_u64() {
        assert_eq!(
            u64::try_from(decode_compact_bits(0x20_ff_ff_ff)).unwrap_or(u64::MAX),
            u64::MAX
        );
    }
}

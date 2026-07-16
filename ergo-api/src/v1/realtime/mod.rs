//! Real-time subscriptions (G5): the `WS /api/v1/ws` surface + the
//! `RealtimeBus` fan-out hub.
//!
//! The single biggest net-new of the v1 API: every Ergo node polls today; this
//! is the push surface. Layering:
//!
//! * [`model`] — channel vocabulary + validation + the canonical event body.
//! * [`bus`] — [`RealtimeBus`], the fine-grained fan-out hub with per-subscriber
//!   bounded queues, the never-block slow-consumer drop policy, the global
//!   `seq`, and the resume window; plus [`ConnLimiter`] for the per-IP /
//!   global socket caps.
//! * [`protocol`] — the WS frame schema + the transport-free [`Session`] state
//!   machine (subscribe / unsubscribe / resume / ping / auth, caps, terminal
//!   channels, reorg-aware event rendering).
//! * [`ws`] — the thin axum [`WebSocketUpgrade`](axum::extract::ws::WebSocketUpgrade)
//!   adapter + the server-seam coarse-ring bridge feeder.
//!
//! **Upstream tap:** the bus is fed by [`ws::spawn_event_bridge`], which bridges
//! the node's existing coarse operator event ring (`GET /api/v1/events`) into
//! the bus `blocks` channel — one push path, no second event source. The
//! fine-grained `address:`/`box:`/`token:`/`tx:` taps live in node internals and
//! are a follow-up; until they land those classes are gated
//! `channel_unavailable`. Webhooks (the durable sibling) are a separate
//! follow-up and are NOT built here.

pub mod bus;
pub mod model;
pub mod protocol;
pub mod ws;

use std::sync::Arc;

pub use bus::{BackfillPage, BusSubscription, ConnGuard, ConnLimiter, RealtimeBus, RealtimeEvent};
pub use model::{parse_channel, ChannelClass, ParsedChannel, RealtimeEventBody};
pub use protocol::{ClientFrame, ServerFrame, Session};
pub use ws::{spawn_event_bridge, spawn_event_bridge_once, ws_handler, DEFAULT_BRIDGE_INTERVAL};

/// The shared realtime handle threaded through [`V1State`](crate::v1::V1State):
/// the fan-out bus plus the connection limiter. Absent (`None`) ⇒ the
/// `/api/v1/ws` route answers `realtime_disabled` (never a bare 404), per the
/// subsystem-off rule.
#[derive(Clone)]
pub struct RealtimeHandle {
    /// The fan-out hub, constructed once and shared like the O4 depth ring.
    pub bus: Arc<RealtimeBus>,
    /// Per-IP + global live-socket caps, checked pre-upgrade.
    pub limiter: Arc<ConnLimiter>,
}

/// Default per-IP socket cap.
pub const MAX_SOCKETS_PER_IP: usize = 16;
/// Default global socket ceiling — a conservative FD-derived bound; the
/// operator can raise it when the node's FD budget allows.
pub const GLOBAL_SOCKET_CEILING: usize = 4096;

impl RealtimeHandle {
    /// A `blocks`-only bus (fed from the coarse-ring bridge) and the default
    /// connection caps.
    pub fn blocks_only() -> Self {
        RealtimeHandle {
            bus: Arc::new(RealtimeBus::blocks_only()),
            limiter: Arc::new(ConnLimiter::new(MAX_SOCKETS_PER_IP, GLOBAL_SOCKET_CEILING)),
        }
    }

    /// A realtime handle with live block, mempool, peers, and per-tx channels.
    pub fn blocks_and_mempool() -> Self {
        RealtimeHandle {
            bus: Arc::new(RealtimeBus::blocks_and_mempool()),
            limiter: Arc::new(ConnLimiter::new(MAX_SOCKETS_PER_IP, GLOBAL_SOCKET_CEILING)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn blocks_and_mempool_handle_marks_mempool_live() {
        let handle = RealtimeHandle::blocks_and_mempool();
        assert!(handle.bus.is_live(ChannelClass::Blocks));
        assert!(handle.bus.is_live(ChannelClass::Mempool));
        assert!(handle.bus.is_live(ChannelClass::Peers));
        assert!(handle.bus.is_live(ChannelClass::Tx));
    }
}

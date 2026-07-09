//! WS frame protocol + the pure per-socket session state machine
//! (`v1-api-design.md` §4.1, fragment §2.1–§2.5).
//!
//! All frames are text JSON, `snake_case`, one object per frame. Client control
//! ops: `subscribe` / `unsubscribe` / `resume` / `ping` / `auth`. Server frames
//! are the `type`-tagged set below. The [`Session`] is deliberately transport-
//! free — it takes parsed control frames and produces server frames, mutating
//! the shared subscription filter the [`RealtimeBus`](super::bus::RealtimeBus)
//! reads — so the whole protocol is unit-testable without a live socket
//! ([`super::ws`] is the thin axum adapter over it).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::v1::error::Reason;
use crate::v1::routes::dto::unix_ms_to_iso;

use super::bus::RealtimeEvent;
use super::model::{parse_channel, ChannelClass};

/// Max subscribed channels per socket (§2.6).
pub const MAX_CHANNELS: usize = 64;
/// Max inbound control-frame size in bytes (§2.6).
pub const MAX_MESSAGE_BYTES: usize = 65_536;
/// Server heartbeat cadence, milliseconds (§2.6).
pub const HEARTBEAT_MS: u64 = 15_000;
/// Control-frame rate-limit window (§2.6).
pub const CONTROL_WINDOW: Duration = Duration::from_secs(10);
/// Max control ops per [`CONTROL_WINDOW`] (§2.6).
pub const MAX_CONTROL_OPS: usize = 20;

/// The server-advertised limits, echoed in the `welcome` frame.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Limits {
    /// Max subscribed channels per socket.
    pub max_channels: usize,
    /// Max inbound control-frame bytes.
    pub max_message_bytes: usize,
    /// Retained resume window (events).
    pub resume_window: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_channels: MAX_CHANNELS,
            max_message_bytes: MAX_MESSAGE_BYTES,
            resume_window: super::bus::RESUME_WINDOW,
        }
    }
}

/// A parsed client control frame (§2.3). Produced by [`parse_client_frame`],
/// which reports `unknown_op` precisely rather than a generic parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    /// Additive subscribe; the server dedupes against the current set.
    Subscribe {
        id: Option<String>,
        channels: Vec<String>,
    },
    /// Remove channels from the current set.
    Unsubscribe {
        id: Option<String>,
        channels: Vec<String>,
    },
    /// Re-attach after reconnect: replay matching events with `seq > since`.
    Resume {
        id: Option<String>,
        since: u64,
        channels: Vec<String>,
    },
    /// App-level liveness (distinct from the WS protocol ping/pong).
    Ping { id: Option<String> },
    /// Reserved for future T1 channels; T0 ignores it.
    Auth { id: Option<String> },
}

/// Why a client frame could not be parsed into a [`ClientFrame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameParseError {
    /// The `op` field named an op the server does not implement.
    UnknownOp,
    /// Malformed JSON, missing `op`, or a required field absent/ill-typed.
    BadRequest(String),
}

/// Parse a raw text frame into a [`ClientFrame`], distinguishing `unknown_op`
/// (a known JSON object with an unrecognized `op`) from a generic bad request.
pub fn parse_client_frame(text: &str) -> Result<ClientFrame, FrameParseError> {
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| FrameParseError::BadRequest(format!("frame is not JSON: {e}")))?;
    let op = v
        .get("op")
        .and_then(|o| o.as_str())
        .ok_or_else(|| FrameParseError::BadRequest("missing `op` field".to_string()))?;
    let id = v.get("id").and_then(|i| i.as_str()).map(str::to_string);
    let channels = || -> Result<Vec<String>, FrameParseError> {
        v.get("channels")
            .and_then(|c| c.as_array())
            .ok_or_else(|| FrameParseError::BadRequest("`channels` must be an array".to_string()))?
            .iter()
            .map(|c| {
                c.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| FrameParseError::BadRequest("channel must be a string".into()))
            })
            .collect()
    };
    match op {
        "subscribe" => Ok(ClientFrame::Subscribe {
            id,
            channels: channels()?,
        }),
        "unsubscribe" => Ok(ClientFrame::Unsubscribe {
            id,
            channels: channels()?,
        }),
        "resume" => {
            let since = v
                .get("since")
                .and_then(|s| s.as_u64())
                .ok_or_else(|| FrameParseError::BadRequest("`since` must be a u64".to_string()))?;
            Ok(ClientFrame::Resume {
                id,
                since,
                channels: channels()?,
            })
        }
        "ping" => Ok(ClientFrame::Ping { id }),
        "auth" => Ok(ClientFrame::Auth { id }),
        _ => Err(FrameParseError::UnknownOp),
    }
}

/// A server → client frame (§2.4). `type`-tagged, snake_case.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    /// Sent once on open.
    Welcome {
        session_id: String,
        latest_seq: u64,
        heartbeat_ms: u64,
        limits: Limits,
    },
    /// Per accepted control op.
    Ack {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        op: &'static str,
        channels: Vec<String>,
        channel_count: usize,
    },
    /// Per-channel subscribe rejection (may accompany a partial ack).
    SubscribeRejected {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        channel: String,
        reason: Reason,
        message: String,
    },
    /// A delivered event payload.
    Event {
        channel: String,
        event: &'static str,
        seq: u64,
        emitted_at_unix_ms: u64,
        emitted_at_iso: String,
        confirmed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        height: Option<u32>,
        data: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_seq: Option<u64>,
    },
    /// Reply to an app-level `ping`.
    Pong {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        latest_seq: u64,
    },
    /// Server-initiated idle keepalive.
    Heartbeat {
        emitted_at_unix_ms: u64,
        latest_seq: u64,
    },
    /// Channel(s) removed — explicit unsubscribe or terminal `fulfilled`.
    Unsubscribed {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        channels: Vec<String>,
        reason: &'static str,
    },
    /// Resume fell off the retained window — client must cold re-read REST.
    Resync {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        gap: bool,
        latest_seq: u64,
    },
    /// Server going away / evicting.
    Close {
        reason: Reason,
        message: String,
        last_seq: u64,
    },
    /// Non-fatal client-input error; the socket stays open.
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        reason: Reason,
        message: String,
    },
}

/// The per-socket protocol state machine (transport-free).
pub struct Session {
    /// Opaque per-connection id echoed in the `welcome` frame.
    pub session_id: String,
    /// Authoritative channel → class map for this socket.
    channels: HashMap<String, ChannelClass>,
    /// The subscription filter shared with the bus (mirror of `channels` keys).
    filter: Arc<RwLock<HashSet<String>>>,
    limits: Limits,
    network: ergo_ser::address::NetworkPrefix,
    op_times: VecDeque<Instant>,
    /// Highest event `seq` already rendered to this socket. Both delivery
    /// paths (resume replay + the live queue) pass through [`Self::on_event`],
    /// so this watermark makes an event published between subscribe-activation
    /// and the backfill snapshot render exactly once.
    last_event_seq: u64,
}

impl Session {
    /// A fresh session bound to the bus subscription's shared `filter`.
    pub fn new(
        session_id: String,
        filter: Arc<RwLock<HashSet<String>>>,
        network: ergo_ser::address::NetworkPrefix,
    ) -> Self {
        Session {
            session_id,
            channels: HashMap::new(),
            filter,
            limits: Limits::default(),
            network,
            op_times: VecDeque::new(),
            last_event_seq: 0,
        }
    }

    /// The `welcome` frame for this session.
    pub fn welcome(&self, latest_seq: u64) -> ServerFrame {
        ServerFrame::Welcome {
            session_id: self.session_id.clone(),
            latest_seq,
            heartbeat_ms: HEARTBEAT_MS,
            limits: self.limits,
        }
    }

    /// Number of currently-subscribed channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Record a control op against the rate limiter (§2.6). Returns `false`
    /// when the socket has exceeded [`MAX_CONTROL_OPS`] in [`CONTROL_WINDOW`],
    /// in which case the caller emits `rate_limited` and does NOT dispatch.
    pub fn record_control_op(&mut self, now: Instant) -> bool {
        while let Some(&front) = self.op_times.front() {
            if now.duration_since(front) >= CONTROL_WINDOW {
                self.op_times.pop_front();
            } else {
                break;
            }
        }
        if self.op_times.len() >= MAX_CONTROL_OPS {
            return false;
        }
        self.op_times.push_back(now);
        true
    }

    fn sync_filter(&self) {
        let mut f = self.filter.write().unwrap_or_else(|e| e.into_inner());
        *f = self.channels.keys().cloned().collect();
    }

    /// A snapshot copy of the current subscription key set — used by `resume`
    /// to backfill only the channels this socket is subscribed to.
    pub fn snapshot_filter(&self) -> HashSet<String> {
        self.channels.keys().cloned().collect()
    }

    /// Handle `subscribe` (§2.3): validate + liveness-gate each channel,
    /// enforce [`MAX_CHANNELS`]. Partial success is explicit — accepted
    /// channels return in the `ack`, each rejected one gets its own
    /// `subscribe_rejected`.
    pub fn handle_subscribe(
        &mut self,
        id: Option<String>,
        channels: Vec<String>,
        is_live: impl Fn(ChannelClass) -> bool,
    ) -> Vec<ServerFrame> {
        let mut frames = Vec::new();
        let mut accepted = Vec::new();
        for raw in channels {
            match parse_channel(&raw, self.network) {
                Err(rej) => frames.push(ServerFrame::SubscribeRejected {
                    id: id.clone(),
                    channel: raw,
                    reason: Reason::InvalidSelector,
                    message: rej.message,
                }),
                Ok(pc) => {
                    if self.channels.contains_key(&pc.key) {
                        // Idempotent: already subscribed, count it as accepted.
                        accepted.push(pc.key);
                        continue;
                    }
                    if !is_live(pc.class) {
                        frames.push(ServerFrame::SubscribeRejected {
                            id: id.clone(),
                            channel: raw,
                            reason: Reason::ChannelUnavailable,
                            message: format!(
                                "channel class `{}` has no live feed on this node yet",
                                pc.class.as_str()
                            ),
                        });
                        continue;
                    }
                    if self.channels.len() >= self.limits.max_channels {
                        frames.push(ServerFrame::SubscribeRejected {
                            id: id.clone(),
                            channel: raw,
                            reason: Reason::ChannelLimit,
                            message: format!(
                                "max {} channels per socket",
                                self.limits.max_channels
                            ),
                        });
                        continue;
                    }
                    self.channels.insert(pc.key.clone(), pc.class);
                    accepted.push(pc.key);
                }
            }
        }
        self.sync_filter();
        // The ack always reports the full accepted set + current count, even if
        // empty (so a client sees the outcome of an all-rejected batch too).
        let mut ack_channels = accepted;
        ack_channels.sort();
        frames.insert(
            0,
            ServerFrame::Ack {
                id,
                op: "subscribe",
                channels: ack_channels,
                channel_count: self.channels.len(),
            },
        );
        frames
    }

    /// Handle `unsubscribe` (§2.3): remove each named channel; ack the removed
    /// set.
    pub fn handle_unsubscribe(
        &mut self,
        id: Option<String>,
        channels: Vec<String>,
    ) -> Vec<ServerFrame> {
        let mut removed = Vec::new();
        for raw in channels {
            // Normalize via parse so `unsubscribe` keys match `subscribe` keys.
            let key = match parse_channel(&raw, self.network) {
                Ok(pc) => pc.key,
                Err(_) => raw,
            };
            if self.channels.remove(&key).is_some() {
                removed.push(key);
            }
        }
        self.sync_filter();
        removed.sort();
        vec![ServerFrame::Ack {
            id,
            op: "unsubscribe",
            channels: removed,
            channel_count: self.channels.len(),
        }]
    }

    /// Handle `ping` (§2.3).
    pub fn handle_ping(&self, id: Option<String>, latest_seq: u64) -> ServerFrame {
        ServerFrame::Pong { id, latest_seq }
    }

    /// Handle `auth` (§2.3): T0 channels ignore it; ack so the client knows the
    /// frame was seen (the socket stays a pure T0 feed).
    pub fn handle_auth(&self, id: Option<String>) -> ServerFrame {
        ServerFrame::Ack {
            id,
            op: "auth",
            channels: Vec::new(),
            channel_count: self.channels.len(),
        }
    }

    /// Render a delivered [`RealtimeEvent`] into one frame per matched
    /// subscribed channel (§2.2). A terminal channel (`box:`/`tx:`) is removed
    /// after firing and gets a trailing `unsubscribed reason:"fulfilled"`.
    pub fn on_event(&mut self, event: &RealtimeEvent) -> Vec<ServerFrame> {
        // Dedupe across the replay/live seam: an event published between
        // subscribe-activation and the backfill snapshot arrives on BOTH
        // paths; the seq watermark renders it exactly once.
        if event.seq <= self.last_event_seq {
            return Vec::new();
        }
        self.last_event_seq = event.seq;
        let mut matched: Vec<String> = event
            .routes
            .iter()
            .filter(|r| self.channels.contains_key(*r))
            .cloned()
            .collect();
        matched.sort();
        if matched.is_empty() {
            return Vec::new();
        }
        let mut frames = Vec::new();
        let mut fulfilled = Vec::new();
        for channel in matched {
            let class = self.channels.get(&channel).copied();
            frames.push(ServerFrame::Event {
                channel: channel.clone(),
                event: event.event,
                seq: event.seq,
                emitted_at_unix_ms: event.emitted_at_unix_ms,
                emitted_at_iso: unix_ms_to_iso(event.emitted_at_unix_ms),
                confirmed: event.confirmed,
                height: event.height,
                data: event.data.clone(),
                previous_seq: event.previous_seq,
            });
            if class.map(ChannelClass::is_terminal).unwrap_or(false) {
                self.channels.remove(&channel);
                fulfilled.push(channel);
            }
        }
        if !fulfilled.is_empty() {
            self.sync_filter();
            fulfilled.sort();
            frames.push(ServerFrame::Unsubscribed {
                id: None,
                channels: fulfilled,
                reason: "fulfilled",
            });
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::address::NetworkPrefix;

    // ----- helpers -----

    const HEX64: &str = "6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f";

    fn session() -> Session {
        Session::new(
            "sess1".to_string(),
            Arc::new(RwLock::new(HashSet::new())),
            NetworkPrefix::Mainnet,
        )
    }

    fn blocks_live(c: ChannelClass) -> bool {
        matches!(c, ChannelClass::Blocks)
    }

    fn all_live(_c: ChannelClass) -> bool {
        true
    }

    fn frame_json(f: &ServerFrame) -> serde_json::Value {
        serde_json::to_value(f).unwrap()
    }

    // ----- happy path -----

    #[test]
    fn subscribe_live_channel_acks_and_updates_filter() {
        let mut s = session();
        let frames = s.handle_subscribe(Some("c1".into()), vec!["blocks".into()], blocks_live);
        assert_eq!(s.channel_count(), 1);
        let ack = frame_json(&frames[0]);
        assert_eq!(ack["type"], "ack");
        assert_eq!(ack["op"], "subscribe");
        assert_eq!(ack["channels"][0], "blocks");
        assert_eq!(ack["channel_count"], 1);
        assert!(s.filter.read().unwrap().contains("blocks"));
    }

    #[test]
    fn parse_client_frame_variants() {
        assert_eq!(
            parse_client_frame(r#"{"op":"subscribe","id":"c1","channels":["blocks"]}"#).unwrap(),
            ClientFrame::Subscribe {
                id: Some("c1".into()),
                channels: vec!["blocks".into()]
            }
        );
        assert_eq!(
            parse_client_frame(r#"{"op":"ping"}"#).unwrap(),
            ClientFrame::Ping { id: None }
        );
        assert_eq!(
            parse_client_frame(r#"{"op":"resume","since":42,"channels":[]}"#).unwrap(),
            ClientFrame::Resume {
                id: None,
                since: 42,
                channels: vec![]
            }
        );
    }

    // ----- error paths -----

    #[test]
    fn unknown_op_is_distinguished() {
        assert_eq!(
            parse_client_frame(r#"{"op":"frobnicate"}"#),
            Err(FrameParseError::UnknownOp)
        );
        assert!(matches!(
            parse_client_frame(r#"{"no":"op"}"#),
            Err(FrameParseError::BadRequest(_))
        ));
    }

    #[test]
    fn subscribe_invalid_selector_rejects_that_channel_only() {
        let mut s = session();
        let frames = s.handle_subscribe(None, vec!["blocks".into(), "tx:zzz".into()], blocks_live);
        // ack (blocks) + one subscribe_rejected (tx:zzz).
        let ack = frame_json(&frames[0]);
        assert_eq!(ack["channels"][0], "blocks");
        let rej = frame_json(&frames[1]);
        assert_eq!(rej["type"], "subscribe_rejected");
        assert_eq!(rej["reason"], "invalid_selector");
    }

    #[test]
    fn subscribe_unfed_class_is_channel_unavailable() {
        let mut s = session();
        let frames = s.handle_subscribe(
            None,
            vec![format!("tx:{HEX64}")],
            blocks_live, // only blocks live
        );
        let rej = frame_json(&frames[1]);
        assert_eq!(rej["type"], "subscribe_rejected");
        assert_eq!(rej["reason"], "channel_unavailable");
        assert_eq!(s.channel_count(), 0);
    }

    #[test]
    fn subscribe_over_channel_limit_rejects_overflow() {
        let mut s = session();
        s.limits.max_channels = 1;
        let frames = s.handle_subscribe(None, vec!["blocks".into(), "mempool".into()], all_live);
        // blocks accepted; mempool rejected channel_limit.
        assert_eq!(s.channel_count(), 1);
        let has_limit = frames.iter().any(|f| {
            matches!(f, ServerFrame::SubscribeRejected { reason, .. } if *reason == Reason::ChannelLimit)
        });
        assert!(has_limit);
    }

    #[test]
    fn control_op_rate_limit_trips_after_max() {
        let mut s = session();
        let now = Instant::now();
        for _ in 0..MAX_CONTROL_OPS {
            assert!(s.record_control_op(now));
        }
        assert!(!s.record_control_op(now), "over the cap in-window");
        // A later op past the window is allowed again.
        assert!(s.record_control_op(now + CONTROL_WINDOW + Duration::from_millis(1)));
    }

    // ----- terminal channels + events -----

    #[test]
    fn on_event_delivers_to_matching_channel_with_iso_mirror() {
        let mut s = session();
        s.handle_subscribe(None, vec!["blocks".into()], blocks_live);
        let ev = RealtimeEvent {
            seq: 5,
            emitted_at_unix_ms: 1_751_846_400_000,
            routes: vec!["blocks".into()],
            event: "block_applied",
            confirmed: true,
            height: Some(100),
            data: serde_json::json!({"header_id": "aa"}),
            previous_seq: None,
        };
        let frames = s.on_event(&ev);
        let f = frame_json(&frames[0]);
        assert_eq!(f["type"], "event");
        assert_eq!(f["channel"], "blocks");
        assert_eq!(f["seq"], 5);
        assert_eq!(f["confirmed"], true);
        assert_eq!(f["emitted_at_iso"], "2025-07-07T00:00:00.000Z");
    }

    #[test]
    fn terminal_channel_fires_once_then_auto_unsubscribes() {
        let mut s = session();
        s.handle_subscribe(None, vec![format!("box:{HEX64}")], all_live);
        assert_eq!(s.channel_count(), 1);
        let ev = RealtimeEvent {
            seq: 9,
            emitted_at_unix_ms: 0,
            routes: vec![format!("box:{HEX64}")],
            event: "box_spent",
            confirmed: true,
            height: Some(100),
            data: serde_json::json!({"box_id": HEX64}),
            previous_seq: None,
        };
        let frames = s.on_event(&ev);
        // event frame + unsubscribed(fulfilled)
        assert_eq!(frame_json(&frames[0])["type"], "event");
        let unsub = frame_json(&frames[1]);
        assert_eq!(unsub["type"], "unsubscribed");
        assert_eq!(unsub["reason"], "fulfilled");
        assert_eq!(s.channel_count(), 0, "terminal channel freed");
        // A second event no longer matches.
        assert!(s.on_event(&ev).is_empty());
    }

    #[test]
    fn unsubscribe_removes_channel() {
        let mut s = session();
        s.handle_subscribe(None, vec!["blocks".into()], blocks_live);
        let frames = s.handle_unsubscribe(Some("c2".into()), vec!["blocks".into()]);
        let ack = frame_json(&frames[0]);
        assert_eq!(ack["op"], "unsubscribe");
        assert_eq!(ack["channels"][0], "blocks");
        assert_eq!(s.channel_count(), 0);
    }
}

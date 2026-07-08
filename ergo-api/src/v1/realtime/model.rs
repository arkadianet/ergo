//! Realtime channel vocabulary + the canonical event shape (`v1-api-design.md`
//! §4.1, fragment `realtime-ws-webhooks.md` §2.2/§2.5).
//!
//! A [`ChannelClass`] is one of the six subscription classes. A wire channel
//! string is `"<class>"` (class channels) or `"<class>:<selector>"`
//! (selector channels). [`parse_channel`] validates the selector at subscribe
//! time — a malformed one is `invalid_selector` *before* the liveness check —
//! and returns the normalized wire key that both the subscriber filter and the
//! event routing use as one shared identity.
//!
//! A [`RealtimeEventBody`] carries everything about an event except its `seq`,
//! which the [`RealtimeBus`](super::bus::RealtimeBus) assigns at publish time so
//! the whole surface shares ONE monotonic cursor. Payload `data` reuses the v1
//! REST DTO field names verbatim (`header_id`, `value` string, `box_id`, …) —
//! no parallel vocabulary.

use ergo_ser::address::NetworkPrefix;
use serde_json::json;

/// One of the six subscription channel classes (§4.1 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelClass {
    /// `blocks` — `block_applied`, `reorg`. Class channel (no selector).
    Blocks,
    /// `mempool` — `tx_accepted`, `tx_dropped`, `fee_histogram_changed`.
    Mempool,
    /// `address:<address>` — `box_created`, `box_spent`.
    Address,
    /// `box:<box_id>` — `box_spent`. **Terminal** (fires once).
    Box,
    /// `token:<token_id>` — `token_moved`.
    Token,
    /// `tx:<tx_id>` — `tx_confirmed`, `tx_dropped`. **Terminal**.
    Tx,
}

impl ChannelClass {
    /// The lowercase class token as it appears on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelClass::Blocks => "blocks",
            ChannelClass::Mempool => "mempool",
            ChannelClass::Address => "address",
            ChannelClass::Box => "box",
            ChannelClass::Token => "token",
            ChannelClass::Tx => "tx",
        }
    }

    /// True for the two class channels that take no selector.
    fn is_class_channel(self) -> bool {
        matches!(self, ChannelClass::Blocks | ChannelClass::Mempool)
    }

    /// True for channels that fire exactly once and then auto-unsubscribe
    /// (`box:`, `tx:` — §2.2 terminal-channel rule).
    pub fn is_terminal(self) -> bool {
        matches!(self, ChannelClass::Box | ChannelClass::Tx)
    }
}

/// Why a channel selector was rejected at subscribe time. Both map to the
/// canonical [`invalid_selector`](crate::v1::error::Reason::InvalidSelector)
/// reason (§2.2) — there is no separate "unknown channel" reason in the
/// canonical set, so an unknown class token is treated as a malformed selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorReject {
    /// The human-readable reason the selector is invalid.
    pub message: String,
}

impl SelectorReject {
    fn new(message: impl Into<String>) -> Self {
        SelectorReject {
            message: message.into(),
        }
    }
}

/// A parsed, validated channel: its class and the normalized wire key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedChannel {
    /// The channel class (drives liveness + terminal handling).
    pub class: ChannelClass,
    /// The normalized wire key (`"blocks"`, `"address:9f…"`, `"box:6a…"`).
    /// This is the SHARED identity used by both the subscriber filter and the
    /// event route set.
    pub key: String,
}

fn is_lower_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Parse and validate a wire channel string into its class + normalized key
/// (§2.2). Selector validation happens here so a malformed selector is
/// `invalid_selector` before the liveness gate (`channel_unavailable`) ever
/// runs — the two rejects are distinct and ordered.
///
/// `network` validates an `address:` selector against the node's network so a
/// mainnet socket cannot subscribe a testnet address (and vice-versa).
pub fn parse_channel(raw: &str, network: NetworkPrefix) -> Result<ParsedChannel, SelectorReject> {
    let (class_tok, selector) = match raw.split_once(':') {
        Some((c, s)) => (c, Some(s)),
        None => (raw, None),
    };
    let class = match class_tok {
        "blocks" => ChannelClass::Blocks,
        "mempool" => ChannelClass::Mempool,
        "address" => ChannelClass::Address,
        "box" => ChannelClass::Box,
        "token" => ChannelClass::Token,
        "tx" => ChannelClass::Tx,
        other => {
            return Err(SelectorReject::new(format!(
                "unknown channel class `{other}`"
            )))
        }
    };

    if class.is_class_channel() {
        if selector.is_some() {
            return Err(SelectorReject::new(format!(
                "channel `{}` takes no selector",
                class.as_str()
            )));
        }
        return Ok(ParsedChannel {
            class,
            key: class.as_str().to_string(),
        });
    }

    let selector = selector.ok_or_else(|| {
        SelectorReject::new(format!(
            "channel `{}` requires a selector (`{}:<…>`)",
            class.as_str(),
            class.as_str()
        ))
    })?;

    match class {
        ChannelClass::Address => {
            // Reuse the shared address decoder so channel validation cannot
            // drift from the REST address routes (and rejects cross-network).
            if crate::blockchain::address_to_tree_hash(selector, network).is_err() {
                return Err(SelectorReject::new(
                    "address is not valid base58 for this network",
                ));
            }
        }
        ChannelClass::Box | ChannelClass::Token | ChannelClass::Tx => {
            if !is_lower_hex64(selector) {
                return Err(SelectorReject::new(format!(
                    "{}_id must be 64 lowercase hex chars",
                    class.as_str()
                )));
            }
        }
        ChannelClass::Blocks | ChannelClass::Mempool => unreachable!("handled above"),
    }

    Ok(ParsedChannel {
        class,
        key: format!("{}:{selector}", class.as_str()),
    })
}

/// A fully-shaped event minus its `seq` (assigned by the bus at publish time,
/// so the whole realtime surface shares one monotonic cursor). Constructors
/// below build the canonical payloads from §2.5.
#[derive(Debug, Clone)]
pub struct RealtimeEventBody {
    /// Wall-clock time the source signal was observed, unix milliseconds.
    pub emitted_at_unix_ms: u64,
    /// The normalized wire keys this event must be delivered on. A socket
    /// subscribed to any of these keys receives the event once per matched key.
    pub routes: Vec<String>,
    /// The event-kind token (`block_applied`, `reorg`, `box_spent`, …).
    pub event: &'static str,
    /// `false` = mempool-tentative, `true` = on-chain (§2.4).
    pub confirmed: bool,
    /// Chain height the event pertains to, when applicable.
    pub height: Option<u32>,
    /// The event payload, snake_case, reusing the v1 REST DTO field names.
    pub data: serde_json::Value,
    /// For a retraction event (`box_reverted`, `box_unspent`, `tx_dropped`
    /// on reorg): the `seq` this event invalidates (§2.7). `None` otherwise.
    pub previous_seq: Option<u64>,
}

impl RealtimeEventBody {
    /// `block_applied` on the `blocks` channel (§2.5). Always `confirmed`.
    pub fn block_applied(
        unix_ms: u64,
        header_id: String,
        height: u32,
        tx_count: u32,
        size_bytes: u64,
    ) -> Self {
        RealtimeEventBody {
            emitted_at_unix_ms: unix_ms,
            routes: vec!["blocks".to_string()],
            event: "block_applied",
            confirmed: true,
            height: Some(height),
            data: json!({
                "header_id": header_id,
                "height": height,
                "tx_count": tx_count,
                "size_bytes": size_bytes,
            }),
            previous_seq: None,
        }
    }

    /// `reorg` on the `blocks` channel (§2.5). `dropped_header_ids` is the set
    /// of orphaned tip ids the coarse ring can name (empty when only the new
    /// tip is known — the coarse substrate does not enumerate the dropped
    /// branch; documented as a best-effort guarantee).
    pub fn reorg(
        unix_ms: u64,
        height: u32,
        header_id: String,
        depth: u32,
        dropped_header_ids: Vec<String>,
    ) -> Self {
        RealtimeEventBody {
            emitted_at_unix_ms: unix_ms,
            routes: vec!["blocks".to_string()],
            event: "reorg",
            confirmed: true,
            height: Some(height),
            data: json!({
                "height": height,
                "header_id": header_id,
                "depth": depth,
                "dropped_header_ids": dropped_header_ids,
            }),
            previous_seq: None,
        }
    }

    /// `box_spent` (§2.5). Routes to the box's `address:` channel and its
    /// terminal `box:` channel. The `data` is expected to be the v1 box DTO
    /// (built by the caller); this helper only fixes the routing + envelope.
    pub fn box_spent(
        unix_ms: u64,
        address_key: Option<String>,
        box_id: String,
        confirmed: bool,
        height: Option<u32>,
        data: serde_json::Value,
    ) -> Self {
        let mut routes = Vec::with_capacity(2);
        if let Some(a) = address_key {
            routes.push(a);
        }
        routes.push(format!("box:{box_id}"));
        RealtimeEventBody {
            emitted_at_unix_ms: unix_ms,
            routes,
            event: "box_spent",
            confirmed,
            height,
            data,
            previous_seq: None,
        }
    }

    /// `tx_confirmed` on a terminal `tx:` channel (§2.5).
    pub fn tx_confirmed(unix_ms: u64, tx_id: String, height: u32, header_id: String) -> Self {
        RealtimeEventBody {
            emitted_at_unix_ms: unix_ms,
            routes: vec![format!("tx:{tx_id}")],
            event: "tx_confirmed",
            confirmed: true,
            height: Some(height),
            data: json!({
                "tx_id": tx_id,
                "height": height,
                "header_id": header_id,
                "confirmations": 1,
            }),
            previous_seq: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn net() -> NetworkPrefix {
        NetworkPrefix::Mainnet
    }

    const HEX64: &str = "6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f6a2d1e0f";

    // ----- happy path -----

    #[test]
    fn parse_class_channels_have_no_selector() {
        let b = parse_channel("blocks", net()).unwrap();
        assert_eq!(b.class, ChannelClass::Blocks);
        assert_eq!(b.key, "blocks");
        let m = parse_channel("mempool", net()).unwrap();
        assert_eq!(m.class, ChannelClass::Mempool);
    }

    #[test]
    fn parse_hex_selectors_normalize_to_prefixed_key() {
        let c = parse_channel(&format!("box:{HEX64}"), net()).unwrap();
        assert_eq!(c.class, ChannelClass::Box);
        assert_eq!(c.key, format!("box:{HEX64}"));
        assert!(c.class.is_terminal());
        let t = parse_channel(&format!("token:{HEX64}"), net()).unwrap();
        assert_eq!(t.class, ChannelClass::Token);
        assert!(!t.class.is_terminal());
    }

    // ----- error paths -----

    #[test]
    fn parse_class_channel_with_selector_is_invalid() {
        assert!(parse_channel("blocks:foo", net()).is_err());
    }

    #[test]
    fn parse_selector_channel_without_selector_is_invalid() {
        assert!(parse_channel("box", net()).is_err());
    }

    #[test]
    fn parse_short_or_upper_hex_is_invalid() {
        assert!(parse_channel("tx:deadbeef", net()).is_err());
        let upper = HEX64.to_uppercase();
        assert!(parse_channel(&format!("tx:{upper}"), net()).is_err());
    }

    #[test]
    fn parse_unknown_class_is_invalid() {
        assert!(parse_channel("wallet:9f", net()).is_err());
    }

    #[test]
    fn parse_bad_address_is_invalid() {
        assert!(parse_channel("address:not-an-address!!", net()).is_err());
    }

    // ----- constructors -----

    #[test]
    fn block_applied_body_routes_to_blocks_and_is_confirmed() {
        let b = RealtimeEventBody::block_applied(1, "aa".into(), 100, 3, 1234);
        assert_eq!(b.routes, vec!["blocks".to_string()]);
        assert_eq!(b.event, "block_applied");
        assert!(b.confirmed);
        assert_eq!(b.data["tx_count"], 3);
        assert_eq!(b.data["size_bytes"], 1234);
    }

    #[test]
    fn box_spent_body_routes_to_address_and_terminal_box() {
        let b = RealtimeEventBody::box_spent(
            1,
            Some("address:9f".into()),
            HEX64.into(),
            true,
            Some(10),
            json!({"box_id": HEX64}),
        );
        assert_eq!(
            b.routes,
            vec!["address:9f".to_string(), format!("box:{HEX64}")]
        );
        assert_eq!(b.event, "box_spent");
    }
}

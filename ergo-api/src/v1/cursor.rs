//! The ONE cursor-pagination codec (`v1-api-design.md` §1.5, coherence C.4).
//!
//! Every v1 collection is cursor-paginated (`?limit=&cursor=`, never
//! `offset` on the wire) and answers `page:{limit, next_cursor, has_more}`.
//! This module is the single shared codec + page builder; groups differ only
//! in the tiny [`CursorPayload`] they choose (a height key `{h}`, a
//! global-index key `{gi}`, an offset shim `{offset}`, a mempool keyset
//! `{w,t}`, a wallet keyset `{after_index}`, …).
//!
//! **Opaqueness is load-bearing (locked decision D5, §1.5 / §8):** the wire
//! form is `version-byte || compact-JSON(payload)`, base64url-no-pad encoded.
//! Clients MUST treat it as opaque. Because it is opaque, Phase-2 can swap a
//! Phase-1 *offset-alias* payload (which drifts under a moving DESC feed,
//! same as Scala today) for a stable-seek key (`IndexerQuery::*_after`)
//! WITHOUT breaking any client. The [`CURSOR_VERSION`] byte is what lets the
//! decoder reject a future incompatible encoding cleanly instead of
//! mis-parsing it.
//!
//! `has_more` is computed by **overfetch-by-one** (§1.5): a handler requests
//! `limit + 1` rows, and [`Page::from_overfetch`] trims the sentinel row,
//! sets `has_more`, and mints `next_cursor` from the last *kept* row. This
//! works with or without a total-count method — v1's envelope has no `total`.

use utoipa::ToSchema;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::error::{v1_error, Reason};
use axum::response::Response;

/// Version tag prepended to every encoded cursor before the compact JSON.
/// Bumping it (Phase-2 stable-seek payloads) makes every older cursor decode
/// to [`CursorError::Version`] rather than silently mis-seeking — the codec
/// change stays invisible to clients while old in-flight cursors fail closed.
pub const CURSOR_VERSION: u8 = 1;

/// Default page size when a caller omits `limit`. Groups pass their own
/// per-group default (see the §2.2 bounding table); this is the fleet
/// fallback for handlers that don't specialize.
pub const DEFAULT_LIMIT: u32 = 50;

/// Fleet hard cap on `limit` when a group doesn't specify a tighter one.
/// Per-group caps (e.g. `boxes/* = 500`, `stats/* = 16384`) are passed
/// explicitly to [`clamp_limit`]; this is only the safety fallback.
pub const MAX_LIMIT: u32 = 500;

/// Anything a group uses as its opaque cursor state. It is just
/// `Serialize + DeserializeOwned`; the codec is agnostic to its shape.
///
/// Keep payloads compact (short keys — `{"h":…}`, `{"gi":…}`) since the JSON
/// is base64'd onto every `next_cursor`.
pub trait CursorPayload: Serialize + DeserializeOwned {}
impl<T: Serialize + DeserializeOwned> CursorPayload for T {}

/// Why a cursor failed to decode. Never leaks internals to the client — it
/// maps to a single [`Reason::InvalidCursor`] response via
/// [`CursorError::into_response`].
#[derive(Debug)]
pub enum CursorError {
    /// Not valid base64url.
    Base64,
    /// Decoded to zero bytes (no version, no payload).
    Empty,
    /// Version byte is not one this build understands.
    Version(u8),
    /// Version matched but the JSON payload didn't parse to the expected type.
    Payload,
}

impl CursorError {
    /// Render as the canonical `invalid_cursor` 400 envelope (§1.5). The
    /// `detail` is generic on purpose — a tampering client learns nothing
    /// about the internal encoding.
    pub fn into_response(self) -> Response {
        v1_error(
            Reason::InvalidCursor,
            "pagination cursor is malformed or stale",
            "drop the `cursor` param to restart from the first page",
        )
    }
}

/// Encode an opaque `next_cursor` from a group's payload (§1.5). The result
/// is `base64url(no-pad, [CURSOR_VERSION] ++ compact-JSON(payload))`.
///
/// Infallible for any payload that serializes (all `#[derive(Serialize)]`
/// structs of finite data do); a serialization failure degenerates to an
/// empty-`{}` body rather than panicking, which the decoder then rejects.
pub fn encode_cursor<T: CursorPayload>(payload: &T) -> String {
    let mut bytes = Vec::with_capacity(32);
    bytes.push(CURSOR_VERSION);
    // Compact (no whitespace) — serde_json's default `to_vec` is already
    // compact. A serialize failure is not expected for wire payloads; fall
    // back to an empty object so we never panic on the response path.
    match serde_json::to_vec(payload) {
        Ok(mut json) => bytes.append(&mut json),
        Err(_) => bytes.extend_from_slice(b"{}"),
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode a client-supplied opaque cursor back to a group's payload (§1.5).
/// Any tamper — bad base64, wrong version, wrong shape — is
/// [`CursorError`], which the caller renders as `invalid_cursor`.
pub fn decode_cursor<T: CursorPayload>(cursor: &str) -> Result<T, CursorError> {
    let raw = URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .map_err(|_| CursorError::Base64)?;
    let (&version, payload) = raw.split_first().ok_or(CursorError::Empty)?;
    if version != CURSOR_VERSION {
        return Err(CursorError::Version(version));
    }
    serde_json::from_slice(payload).map_err(|_| CursorError::Payload)
}

/// Convenience: decode an optional `cursor` query param straight to a
/// boxed error [`Response`] on tamper. `None` (first page) yields `Ok(None)`.
/// The error is boxed to keep the `Ok` path small (repo convention).
pub fn decode_opt_cursor<T: CursorPayload>(
    cursor: Option<&str>,
) -> Result<Option<T>, Box<Response>> {
    match cursor {
        None => Ok(None),
        Some(c) => decode_cursor(c)
            .map(Some)
            .map_err(|e| Box::new(e.into_response())),
    }
}

/// Clamp a caller-supplied `limit` into `[1, max]`, defaulting when absent
/// (§1.5). `requested == Some(0)` clamps up to 1 (a zero-row page is never
/// what a caller means); anything above `max` clamps down to `max`. Groups
/// pass their own `(default, max)` from the §2.2 bounding table.
pub fn clamp_limit(requested: Option<u32>, default: u32, max: u32) -> u32 {
    let max = max.max(1);
    match requested {
        None => default.clamp(1, max),
        Some(n) => n.clamp(1, max),
    }
}

/// The `page` object of a v1 collection envelope (`v1-api-design.md` §1.3 /
/// §1.5): `{ limit, next_cursor, has_more }`. `next_cursor` is `null` exactly
/// when `has_more` is false.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Page {
    /// The effective (clamped) page size that produced these items.
    pub limit: u32,
    /// Opaque cursor to fetch the next page, or `null` at the end.
    pub next_cursor: Option<String>,
    /// Whether a further page exists.
    pub has_more: bool,
}

impl Page {
    /// Build a `Page` and trim an overfetched result set in one step (§1.5
    /// overfetch-by-one). Pass the rows a handler fetched with `limit + 1`;
    /// if more than `limit` came back, the extra row is dropped, `has_more`
    /// is `true`, and `next_cursor` is minted from the last *kept* row via
    /// `key_of`. Otherwise `has_more` is `false` and `next_cursor` is `None`.
    ///
    /// `key_of` returns the [`CursorPayload`] identifying a row (the seek key
    /// the next page resumes after).
    pub fn from_overfetch<T, K, F>(mut items: Vec<T>, limit: u32, key_of: F) -> (Vec<T>, Page)
    where
        K: CursorPayload,
        F: FnOnce(&T) -> K,
    {
        let has_more = items.len() as u64 > u64::from(limit);
        if has_more {
            items.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            items.last().map(|last| encode_cursor(&key_of(last)))
        } else {
            None
        };
        // Defensive: if truncation somehow emptied the page, there is no key
        // to resume from, so there is no next page.
        let (next_cursor, has_more) = match next_cursor {
            Some(c) => (Some(c), true),
            None => (None, false),
        };
        (
            items,
            Page {
                limit,
                next_cursor,
                has_more,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    // ----- helpers -----

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct HeightKey {
        h: u64,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct MempoolKey {
        w: u64,
        t: String,
    }

    // ----- round-trips -----

    #[test]
    fn cursor_height_key_roundtrips() {
        let payload = HeightKey { h: 1_808_894 };
        let encoded = encode_cursor(&payload);
        let decoded: HeightKey = decode_cursor(&encoded).expect("decodes");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn cursor_keyset_roundtrips() {
        let payload = MempoolKey {
            w: 42,
            t: "65238ca7".to_string(),
        };
        let encoded = encode_cursor(&payload);
        let decoded: MempoolKey = decode_cursor(&encoded).expect("decodes");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn cursor_is_url_safe_and_unpadded() {
        // base64url alphabet only, no '+' '/' '=' — safe as a bare query value.
        let encoded = encode_cursor(&HeightKey { h: u64::MAX });
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "cursor must be url-safe: {encoded}",
        );
        assert!(!encoded.contains('='), "cursor must be unpadded");
    }

    #[test]
    fn decode_opt_none_is_first_page() {
        let got: Option<HeightKey> = decode_opt_cursor(None).expect("none ok");
        assert!(got.is_none());
    }

    // ----- error paths (tamper rejection) -----

    #[test]
    fn tampered_base64_rejected() {
        let err = decode_cursor::<HeightKey>("!!!not base64!!!").unwrap_err();
        assert!(matches!(err, CursorError::Base64));
    }

    #[test]
    fn empty_cursor_rejected() {
        let empty = URL_SAFE_NO_PAD.encode([]);
        let err = decode_cursor::<HeightKey>(&empty).unwrap_err();
        assert!(matches!(err, CursorError::Empty));
    }

    #[test]
    fn wrong_version_rejected() {
        // A payload from a "future" v2 encoding fails closed, not mis-parsed.
        let mut bytes = vec![CURSOR_VERSION + 1];
        bytes.extend_from_slice(br#"{"h":1}"#);
        let forged = URL_SAFE_NO_PAD.encode(bytes);
        let err = decode_cursor::<HeightKey>(&forged).unwrap_err();
        assert!(matches!(err, CursorError::Version(v) if v == CURSOR_VERSION + 1));
    }

    #[test]
    fn wrong_payload_shape_rejected() {
        // Correct version, but the JSON is for a different key type.
        let encoded = encode_cursor(&MempoolKey {
            w: 1,
            t: "x".into(),
        });
        let err = decode_cursor::<HeightKey>(&encoded).unwrap_err();
        assert!(matches!(err, CursorError::Payload));
    }

    #[test]
    fn tampered_cursor_maps_to_invalid_cursor_response() {
        let resp = CursorError::Base64.into_response();
        assert_eq!(resp.status(), Reason::InvalidCursor.http_status());
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    // ----- clamp -----

    #[test]
    fn clamp_limit_defaults_when_absent() {
        assert_eq!(clamp_limit(None, 20, 500), 20);
    }

    #[test]
    fn clamp_limit_caps_at_max() {
        assert_eq!(clamp_limit(Some(10_000), 20, 500), 500);
    }

    #[test]
    fn clamp_limit_floors_zero_to_one() {
        assert_eq!(clamp_limit(Some(0), 20, 500), 1);
    }

    #[test]
    fn clamp_limit_passes_in_range() {
        assert_eq!(clamp_limit(Some(37), 20, 500), 37);
    }

    #[test]
    fn clamp_limit_default_above_max_is_capped() {
        // Misconfigured group defaults never exceed the hard cap.
        assert_eq!(clamp_limit(None, 9_999, 200), 200);
    }

    // ----- page builder (overfetch) -----

    #[test]
    fn overfetch_full_page_sets_has_more_and_cursor() {
        // limit=2, fetched 3 (overfetch-by-one) → trim to 2, has_more, cursor.
        let rows = vec![10u64, 20, 30];
        let (items, page) = Page::from_overfetch(rows, 2, |&h| HeightKey { h });
        assert_eq!(items, vec![10, 20]);
        assert_eq!(page.limit, 2);
        assert!(page.has_more);
        let cursor = page.next_cursor.expect("cursor present");
        // Cursor resumes after the last KEPT row (20), not the dropped 30.
        let decoded: HeightKey = decode_cursor(&cursor).expect("decodes");
        assert_eq!(decoded, HeightKey { h: 20 });
    }

    #[test]
    fn overfetch_short_page_has_no_more_and_null_cursor() {
        let rows = vec![10u64, 20];
        let (items, page) = Page::from_overfetch(rows, 5, |&h| HeightKey { h });
        assert_eq!(items, vec![10, 20]);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn overfetch_exact_page_has_no_more() {
        // Exactly `limit` rows (no sentinel) ⇒ end of feed.
        let rows = vec![10u64, 20, 30];
        let (items, page) = Page::from_overfetch(rows, 3, |&h| HeightKey { h });
        assert_eq!(items.len(), 3);
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn overfetch_empty_is_terminal() {
        let rows: Vec<u64> = vec![];
        let (items, page) = Page::from_overfetch(rows, 10, |&h| HeightKey { h });
        assert!(items.is_empty());
        assert!(!page.has_more);
        assert!(page.next_cursor.is_none());
    }
}

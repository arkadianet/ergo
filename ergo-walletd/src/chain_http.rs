//! HTTP chain adapter for the standalone daemon.
//!
//! # What the wire can and cannot prove
//!
//! The node's current chain protocol carries structured block, transaction,
//! and box fields but no raw header or transaction bytes. Header validation is
//! therefore limited to the identity/height/parent fields on the wire;
//! transaction ids can be cross-checked against the ids embedded in their
//! output boxes, but cannot be recomputed from raw transaction bytes. ErgoBox
//! bytes are parsed canonically and all recomputable box fields are checked.
//!
//! **Known deviation:** a block's protocol id is therefore *not* recomputed
//! from raw header bytes here. It is taken from the node and checked for
//! internal consistency (parent linkage, tip agreement, uniqueness) rather
//! than recomputed, so a node that reports a wrong `blockId` for a header this
//! build never sees the bytes of is not caught at this layer. Closing that gap
//! needs raw header bytes on the chain protocol, not a client change.
//!
//! # Bounded pages
//!
//! Every response body is capped at [`MAX_RESPONSE_BODY_BYTES`]. For
//! `blocks-since` that cap is what bounds the *page size*, so a page the node
//! cannot fit is rejected here rather than retried: the daemon never asks for a
//! smaller page, so a body over the cap means a single block is larger than the
//! budget, and the pass fails closed with an error naming both the cap and the
//! page size. See [`crate::sync::DEFAULT_BLOCKS_PER_PAGE`].

use std::io::Read;
use std::time::Duration;

use ergo_primitives::reader::VlqReader;
use ergo_ser::ergo_box::{read_ergo_box, serialize_ergo_box};
use ergo_wallet_protocol::chain as wire;
use ergo_wallet_service::{
    ChainBlock, ChainBox, ChainClient, ChainClientError, ChainInput, ChainOutput, ChainSnapshot,
    ChainTransaction, CommittedTip, ReemissionInput, SubmitRequest, SubmitResponse, UtxoLookup,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::HeaderValue;
use reqwest::{StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::config::ApiKey;

const API_KEY_HEADER: &str = "api_key";
/// Hard ceiling on any response body the daemon will buffer. `blocks-since`
/// pages are the reason it exists: the wire form hex-encodes every output box,
/// so a page's body is roughly twice the blocks it carries, and an unbounded
/// page would grow with `sync_batch` until it hit this.
pub const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct HttpChainClient {
    client: Client,
    base_url: Url,
    api_key: ApiKey,
    max_response_body_bytes: usize,
}

impl std::fmt::Debug for HttpChainClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpChainClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("max_response_body_bytes", &self.max_response_body_bytes)
            .finish()
    }
}

impl HttpChainClient {
    /// Blocking constructor. **Must be called from a thread that is not inside
    /// an async context** — see [`Self::new_in_runtime`] for the async-safe
    /// form and [`crate::prepare`] for how the daemon avoids the trap.
    pub fn new(base_url: Url, api_key: ApiKey) -> Result<Self, ChainClientError> {
        Self::with_timeouts(base_url, api_key, CONNECT_TIMEOUT, TOTAL_TIMEOUT)
    }

    /// Same client as [`Self::new`], built from a thread that *is* inside a
    /// Tokio runtime.
    ///
    /// # Why the blocking constructor cannot be used from async code
    ///
    /// `reqwest`'s blocking client owns a private Tokio runtime, created and
    /// dropped inside `ClientBuilder::build`. Tokio refuses to drop a runtime on
    /// a thread that is inside an async context, and `reqwest` drops a shell
    /// runtime while it is *entered* in exactly that situation, so `build`
    /// **panics** on a runtime worker. (The abort is `debug_assertions`-gated on
    /// the `reqwest` side, which is why it only reproduces in a dev/test build.)
    /// The daemon therefore builds the client in [`crate::prepare`], before its
    /// own runtime exists, and never from an `async fn`.
    ///
    /// A `#[tokio::test]` (or any embedder already inside a runtime) has no such
    /// window, so this constructor provides one: the build is handed to the
    /// runtime's blocking pool, whose threads are *not* inside an async context,
    /// and the finished client — `Send + Sync`, like the one `prepare` builds —
    /// is moved back. Pinned by `tests/it/daemon_boot.rs`.
    pub async fn new_in_runtime(base_url: Url, api_key: ApiKey) -> Result<Self, ChainClientError> {
        Self::with_timeouts_on_blocking_pool(base_url, api_key, CONNECT_TIMEOUT, TOTAL_TIMEOUT)
            .await
    }

    /// [`Self::new_in_runtime`] with explicit timeouts, for tests that need a
    /// short ceiling.
    pub async fn with_timeouts_in_runtime(
        base_url: Url,
        api_key: ApiKey,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, ChainClientError> {
        Self::with_timeouts_on_blocking_pool(base_url, api_key, connect_timeout, total_timeout)
            .await
    }

    async fn with_timeouts_on_blocking_pool(
        base_url: Url,
        api_key: ApiKey,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, ChainClientError> {
        tokio::task::spawn_blocking(move || {
            Self::with_timeouts(base_url, api_key, connect_timeout, total_timeout)
        })
        .await
        .map_err(|error| {
            ChainClientError::Transport(format!("HTTP client initialization task failed: {error}"))
        })?
    }

    /// Blocking constructor. **Must be called from a thread that is not inside
    /// an async context** — a `#[tokio::test]` body, an `async fn`, or anything
    /// under `#[tokio::main]` will make `reqwest` panic. Use
    /// [`Self::with_timeouts_in_runtime`] there, and [`Self::new`] in
    /// [`crate::prepare`], which the binary calls before it starts a runtime.
    ///
    /// There is deliberately no runtime check here. `Handle::try_current()`
    /// cannot tell the two apart: it is `Ok` on a blocking-pool thread (where
    /// the build is safe) as well as on an entered worker (where it panics), so
    /// a check built on it would reject the one context that works. The
    /// invariant is documented, structurally enforced by `main`, and exercised
    /// end-to-end by `tests/it/daemon_boot.rs`.
    pub fn with_timeouts(
        mut base_url: Url,
        api_key: ApiKey,
        connect_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, ChainClientError> {
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        let client = Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(total_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|_| {
                ChainClientError::Transport("HTTP client initialization failed".to_string())
            })?;
        Ok(Self {
            client,
            base_url,
            api_key,
            max_response_body_bytes: MAX_RESPONSE_BODY_BYTES,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    fn get_bytes(&self, path: &str) -> Result<Vec<u8>, ChainClientError> {
        self.get_bytes_optional(path, false)?.ok_or_else(|| {
            ChainClientError::Protocol("chain endpoint returned no body".to_string())
        })
    }

    fn get_bytes_optional(
        &self,
        path: &str,
        allow_not_found: bool,
    ) -> Result<Option<Vec<u8>>, ChainClientError> {
        self.request_bytes(path, allow_not_found, None)
    }

    /// `deadline` overrides the client's total timeout for this one request.
    /// Read paths use it so a local API read cannot inherit the sync path's
    /// 30s budget.
    fn request_bytes(
        &self,
        path: &str,
        allow_not_found: bool,
        deadline: Option<Duration>,
    ) -> Result<Option<Vec<u8>>, ChainClientError> {
        let response = self.send(path, deadline)?;
        if response.status().is_success() {
            return read_body(response, self.max_response_body_bytes)
                .map_err(ChainClientError::from)
                .map(Some);
        }
        if allow_not_found && response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Err(self.status_error(response)?)
    }

    /// Send one GET and hand back the raw response, so callers that need a
    /// different *body* policy (see [`Self::page_bytes`]) can share the URL,
    /// header, and transport handling instead of duplicating it.
    fn send(&self, path: &str, deadline: Option<Duration>) -> Result<Response, ChainClientError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| ChainClientError::Protocol("invalid chain endpoint URL".to_string()))?;
        let value = HeaderValue::from_bytes(self.api_key.expose())
            .map_err(|_| ChainClientError::Protocol("API key is not a valid header".to_string()))?;
        let mut request = self.client.get(url).header(API_KEY_HEADER, value);
        if let Some(deadline) = deadline {
            request = request.timeout(deadline);
        }
        request.send().map_err(map_transport_error)
    }

    /// Map a non-success response onto the typed error. Consumes the response
    /// because the `410` arm reads its body. The body is parsed into a typed
    /// shape and never surfaced as text, so a node cannot smuggle a body into a
    /// log line.
    fn status_error(&self, response: Response) -> Result<ChainClientError, ChainClientError> {
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(ChainClientError::Protocol(format!(
                "node returned HTTP {status}"
            )));
        }
        Ok(match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ChainClientError::Unauthorized,
            StatusCode::CONFLICT => ChainClientError::Conflict,
            StatusCode::GONE => {
                let body = read_body(response, self.max_response_body_bytes)
                    .map_err(ChainClientError::from)?;
                let parsed: wire::BlocksSinceResponse = parse_json(&body)?;
                match parsed {
                    wire::BlocksSinceResponse::Pruned(pruned) => {
                        let tip = neutral_tip(pruned.tip)?;
                        if pruned.minimum_height > tip.height {
                            return Err(ChainClientError::Protocol(
                                "410 response has a pruned floor above its tip".to_string(),
                            ));
                        }
                        ChainClientError::HistoryPruned {
                            minimum_height: Some(pruned.minimum_height),
                        }
                    }
                    _ => ChainClientError::Protocol(
                        "410 response was not a pruned-history response".to_string(),
                    ),
                }
            }
            StatusCode::TOO_MANY_REQUESTS
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => {
                ChainClientError::Unavailable(format!("node returned HTTP {status}"))
            }
            _ => ChainClientError::Protocol(format!("node returned HTTP {status}")),
        })
    }

    /// Body fetch for one `blocks-since` page.
    ///
    /// Identical to [`Self::request_bytes`] except for the body policy, and the
    /// difference is the whole point: the sync loop bounds a page by block
    /// count (`crate::sync::DEFAULT_BLOCKS_PER_PAGE`), and the byte cap is what
    /// stops a page from being unbounded. A body over the cap is reported as the
    /// terminal condition it is, naming both numbers. The daemon never asks for
    /// a smaller page, so retrying could not help, and `SyncError` treats a
    /// protocol failure as terminal — the pass fails closed instead of looping.
    fn page_bytes(&self, path: &str, blocks: u32) -> Result<Vec<u8>, ChainClientError> {
        let response = self.send(path, None)?;
        if !response.status().is_success() {
            return Err(self.status_error(response)?);
        }
        read_page(response, self.max_response_body_bytes, blocks)
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ChainClientError> {
        let body = self.get_bytes(path)?;
        parse_json(&body)
    }

    fn get_json_optional<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<Option<T>, ChainClientError> {
        self.get_bytes_optional(path, true)?
            .map(|body| parse_json(&body))
            .transpose()
    }
}

impl ChainClient for HttpChainClient {
    fn committed_tip(&self) -> Result<CommittedTip, ChainClientError> {
        let tip: wire::ChainTip = self.get_json("api/v1/chain/tip")?;
        neutral_tip(tip)
    }

    fn snapshot(&self) -> Result<ChainSnapshot, ChainClientError> {
        let snapshot: wire::ChainSnapshot = self.get_json("api/v1/chain/snapshot")?;
        neutral_snapshot(snapshot)
    }

    fn committed_tip_within(&self, timeout: Duration) -> Result<CommittedTip, ChainClientError> {
        let body = self
            .request_bytes("api/v1/chain/tip", false, Some(timeout))?
            .ok_or_else(|| {
                ChainClientError::Protocol("chain endpoint returned no body".to_string())
            })?;
        let tip: wire::ChainTip = parse_json(&body)?;
        neutral_tip(tip)
    }

    fn blocks_since(
        &self,
        request: ergo_wallet_service::BlocksSinceRequest,
    ) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
        if request.limit == 0 || request.limit > 1024 {
            return Err(ChainClientError::Protocol(
                "blocks-since limit must be between 1 and 1024".to_string(),
            ));
        }
        let mut url = self
            .base_url
            .join("api/v1/chain/blocks-since")
            .map_err(|_| ChainClientError::Protocol("invalid chain endpoint URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("height", &request.cursor.height.to_string());
            query.append_pair("id", &hex::encode(request.cursor.header_id));
            query.append_pair("limit", &request.limit.to_string());
        }
        let url = url.to_string();
        let path = url.strip_prefix(self.base_url.as_str()).ok_or_else(|| {
            ChainClientError::Protocol("chain endpoint URL escaped base".to_string())
        })?;
        let body = self.page_bytes(path, request.limit)?;
        let response: wire::BlocksSinceResponse = parse_json(&body)?;
        neutral_blocks_since(response, request.cursor, request.limit)
    }

    fn lookup_utxo(
        &self,
        box_id: [u8; 32],
        expected_tip: CommittedTip,
    ) -> Result<UtxoLookup, ChainClientError> {
        let mut url = self
            .base_url
            .join(&format!("api/v1/chain/boxes/{}", hex::encode(box_id)))
            .map_err(|_| ChainClientError::Protocol("invalid box endpoint URL".to_string()))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("tip", &hex::encode(expected_tip.header_id));
            query.append_pair("height", &expected_tip.height.to_string());
        }
        let path = url
            .to_string()
            .strip_prefix(self.base_url.as_str())
            .ok_or_else(|| ChainClientError::Protocol("box endpoint URL escaped base".to_string()))?
            .to_string();
        let Some(response) = self.get_json_optional::<wire::BoxLookupResponse>(&path)? else {
            return Ok(UtxoLookup {
                tip: expected_tip,
                utxo: None,
            });
        };
        let tip = neutral_tip(response.tip)?;
        if tip != expected_tip {
            return Err(ChainClientError::stale_tip(expected_tip, tip));
        }
        let box_info = response.box_info;
        if box_info.box_id != hex::encode(box_id) {
            return Err(ChainClientError::Protocol(
                "box lookup returned a different box id".to_string(),
            ));
        }
        Ok(UtxoLookup {
            tip,
            utxo: Some(neutral_box(box_info)?),
        })
    }

    fn submit(&self, _request: SubmitRequest) -> Result<SubmitResponse, ChainClientError> {
        Err(ChainClientError::Unsupported)
    }
}

fn map_transport_error(error: reqwest::Error) -> ChainClientError {
    if error.is_timeout() {
        ChainClientError::Timeout("chain request timed out".to_string())
    } else {
        ChainClientError::Transport("chain request failed".to_string())
    }
}

/// Why a response body could not be used. Kept distinct from
/// `ChainClientError` so each caller can report the failure in terms of what it
/// asked for — a `blocks-since` page names its page size, everything else does
/// not — without the two call sites having to recognise each other's message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyError {
    /// The body was larger than the cap. Terminal for every caller: a smaller
    /// request is the only fix and the daemon does not make one on its own.
    TooLarge { limit: usize },
    /// The connection ended before the body was complete.
    Incomplete,
}

impl From<BodyError> for ChainClientError {
    fn from(error: BodyError) -> Self {
        match error {
            BodyError::TooLarge { limit } => {
                Self::Protocol(format!("chain response body exceeds the {limit}-byte cap"))
            }
            BodyError::Incomplete => Self::Transport("chain response read failed".to_string()),
        }
    }
}

/// Read at most `limit` bytes, from the declared `Content-Length` when there is
/// one and from the stream itself otherwise, so a lying or absent length
/// cannot get past the cap.
fn read_body(response: Response, limit: usize) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BodyError::TooLarge { limit });
    }
    let mut body = Vec::new();
    response
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| BodyError::Incomplete)?;
    if body.len() > limit {
        return Err(BodyError::TooLarge { limit });
    }
    Ok(body)
}

/// Body fetch for one `blocks-since` page: the same ceiling as every other
/// endpoint, reported in terms of the page.
///
/// The message names both numbers on purpose. The sync loop bounds a page by
/// block count (`crate::sync::DEFAULT_BLOCKS_PER_PAGE`) and this cap bounds it
/// by bytes; when the bytes run out first the page size has already been
/// applied, so the only remaining explanation is a block larger than the cap —
/// which the daemon cannot fetch, because it never shrinks a page. Naming the
/// cap and the page turns that into an operator-actionable terminal error
/// instead of an anonymous "body too large".
fn read_page(response: Response, limit: usize, blocks: u32) -> Result<Vec<u8>, ChainClientError> {
    read_body(response, limit).map_err(|error| match error {
        BodyError::TooLarge { limit } => ChainClientError::Protocol(format!(
            "a {blocks}-block page does not fit the {limit}-byte response cap; the daemon does \
             not retry with a smaller page, so a single block larger than the cap is terminal"
        )),
        other => other.into(),
    })
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ChainClientError> {
    serde_json::from_slice(body)
        .map_err(|_| ChainClientError::Protocol("invalid chain JSON response".to_string()))
}

fn decode_id(value: &str, field: &str) -> Result<[u8; 32], ChainClientError> {
    wire::validate_id32(value, field)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))?;
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            ChainClientError::Protocol(format!("invalid {field} length in chain response"))
        })
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, ChainClientError> {
    wire::validate_hex_bytes(value, field)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))?;
    hex::decode(value)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))
}

fn canonical_box(
    bytes: &[u8],
    field: &str,
) -> Result<ergo_ser::ergo_box::ErgoBox, ChainClientError> {
    if bytes.is_empty() {
        return Err(ChainClientError::Protocol(format!("{field} are empty")));
    }
    let mut reader = VlqReader::new(bytes);
    let ergo_box = read_ergo_box(&mut reader)
        .map_err(|_| ChainClientError::Protocol(format!("invalid {field} in chain response")))?;
    if !reader.is_empty() {
        return Err(ChainClientError::Protocol(format!(
            "{field} have trailing data"
        )));
    }
    let canonical = serialize_ergo_box(&ergo_box)
        .map_err(|_| ChainClientError::Protocol(format!("cannot canonicalize {field}")))?;
    if canonical != bytes {
        return Err(ChainClientError::Protocol(format!(
            "{field} are not canonical ErgoBox bytes"
        )));
    }
    Ok(ergo_box)
}

fn box_assets_match(ergo_box: &ergo_ser::ergo_box::ErgoBox, right: &[([u8; 32], u64)]) -> bool {
    ergo_box.candidate.tokens.len() == right.len()
        && ergo_box
            .candidate
            .tokens
            .iter()
            .zip(right)
            .all(|(token, (token_id, amount))| {
                *token.token_id.as_bytes() == *token_id && token.amount == *amount
            })
}

fn neutral_tip(tip: wire::ChainTip) -> Result<CommittedTip, ChainClientError> {
    let header_id = decode_id(&tip.header_id, "header_id")?;
    if tip.height > 0 && header_id == [0; 32] {
        return Err(ChainClientError::Protocol(
            "positive-height tip has a zero header id".to_string(),
        ));
    }
    Ok(CommittedTip::new(tip.height, header_id))
}

fn neutral_snapshot(snapshot: wire::ChainSnapshot) -> Result<ChainSnapshot, ChainClientError> {
    if !snapshot.active_parameters.is_object() {
        return Err(ChainClientError::Protocol(
            "snapshot active parameters must be an object".to_string(),
        ));
    }
    let tip = neutral_tip(snapshot.tip)?;
    let mut headers = Vec::with_capacity(snapshot.headers.len());
    let mut ids = std::collections::BTreeSet::new();
    let mut previous: Option<ergo_wallet_service::ChainHeader> = None;
    for header in snapshot.headers {
        let header_id = decode_id(&header.header_id, "header_id")?;
        let parent_id = decode_id(&header.parent_id, "parent_id")?;
        if header.height > 0 && header_id == [0; 32] {
            return Err(ChainClientError::Protocol(
                "positive-height snapshot header has a zero id".to_string(),
            ));
        }
        if !ids.insert(header_id) {
            return Err(ChainClientError::Protocol(
                "snapshot contains duplicate headers".to_string(),
            ));
        }
        if let Some(previous) = &previous {
            if header.height != previous.height.saturating_add(1) {
                return Err(ChainClientError::Protocol(
                    "snapshot headers are not height-contiguous".to_string(),
                ));
            }
            if parent_id != previous.header_id {
                return Err(ChainClientError::Protocol(
                    "snapshot header parent continuity is invalid".to_string(),
                ));
            }
        }
        let value = ergo_wallet_service::ChainHeader {
            height: header.height,
            header_id,
            parent_id,
            timestamp_unix_ms: header.timestamp_unix_ms,
        };
        previous = Some(value.clone());
        headers.push(value);
    }
    if let Some(last) = headers.last() {
        if last.height == tip.height && last.header_id != tip.header_id {
            return Err(ChainClientError::Protocol(
                "snapshot tip does not match its last header".to_string(),
            ));
        }
    }
    let reemission_inputs = snapshot
        .reemission_inputs
        .into_iter()
        .map(|input| {
            Ok(ReemissionInput {
                token_id: decode_id(&input.token_id, "token_id")?,
                amount: input.amount.parse::<u64>().map_err(|_| {
                    ChainClientError::Protocol("invalid reemission amount".to_string())
                })?,
                box_ids: input
                    .box_ids
                    .unwrap_or_default()
                    .into_iter()
                    .map(|id| decode_id(&id, "box_id"))
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect::<Result<Vec<_>, ChainClientError>>()?;
    let snapshot_id = decode_id(&snapshot.snapshot_id, "snapshot_id")?;
    if snapshot_id == [0; 32] || snapshot_id == [0xff; 32] {
        return Err(ChainClientError::Protocol(
            "snapshot_id is reserved".to_string(),
        ));
    }
    Ok(ChainSnapshot {
        tip,
        headers,
        active_parameters: snapshot.active_parameters,
        reemission_inputs,
        snapshot_id,
    })
}

fn neutral_box(box_info: wire::ChainBox) -> Result<ChainBox, ChainClientError> {
    let bytes = decode_hex(&box_info.bytes, "box bytes")?;
    let parsed = canonical_box(&bytes, "box bytes")?;
    let box_id = decode_id(&box_info.box_id, "box_id")?;
    let computed_id = parsed
        .box_id()
        .map_err(|_| ChainClientError::Protocol("cannot compute box id".to_string()))?;
    if *computed_id.as_bytes() != box_id {
        return Err(ChainClientError::Protocol(
            "box id does not match canonical box bytes".to_string(),
        ));
    }
    let creation_tx_id = decode_id(&box_info.creation_tx_id, "creation_tx_id")?;
    if parsed.transaction_id.as_bytes() != &creation_tx_id {
        return Err(ChainClientError::Protocol(
            "box transaction id does not match canonical box bytes".to_string(),
        ));
    }
    if parsed.index != box_info.creation_output_index {
        return Err(ChainClientError::Protocol(
            "box output index does not match canonical box bytes".to_string(),
        ));
    }
    if parsed.candidate.value != box_info.value {
        return Err(ChainClientError::Protocol(
            "box value does not match canonical box bytes".to_string(),
        ));
    }
    let assets: Vec<([u8; 32], u64)> = box_info
        .assets
        .into_iter()
        .map(|asset| {
            Ok((
                decode_id(&asset.token_id, "token_id")?,
                asset
                    .amount
                    .parse::<u64>()
                    .map_err(|_| ChainClientError::Protocol("invalid asset amount".to_string()))?,
            ))
        })
        .collect::<Result<Vec<_>, ChainClientError>>()?;
    if !box_assets_match(&parsed, &assets) {
        return Err(ChainClientError::Protocol(
            "box assets do not match canonical box bytes".to_string(),
        ));
    }
    if parsed.candidate.creation_height != box_info.creation_height {
        return Err(ChainClientError::Protocol(
            "box creation height does not match canonical box bytes".to_string(),
        ));
    }
    Ok(ChainBox {
        box_id,
        bytes,
        value: box_info.value,
        assets: assets
            .into_iter()
            .map(|(token_id, amount)| ergo_wallet_service::chain::ChainAsset { token_id, amount })
            .collect(),
        creation_tx_id,
        creation_output_index: box_info.creation_output_index,
        creation_height: box_info.creation_height,
    })
}

fn neutral_block(block: wire::ChainBlock) -> Result<ChainBlock, ChainClientError> {
    let block_id = decode_id(&block.block_id, "block_id")?;
    if block.height > 0 && block_id == [0; 32] {
        return Err(ChainClientError::Protocol(
            "positive-height block has a zero block id".to_string(),
        ));
    }
    let parent_id = decode_id(&block.parent_id, "parent_id")?;
    let mut tx_ids = std::collections::BTreeSet::new();
    let mut block_box_ids = std::collections::BTreeSet::new();
    let mut transactions = Vec::with_capacity(block.transactions.len());
    for transaction in block.transactions {
        let tx_id = decode_id(&transaction.tx_id, "tx_id")?;
        if !tx_ids.insert(tx_id) {
            return Err(ChainClientError::Protocol(
                "block contains duplicate transactions".to_string(),
            ));
        }
        let mut inputs = Vec::with_capacity(transaction.inputs.len());
        for (position, input) in transaction.inputs.into_iter().enumerate() {
            if input.index as usize != position {
                return Err(ChainClientError::Protocol(
                    "transaction input indices are not contiguous".to_string(),
                ));
            }
            inputs.push(ChainInput {
                box_id: decode_id(&input.box_id, "input box_id")?,
                index: input.index,
            });
        }
        let mut outputs = Vec::with_capacity(transaction.outputs.len());
        for (position, output) in transaction.outputs.into_iter().enumerate() {
            if output.index as usize != position {
                return Err(ChainClientError::Protocol(
                    "transaction output indices are not contiguous".to_string(),
                ));
            }
            let bytes = decode_hex(&output.bytes, "output bytes")?;
            let parsed = canonical_box(&bytes, "output bytes")?;
            let output_id = decode_id(&output.box_id, "output box_id")?;
            let computed_id = parsed.box_id().map_err(|_| {
                ChainClientError::Protocol("cannot compute output box id".to_string())
            })?;
            if *computed_id.as_bytes() != output_id
                || parsed.transaction_id.as_bytes() != &tx_id
                || parsed.index != output.index
            {
                return Err(ChainClientError::Protocol(format!(
                    "chain output identity mismatch at {}:{}",
                    hex::encode(tx_id),
                    output.index
                )));
            }
            if !block_box_ids.insert(output_id) {
                return Err(ChainClientError::Protocol(
                    "block contains duplicate output boxes".to_string(),
                ));
            }
            outputs.push(ChainOutput {
                box_id: output_id,
                index: output.index,
                bytes,
            });
        }
        transactions.push(ChainTransaction {
            tx_id,
            inputs,
            outputs,
        });
    }
    Ok(ChainBlock {
        block_id,
        height: block.height,
        parent_id,
        transactions,
    })
}

fn neutral_blocks_since(
    response: wire::BlocksSinceResponse,
    cursor: ergo_wallet_service::ChainCursor,
    limit: u32,
) -> Result<ergo_wallet_service::BlocksSinceResponse, ChainClientError> {
    match response {
        wire::BlocksSinceResponse::Forward(forward) => {
            let tip = neutral_tip(forward.tip)?;
            if tip.height < cursor.height {
                return Err(ChainClientError::Protocol(
                    "chain response tip is behind the requested cursor".to_string(),
                ));
            }
            if forward.blocks.len() > limit as usize || forward.blocks.len() > 1024 {
                return Err(ChainClientError::Protocol(
                    "chain returned more blocks than requested".to_string(),
                ));
            }
            let mut expected_height = cursor.height.saturating_add(1);
            let mut expected_parent = (cursor.height > 0).then_some(cursor.header_id);
            let mut block_ids = std::collections::BTreeSet::new();
            let mut blocks = Vec::with_capacity(forward.blocks.len());
            for block in forward.blocks {
                let block = neutral_block(block)?;
                if block.height != expected_height {
                    return Err(ChainClientError::Protocol(format!(
                        "chain block height {} does not match expected {expected_height}",
                        block.height
                    )));
                }
                if !block_ids.insert(block.block_id) {
                    return Err(ChainClientError::Protocol(
                        "chain page contains duplicate block ids".to_string(),
                    ));
                }
                if expected_parent.is_some_and(|parent| block.parent_id != parent) {
                    return Err(ChainClientError::Protocol(
                        "chain block parent continuity is invalid".to_string(),
                    ));
                }
                expected_parent = Some(block.block_id);
                expected_height = expected_height.saturating_add(1);
                blocks.push(block);
            }
            if let Some(last) = blocks.last() {
                if last.height == tip.height && last.block_id != tip.header_id {
                    return Err(ChainClientError::Protocol(
                        "chain page tip block id does not match the response tip".to_string(),
                    ));
                }
            } else if cursor.height == tip.height && cursor.header_id != tip.header_id {
                return Err(ChainClientError::Protocol(
                    "empty chain page does not match the response tip".to_string(),
                ));
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Forward(
                ergo_wallet_service::ForwardBlocksSince { tip, blocks },
            ))
        }
        wire::BlocksSinceResponse::Ancestor(ancestor) => {
            let tip = neutral_tip(ancestor.tip)?;
            let ancestor_id = decode_id(&ancestor.ancestor.header_id, "ancestor header_id")?;
            if ancestor.ancestor.height > tip.height {
                return Err(ChainClientError::Protocol(
                    "chain ancestor is ahead of its tip".to_string(),
                ));
            }
            if ancestor.ancestor.height == 0 && ancestor_id != [0; 32] {
                return Err(ChainClientError::Protocol(
                    "genesis ancestor must use the genesis cursor id".to_string(),
                ));
            }
            if ancestor.ancestor.height > 0 && ancestor_id == [0; 32] {
                return Err(ChainClientError::Protocol(
                    "positive-height ancestor has a zero header id".to_string(),
                ));
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Ancestor(
                ergo_wallet_service::AncestorBlocksSince {
                    tip,
                    ancestor: ergo_wallet_service::ChainCursor {
                        height: ancestor.ancestor.height,
                        header_id: ancestor_id,
                    },
                },
            ))
        }
        wire::BlocksSinceResponse::Pruned(pruned) => {
            let tip = neutral_tip(pruned.tip)?;
            if pruned.minimum_height > tip.height {
                return Err(ChainClientError::Protocol(
                    "pruned floor is above the chain tip".to_string(),
                ));
            }
            Ok(ergo_wallet_service::BlocksSinceResponse::Pruned(
                ergo_wallet_service::PrunedBlocksSince {
                    tip,
                    minimum_height: pruned.minimum_height,
                },
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::ErgoTree;
    use ergo_ser::opcode::Expr;
    use ergo_ser::register::AdditionalRegisters;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn sample_box(tx_id: [u8; 32], index: u16) -> (Vec<u8>, [u8; 32]) {
        let tree = ErgoTree {
            version: 0,
            has_size: true,
            constant_segregation: true,
            constants: vec![(SigmaType::SBoolean, SigmaValue::Boolean(true))],
            body: Expr::Const {
                tpe: SigmaType::SBoolean,
                val: SigmaValue::Boolean(true),
            },
        };
        let candidate = ErgoBoxCandidate::new(1, tree, 1, Vec::new(), AdditionalRegisters::empty())
            .expect("valid test box");
        let ergo_box = ErgoBox {
            candidate,
            transaction_id: ModifierId::from_bytes(tx_id),
            index,
        };
        let box_id = *ergo_box.box_id().expect("valid test box id").as_bytes();
        (
            serialize_ergo_box(&ergo_box).expect("serializable test box"),
            box_id,
        )
    }

    fn serve_once<F>(handler: F) -> (String, thread::JoinHandle<()>)
    where
        F: FnOnce(&str, &str) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 4096];
            let count = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..count]);
            let mut lines = request.lines();
            let first = lines.next().unwrap_or_default().to_string();
            let path = first
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();
            let header = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("api_key:"))
                .unwrap_or_default()
                .to_string();
            let body = handler(&path, &header);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/"), handle)
    }

    #[test]
    fn sends_api_key_and_rejects_unauthorized() {
        let (url, handle) = serve_once(|path, header| {
            assert!(path.starts_with("/api/v1/chain/tip"));
            assert!(header.to_ascii_lowercase().contains("secret"));
            format!(r#"{{"height":1,"headerId":"{}"}}"#, id(1))
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.committed_tip().unwrap().height, 1);
        handle.join().unwrap();
    }

    #[test]
    fn maps_status_codes_without_exposing_body() {
        for (status, expected) in [
            (401u16, "unauthorized"),
            (409, "conflict"),
            (503, "unavailable"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).unwrap();
                let body = "secret-value-that-must-not-escape";
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let client = HttpChainClient::with_timeouts(
                Url::parse(&format!("http://{address}/")).unwrap(),
                ApiKey::from_test(b"secret".to_vec()),
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .unwrap();
            let error = client.committed_tip().unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("secret-value"));
            handle.join().unwrap();
        }
    }

    #[test]
    fn parses_blocks_since_and_rejects_invalid_continuity() {
        let (url, handle) = serve_once(|path, _| {
            assert!(path.starts_with("/api/v1/chain/blocks-since"));
            format!(
                r#"{{"type":"forward","tip":{{"height":1,"headerId":"{}"}},"blocks":[{{"blockId":"{}","height":1,"parentId":"{}","transactions":[]}}]}}"#,
                id(1),
                id(1),
                id(0)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let response = client
            .blocks_since(ergo_wallet_service::BlocksSinceRequest {
                cursor: ergo_wallet_service::ChainCursor::genesis(),
                limit: 1,
            })
            .unwrap();
        assert!(matches!(
            response,
            ergo_wallet_service::BlocksSinceResponse::Forward(_)
        ));
        handle.join().unwrap();

        let (url, handle) = serve_once(|_, _| {
            format!(
                r#"{{"type":"forward","tip":{{"height":2,"headerId":"{}"}},"blocks":[{{"blockId":"{}","height":2,"parentId":"{}","transactions":[]}}]}}"#,
                id(2),
                id(2),
                id(1)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.blocks_since(ergo_wallet_service::BlocksSinceRequest {
                cursor: ergo_wallet_service::ChainCursor::genesis(),
                limit: 1,
            }),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();
    }

    #[test]
    fn parses_snapshot_and_box_lookup_and_submits_are_disabled() {
        let (url, handle) = serve_once(|path, _| {
            assert_eq!(path, "/api/v1/chain/snapshot");
            format!(
                r#"{{"tip":{{"height":1,"headerId":"{}"}},"headers":[],"activeParameters":{{}},"reemissionInputs":[],"snapshotId":"{}"}}"#,
                id(1),
                id(2)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(client.snapshot().unwrap().snapshot_id, [2; 32]);
        handle.join().unwrap();

        let (box_bytes, box_id) = sample_box([4; 32], 0);
        let (url, handle) = serve_once(move |path, _| {
            assert!(path.starts_with("/api/v1/chain/boxes/"));
            format!(
                r#"{{"tip":{{"height":1,"headerId":"{}"}},"box":{{"boxId":"{}","bytes":"{}","value":"1","assets":[],"creationTxId":"{}","creationOutputIndex":0,"creationHeight":1}}}}"#,
                id(1),
                hex::encode(box_id),
                hex::encode(&box_bytes),
                id(4)
            )
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        let lookup = client
            .lookup_utxo(box_id, CommittedTip::new(1, [1; 32]))
            .unwrap();
        assert_eq!(lookup.utxo.unwrap().box_id, box_id);
        assert!(matches!(
            client.submit(ergo_wallet_service::SubmitRequest {
                transaction: vec![1],
                snapshot_id: None,
            }),
            Err(ChainClientError::Unsupported)
        ));
        handle.join().unwrap();
    }

    #[test]
    fn rejects_malformed_and_oversized_responses() {
        let (url, handle) = serve_once(|_, _| "not-json".to_string());
        let client = HttpChainClient::with_timeouts(
            Url::parse(&url).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.committed_tip(),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            let body = "x".repeat(9 * 1024 * 1024);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&format!("http://{address}/")).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.committed_tip(),
            Err(ChainClientError::Protocol(_))
        ));
        handle.join().unwrap();
    }

    /// A `blocks-since` body over the cap is reported in terms of the page: the
    /// error names the cap *and* the page size, and states that no smaller page
    /// will be tried, because that is the whole operator-facing content of the
    /// failure. A generic "body too large" would leave them guessing.
    #[test]
    fn an_oversized_page_names_the_cap_the_page_and_the_no_smaller_page_rule() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            // No `Content-Length`: the cap has to hold from the stream alone,
            // which is the case a chunked node response would take.
            let body = "x".repeat(9 * 1024 * 1024);
            let response = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}");
            let _ = stream.write_all(response.as_bytes());
        });
        let client = HttpChainClient::with_timeouts(
            Url::parse(&format!("http://{address}/")).unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .unwrap();
        let error = client
            .blocks_since(ergo_wallet_service::BlocksSinceRequest {
                cursor: ergo_wallet_service::ChainCursor::genesis(),
                limit: 1,
            })
            .unwrap_err()
            .to_string();
        handle.join().unwrap();
        assert!(
            error.contains(&MAX_RESPONSE_BODY_BYTES.to_string()),
            "{error}"
        );
        assert!(error.contains("1-block page"), "{error}");
        assert!(
            error.contains("does not retry with a smaller page"),
            "{error}"
        );
    }

    // ----- construction context -----

    /// `reqwest::blocking` drops a shell Tokio runtime *while it is entered*
    /// inside `ClientBuilder::build`, and Tokio aborts when a runtime is dropped
    /// from a thread inside an async context. So a `#[tokio::test]` body (or an
    /// `async fn`, or anything under `#[tokio::main]`) must not call the
    /// blocking constructor. This pins the supported escape hatch: hand the
    /// build to the runtime's blocking pool, which is not an async context.
    #[tokio::test]
    async fn new_in_runtime_builds_the_client_from_a_blocking_pool_thread() {
        let client = HttpChainClient::new_in_runtime(
            Url::parse("http://127.0.0.1:1/").unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
        )
        .await
        .expect("the blocking pool is not inside an async context");
        assert_eq!(client.base_url().as_str(), "http://127.0.0.1:1/");
        // The finished client is `Send + Sync`, so it can be handed to the
        // daemon's blocking sync loop exactly like one built by `prepare`.
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&client);

        let client = HttpChainClient::with_timeouts_in_runtime(
            Url::parse("http://127.0.0.1:1").unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .expect("the timeout variant takes the same path");
        // The trailing slash is still normalised on the blocking-pool path.
        assert_eq!(client.base_url().as_str(), "http://127.0.0.1:1/");
    }

    /// The blocking constructor is the one `prepare` uses, and a plain `#[test]`
    /// body is not inside an async context — so it must build cleanly. Together
    /// with `new_in_runtime` above this pins both halves of the invariant that
    /// `main` relies on: build before the runtime, or build on the blocking pool.
    #[test]
    fn blocking_constructor_builds_outside_a_runtime() {
        let client = HttpChainClient::new(
            Url::parse("http://127.0.0.1:1").unwrap(),
            ApiKey::from_test(b"secret".to_vec()),
        )
        .expect("a plain test thread is not inside an async context");
        assert_eq!(client.base_url().as_str(), "http://127.0.0.1:1/");
        // The key never appears in a log line.
        let debug = format!("{client:?}");
        assert!(
            !debug.contains("secret"),
            "the api key must be redacted: {debug}"
        );
        assert!(debug.contains("[REDACTED]"), "{debug}");
    }
}

//! The v1 nested error envelope + the canonical machine-readable `reason`
//! enum.
//!
//! Implements `v1-api-design.md` §1.3 (envelope family) and §1.4 (the
//! canonical error `reason` enum, adopted verbatim from the coherence pass
//! Part A). Every future `/api/v1/*` endpoint draws its error reasons from
//! this ONE enum and emits errors through [`v1_error`] — there is no
//! per-group error shape and no per-group reason spelling.
//!
//! Wire shape (machine-first — a client switches on `reason`, `message` is
//! human, `detail` is actionable):
//! ```json
//! { "error": { "reason": "indexer_disabled",
//!              "message": "box-by-address queries require the indexer",
//!              "detail":  "start the node with [indexer] enabled = true" } }
//! ```
//!
//! This replaces the frozen compat shapes (`utils.rs` flat
//! `{error:400,reason:"bad-request",detail}`, `types.rs`
//! `ApiNativeSubmitError{reason,detail}` with no `message`). Those stay
//! untouched; v1 is a parallel, additive surface.
//!
//! **Status mapping (§1.4):** derived solely from the `reason` so a client
//! can also switch on HTTP status consistently. The suffix rules
//! (`*_not_found`→404, `invalid_*`→400, `*_disabled`→409, `*_unavailable`
//! →503, …) hold except where §1.4/§1.6 explicitly override a member
//! (documented at each override arm below).

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Canonical machine-readable error reason (`v1-api-design.md` §1.4;
/// coherence Part A). Serialized as `lowercase_snake_case`; the string is a
/// **stable enum a client switches on** — treat additions as an open set
/// (§1.6), never rename an existing variant inside v1.
///
/// One spelling per concept: typed `<resource>_not_found` (never bare
/// `not_found`), `invalid_<thing>` (never `bad_<thing>`), `<subsystem>_disabled`
/// (409, config-off), `<thing>_unavailable` (503, transient). The frozen
/// tx/submit bare verbs (`deserialize`, `non_canonical`, …) are kept as-is
/// because `server::map_submit_error` already emits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reason {
    // ----- not found (real 404) -----
    BoxNotFound,
    TxNotFound,
    TokenNotFound,
    HeaderNotFound,
    BlockNotFound,
    ScanNotFound,
    ProtocolNotFound,
    WebhookNotFound,
    AccountNotFound,
    AddressNotWatched,
    TxNotInBlock,
    NotBlacklisted,
    NotASingletonProtocol,

    // ----- invalid input (400) -----
    BadRequest,
    InvalidAddress,
    InvalidErgoTree,
    InvalidBoxId,
    InvalidTokenId,
    InvalidTxId,
    InvalidHex,
    InvalidBase58,
    InvalidParams,
    InvalidRange,
    InvalidSelector,
    InvalidSortDirection,
    InvalidBoxBytes,
    InvalidSeedLength,
    InvalidPow,
    /// Tamper / stale / malformed pagination cursor (`v1-api-design.md`
    /// §1.5). Added to the canonical set because §1.5 names it explicitly
    /// and it obeys naming rule 2 (`invalid_<thing>`).
    InvalidCursor,
    AddressTooShort,
    BadChecksum,
    NetworkMismatch,
    UnsupportedAddressType,
    BadPubkeyLength,
    BadEncoding,
    UnsupportedHashAlgo,
    /// Well-formed but not-yet-supported tx intent. Maps to **422**, not
    /// 400: §1.6 blesses a documented `unsupported_intent` shape flipping
    /// 422→200 additively as new intents ship.
    UnsupportedIntent,
    NotHotReloadable,
    NotVotable,
    OutOfRange,
    UnknownKind,
    UnknownOp,
    EmptyBatch,
    BinaryUnsupported,
    InsecureUrl,
    ForbiddenTarget,

    // ----- tx/submit domain (frozen bare verbs — `map_submit_error`) -----
    Deserialize,
    NonCanonical,
    DoubleSpend,
    InsufficientFee,
    TooBig,
    Invalid,
    InsufficientFunds,
    NoInputsFound,
    DustChange,
    StaleCandidate,
    ForcedTxExceedsBudget,
    InsufficientSignatures,
    ScriptError,
    UnresolvedInput,
    CostLimit,
    TooDeep,

    // ----- subsystem-off (409, `_disabled`) -----
    IndexerDisabled,
    IndexerSyncing,
    IndexerHalted,
    SubmitDisabled,
    MempoolViewDisabled,
    RealtimeDisabled,
    WebhooksDisabled,
    SnapshotDisabled,
    MiningDisabled,
    SensitiveOpDisabled,

    // ----- transiently-unavailable (503, `_unavailable`) -----
    ChainReaderUnavailable,
    ChainParamsUnavailable,
    VotedParamsUnavailable,
    StateUnavailable,
    NipopowUnavailable,
    AdProofsUnavailable,
    ChannelUnavailable,
    CandidateUnavailable,
    RewardUnavailable,
    BlockPruned,
    /// Built-without / not-configured (§1.4 note): keeps the `_unavailable`
    /// spelling the script group chose but is semantically subsystem-off →
    /// **501 Not Implemented**, not 503.
    CompilerUnavailable,
    /// Built-without / not-configured (§1.4 note): `_unavailable` spelling,
    /// **501 Not Implemented** status. See [`Reason::CompilerUnavailable`].
    OracleUnavailable,
    Overloaded,
    ShuttingDown,
    /// A route/bridge is not wired in this build/deployment (operationally
    /// **unavailable**, not a config-off subsystem). Uses the `_unavailable`
    /// spelling so the suffix rule (`*_unavailable`→503) and the status agree,
    /// mirroring the frozen compat `route_disabled`→503 mapping in
    /// `server::map_submit_error`.
    RouteUnavailable,
    /// Upstream/handler timeout. Maps to **504 Gateway Timeout** to mirror
    /// the frozen `server::map_submit_error` mapping for the same reason.
    Timeout,

    // ----- auth / tier -----
    Unauthorized,
    WrongPassword,
    WalletUninitialized,
    MissingSecret,
    AcknowledgementRequired,
    SecretNotRecoverable,
    ChangeAddressUntracked,

    // ----- caps / rate (429 / 413) -----
    RateLimited,
    LimitExceeded,
    BatchTooLarge,
    TooManyIds,
    IntentTooLarge,
    QueryTooComplex,
    ProofTooLarge,
    TokenTooLarge,
    ChannelLimit,
    ConnectionLimit,
    WebhookLimit,
    TooManySessions,
    SlowConsumer,
    IdleTimeout,

    // ----- state-conflict (409) / internal (500) -----
    AlreadyBlacklisted,
    InternalError,
}

impl Reason {
    /// HTTP status for this reason (`v1-api-design.md` §1.4). Pure function
    /// of the reason so status and `reason` never disagree. Overrides of the
    /// mechanical suffix rule are documented on the variants and grouped
    /// explicitly below.
    pub fn http_status(self) -> StatusCode {
        use Reason::*;
        match self {
            // 404 — real not-found
            BoxNotFound
            | TxNotFound
            | TokenNotFound
            | HeaderNotFound
            | BlockNotFound
            | ScanNotFound
            | ProtocolNotFound
            | WebhookNotFound
            | AccountNotFound
            | AddressNotWatched
            | TxNotInBlock
            | NotBlacklisted
            | NotASingletonProtocol => StatusCode::NOT_FOUND,

            // 400 — invalid input + the frozen submit-domain bare verbs
            // (`map_submit_error` maps every submit verb except the transient
            // few to 400 — mirrored here).
            BadRequest
            | InvalidAddress
            | InvalidErgoTree
            | InvalidBoxId
            | InvalidTokenId
            | InvalidTxId
            | InvalidHex
            | InvalidBase58
            | InvalidParams
            | InvalidRange
            | InvalidSelector
            | InvalidSortDirection
            | InvalidBoxBytes
            | InvalidSeedLength
            | InvalidPow
            | InvalidCursor
            | AddressTooShort
            | BadChecksum
            | NetworkMismatch
            | UnsupportedAddressType
            | BadPubkeyLength
            | BadEncoding
            | UnsupportedHashAlgo
            | NotHotReloadable
            | NotVotable
            | OutOfRange
            | UnknownKind
            | UnknownOp
            | EmptyBatch
            | BinaryUnsupported
            | InsecureUrl
            | ForbiddenTarget
            | Deserialize
            | NonCanonical
            | DoubleSpend
            | InsufficientFee
            | TooBig
            | Invalid
            | InsufficientFunds
            | NoInputsFound
            | DustChange
            | StaleCandidate
            | ForcedTxExceedsBudget
            | InsufficientSignatures
            | ScriptError
            | UnresolvedInput
            | CostLimit
            | TooDeep => StatusCode::BAD_REQUEST,

            // 422 — well-formed but unsupported intent (§1.6 additive path)
            UnsupportedIntent => StatusCode::UNPROCESSABLE_ENTITY,

            // 409 — subsystem-off (config) + state-conflict
            IndexerDisabled | IndexerSyncing | IndexerHalted | SubmitDisabled
            | MempoolViewDisabled | RealtimeDisabled | WebhooksDisabled | SnapshotDisabled
            | MiningDisabled | SensitiveOpDisabled | AlreadyBlacklisted => StatusCode::CONFLICT,

            // 501 — built-without / not-configured (§1.4 note)
            CompilerUnavailable | OracleUnavailable => StatusCode::NOT_IMPLEMENTED,

            // 504 — timeout (frozen `map_submit_error` parity)
            Timeout => StatusCode::GATEWAY_TIMEOUT,

            // 503 — transiently unavailable
            ChainReaderUnavailable
            | ChainParamsUnavailable
            | VotedParamsUnavailable
            | StateUnavailable
            | NipopowUnavailable
            | AdProofsUnavailable
            | ChannelUnavailable
            | CandidateUnavailable
            | RewardUnavailable
            | BlockPruned
            | Overloaded
            | ShuttingDown
            | RouteUnavailable => StatusCode::SERVICE_UNAVAILABLE,

            // 401 — authentication required / wrong credential
            Unauthorized | WrongPassword => StatusCode::UNAUTHORIZED,

            // 409 — auth-adjacent precondition/state
            WalletUninitialized
            | MissingSecret
            | AcknowledgementRequired
            | SecretNotRecoverable
            | ChangeAddressUntracked => StatusCode::CONFLICT,

            // 429 — too many requests / resources
            RateLimited | LimitExceeded | ChannelLimit | ConnectionLimit | WebhookLimit
            | TooManySessions | SlowConsumer => StatusCode::TOO_MANY_REQUESTS,

            // 408 — idle client timeout (control-plane)
            IdleTimeout => StatusCode::REQUEST_TIMEOUT,

            // 413 — payload / complexity too large
            BatchTooLarge | TooManyIds | IntentTooLarge | QueryTooComplex | ProofTooLarge
            | TokenTooLarge => StatusCode::PAYLOAD_TOO_LARGE,

            // 500 — internal
            InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Inner object of the v1 error envelope (`v1-api-design.md` §1.3).
#[derive(Debug, Clone, Serialize)]
pub struct V1ErrorInner {
    /// Stable machine-readable enum a client switches on.
    pub reason: Reason,
    /// Human-readable one-liner.
    pub message: String,
    /// Actionable remediation hint (may be empty when none applies).
    pub detail: String,
}

/// The v1 error envelope: `{ "error": { reason, message, detail } }`
/// (`v1-api-design.md` §1.3). Carries its own HTTP status via the `reason`.
///
/// Prefer returning `Result<T, V1Error>` from a handler and `?`-ing the
/// error path; [`IntoResponse`] renders the envelope with the correct
/// status. [`v1_error`] is the free-function form for inline early returns.
#[derive(Debug, Clone, Serialize)]
pub struct V1Error {
    /// The single `error` key holding the machine/human/actionable triple.
    pub error: V1ErrorInner,
}

impl V1Error {
    /// Construct a v1 error from a `reason`, human `message`, and actionable
    /// `detail`. The HTTP status is derived from the `reason`
    /// ([`Reason::http_status`]).
    pub fn new(reason: Reason, message: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            error: V1ErrorInner {
                reason,
                message: message.into(),
                detail: detail.into(),
            },
        }
    }

    /// The HTTP status this envelope renders with.
    pub fn status(&self) -> StatusCode {
        self.error.reason.http_status()
    }
}

impl IntoResponse for V1Error {
    fn into_response(self) -> Response {
        (self.status(), Json(self)).into_response()
    }
}

/// Build a v1 error [`Response`] from a `reason`, human `message`, and
/// actionable `detail` (`v1-api-design.md` §1.3–§1.4). The HTTP status is
/// derived from the `reason`. This is the ONE error helper every v1 endpoint
/// group uses — never a bare `StatusCode::NOT_FOUND` and never a bare 404 for
/// "subsystem off" (a disabled subsystem answers its `*_disabled` reason so
/// clients distinguish *gone* from *disabled*).
pub fn v1_error(reason: Reason, message: impl Into<String>, detail: impl Into<String>) -> Response {
    V1Error::new(reason, message, detail).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use serde_json::Value;

    // ----- helpers -----

    /// Serialize a `Reason` to its wire string via serde (the same path the
    /// envelope uses). This is the contract clients switch on.
    fn wire(reason: Reason) -> String {
        match serde_json::to_value(reason).expect("reason serializes") {
            Value::String(s) => s,
            other => panic!("reason must serialize to a string, got {other:?}"),
        }
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("body is json")
    }

    /// The canonical (reason → exact wire string, exact HTTP status) table.
    /// This IS the product contract from `v1-api-design.md` §1.4 — the spec
    /// is the oracle. Any serde-snake-case drift or status regression fails
    /// here loudly. 111 variants = the 110 canonical Part-A reasons + the
    /// `invalid_cursor` §1.5 addition.
    fn contract() -> Vec<(Reason, &'static str, StatusCode)> {
        use Reason::*;
        let nf = StatusCode::NOT_FOUND;
        let br = StatusCode::BAD_REQUEST;
        let cf = StatusCode::CONFLICT;
        let su = StatusCode::SERVICE_UNAVAILABLE;
        let rl = StatusCode::TOO_MANY_REQUESTS;
        let pl = StatusCode::PAYLOAD_TOO_LARGE;
        let ua = StatusCode::UNAUTHORIZED;
        vec![
            // not-found (404)
            (BoxNotFound, "box_not_found", nf),
            (TxNotFound, "tx_not_found", nf),
            (TokenNotFound, "token_not_found", nf),
            (HeaderNotFound, "header_not_found", nf),
            (BlockNotFound, "block_not_found", nf),
            (ScanNotFound, "scan_not_found", nf),
            (ProtocolNotFound, "protocol_not_found", nf),
            (WebhookNotFound, "webhook_not_found", nf),
            (AccountNotFound, "account_not_found", nf),
            (AddressNotWatched, "address_not_watched", nf),
            (TxNotInBlock, "tx_not_in_block", nf),
            (NotBlacklisted, "not_blacklisted", nf),
            (NotASingletonProtocol, "not_a_singleton_protocol", nf),
            // invalid input (400)
            (BadRequest, "bad_request", br),
            (InvalidAddress, "invalid_address", br),
            (InvalidErgoTree, "invalid_ergo_tree", br),
            (InvalidBoxId, "invalid_box_id", br),
            (InvalidTokenId, "invalid_token_id", br),
            (InvalidTxId, "invalid_tx_id", br),
            (InvalidHex, "invalid_hex", br),
            (InvalidBase58, "invalid_base58", br),
            (InvalidParams, "invalid_params", br),
            (InvalidRange, "invalid_range", br),
            (InvalidSelector, "invalid_selector", br),
            (InvalidSortDirection, "invalid_sort_direction", br),
            (InvalidBoxBytes, "invalid_box_bytes", br),
            (InvalidSeedLength, "invalid_seed_length", br),
            (InvalidPow, "invalid_pow", br),
            (InvalidCursor, "invalid_cursor", br),
            (AddressTooShort, "address_too_short", br),
            (BadChecksum, "bad_checksum", br),
            (NetworkMismatch, "network_mismatch", br),
            (UnsupportedAddressType, "unsupported_address_type", br),
            (BadPubkeyLength, "bad_pubkey_length", br),
            (BadEncoding, "bad_encoding", br),
            (UnsupportedHashAlgo, "unsupported_hash_algo", br),
            (NotHotReloadable, "not_hot_reloadable", br),
            (NotVotable, "not_votable", br),
            (OutOfRange, "out_of_range", br),
            (UnknownKind, "unknown_kind", br),
            (UnknownOp, "unknown_op", br),
            (EmptyBatch, "empty_batch", br),
            (BinaryUnsupported, "binary_unsupported", br),
            (InsecureUrl, "insecure_url", br),
            (ForbiddenTarget, "forbidden_target", br),
            // unsupported intent (422)
            (
                UnsupportedIntent,
                "unsupported_intent",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            // submit domain (400)
            (Deserialize, "deserialize", br),
            (NonCanonical, "non_canonical", br),
            (DoubleSpend, "double_spend", br),
            (InsufficientFee, "insufficient_fee", br),
            (TooBig, "too_big", br),
            (Invalid, "invalid", br),
            (InsufficientFunds, "insufficient_funds", br),
            (NoInputsFound, "no_inputs_found", br),
            (DustChange, "dust_change", br),
            (StaleCandidate, "stale_candidate", br),
            (ForcedTxExceedsBudget, "forced_tx_exceeds_budget", br),
            (InsufficientSignatures, "insufficient_signatures", br),
            (ScriptError, "script_error", br),
            (UnresolvedInput, "unresolved_input", br),
            (CostLimit, "cost_limit", br),
            (TooDeep, "too_deep", br),
            // subsystem-off (409)
            (IndexerDisabled, "indexer_disabled", cf),
            (IndexerSyncing, "indexer_syncing", cf),
            (IndexerHalted, "indexer_halted", cf),
            (SubmitDisabled, "submit_disabled", cf),
            (MempoolViewDisabled, "mempool_view_disabled", cf),
            (RealtimeDisabled, "realtime_disabled", cf),
            (WebhooksDisabled, "webhooks_disabled", cf),
            (SnapshotDisabled, "snapshot_disabled", cf),
            (MiningDisabled, "mining_disabled", cf),
            (SensitiveOpDisabled, "sensitive_op_disabled", cf),
            // transiently-unavailable (503) + 501/504 overrides
            (ChainReaderUnavailable, "chain_reader_unavailable", su),
            (ChainParamsUnavailable, "chain_params_unavailable", su),
            (VotedParamsUnavailable, "voted_params_unavailable", su),
            (StateUnavailable, "state_unavailable", su),
            (NipopowUnavailable, "nipopow_unavailable", su),
            (AdProofsUnavailable, "ad_proofs_unavailable", su),
            (ChannelUnavailable, "channel_unavailable", su),
            (CandidateUnavailable, "candidate_unavailable", su),
            (RewardUnavailable, "reward_unavailable", su),
            (BlockPruned, "block_pruned", su),
            (
                CompilerUnavailable,
                "compiler_unavailable",
                StatusCode::NOT_IMPLEMENTED,
            ),
            (
                OracleUnavailable,
                "oracle_unavailable",
                StatusCode::NOT_IMPLEMENTED,
            ),
            (Overloaded, "overloaded", su),
            (ShuttingDown, "shutting_down", su),
            (RouteUnavailable, "route_unavailable", su),
            (Timeout, "timeout", StatusCode::GATEWAY_TIMEOUT),
            // auth / tier
            (Unauthorized, "unauthorized", ua),
            (WrongPassword, "wrong_password", ua),
            (WalletUninitialized, "wallet_uninitialized", cf),
            (MissingSecret, "missing_secret", cf),
            (AcknowledgementRequired, "acknowledgement_required", cf),
            (SecretNotRecoverable, "secret_not_recoverable", cf),
            (ChangeAddressUntracked, "change_address_untracked", cf),
            // caps / rate
            (RateLimited, "rate_limited", rl),
            (LimitExceeded, "limit_exceeded", rl),
            (BatchTooLarge, "batch_too_large", pl),
            (TooManyIds, "too_many_ids", pl),
            (IntentTooLarge, "intent_too_large", pl),
            (QueryTooComplex, "query_too_complex", pl),
            (ProofTooLarge, "proof_too_large", pl),
            (TokenTooLarge, "token_too_large", pl),
            (ChannelLimit, "channel_limit", rl),
            (ConnectionLimit, "connection_limit", rl),
            (WebhookLimit, "webhook_limit", rl),
            (TooManySessions, "too_many_sessions", rl),
            (SlowConsumer, "slow_consumer", rl),
            (IdleTimeout, "idle_timeout", StatusCode::REQUEST_TIMEOUT),
            // state-conflict / internal
            (AlreadyBlacklisted, "already_blacklisted", cf),
            (
                InternalError,
                "internal_error",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ]
    }

    // ----- happy path -----

    #[tokio::test]
    async fn v1_error_renders_nested_envelope_with_all_three_fields() {
        let resp = v1_error(
            Reason::IndexerDisabled,
            "box-by-address queries require the indexer",
            "start the node with [indexer] enabled = true",
        );
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let json = body_json(resp).await;
        assert_eq!(json["error"]["reason"], "indexer_disabled");
        assert_eq!(
            json["error"]["message"],
            "box-by-address queries require the indexer"
        );
        assert_eq!(
            json["error"]["detail"],
            "start the node with [indexer] enabled = true"
        );
        // Machine-first: exactly one top-level `error` key, nothing flat.
        assert!(json.get("reason").is_none(), "reason must be nested");
    }

    // ----- oracle parity -----

    #[test]
    fn reason_wire_strings_match_spec_verbatim() {
        for (reason, expected, _) in contract() {
            assert_eq!(wire(reason), expected, "wire string drift for {reason:?}");
        }
    }

    #[test]
    fn reason_status_mapping_matches_spec() {
        for (reason, wire_str, expected) in contract() {
            assert_eq!(
                reason.http_status(),
                expected,
                "status drift for {wire_str} ({reason:?})",
            );
        }
    }

    #[test]
    fn contract_covers_exactly_one_hundred_eleven_reasons_no_duplicates() {
        use std::collections::BTreeSet;
        let rows = contract();
        assert_eq!(rows.len(), 111, "expected 111 canonical reasons");
        let wires: BTreeSet<&str> = rows.iter().map(|(_, w, _)| *w).collect();
        assert_eq!(wires.len(), 111, "wire strings must be unique");
    }
}

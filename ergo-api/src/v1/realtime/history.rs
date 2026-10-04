//! Bounded polling/backfill for the same cursor and event bodies as WebSocket
//! and webhook delivery. The coarse `/events` ring keeps its original contract.

use std::collections::HashSet;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::journal::{JournalStatus, ReplayEvent};
use super::model::parse_channel;
use crate::v1::error::{v1_error, Reason};
use crate::v1::routes::{extract::V1Query, V1State};

#[derive(Deserialize)]
pub(crate) struct ReplayQuery {
    channels: String,
    since: Option<u64>,
    limit: Option<usize>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ReplayPage {
    events: Vec<ReplayEvent>,
    latest_seq: u64,
    oldest_seq: Option<u64>,
    /// Pass this cursor as `since` on the next page, including empty pages.
    next_seq: u64,
    has_more: bool,
    /// Missing source observations, retention expiry or an uncertain crash
    /// interval. A page can contain useful records and still require REST reconciliation.
    gap: bool,
    /// None means this node has no durable replay store. Live records above
    /// complete_through_seq are not covered by a contiguous durable acknowledgement.
    persistence: Option<JournalStatus>,
}

#[utoipa::path(
    get, path = "/api/v1/events/replay", operation_id = "v1_events_replay", tag = "realtime",
    params(
        ("channels" = String, Query, description = "Comma-separated WebSocket channel keys; at most 64"),
        ("since" = Option<u64>, Query, description = "Exclusive shared realtime cursor; default 0"),
        ("limit" = Option<usize>, Query, minimum = 1, maximum = 1024, description = "Page size, 1..1024; default 100"),
    ),
    responses(
        (status = 200, description = "Bounded realtime history with explicit retention/crash gap and confirmed persistence watermark", body = ReplayPage),
        (status = 400, description = "Invalid channel, limit or future cursor", body = crate::v1::V1Error),
        (status = 409, description = "Realtime disabled", body = crate::v1::V1Error),
    )
)]
pub(crate) async fn replay(
    State(state): State<V1State>,
    V1Query(query): V1Query<ReplayQuery>,
) -> Response {
    let Some(realtime) = &state.realtime else {
        return v1_error(
            Reason::RealtimeDisabled,
            "realtime history is unavailable",
            "start the node with an API listener",
        );
    };
    let limit = query.limit.unwrap_or(100);
    let keys: Vec<_> = query.channels.split(',').collect();
    if !(1..=1024).contains(&limit) || keys.is_empty() || keys.len() > super::protocol::MAX_CHANNELS
    {
        return v1_error(
            Reason::BadRequest,
            "invalid replay limit or channel count",
            "use limit 1..1024 and 1..64 channels",
        );
    }
    let mut filter = HashSet::new();
    for raw in keys {
        let parsed = match parse_channel(raw, state.network) {
            Ok(channel) => channel,
            Err(error) => {
                return v1_error(
                    Reason::InvalidSelector,
                    "invalid replay channel",
                    error.message,
                )
            }
        };
        // Historical indexed records remain readable if the current writer is
        // disabled; only subscribing to new observations requires a live feed.
        filter.insert(parsed.key);
    }
    let since = query.since.unwrap_or(0);
    let page = realtime.bus.backfill(&filter, since, limit);
    if since > page.latest_seq {
        return v1_error(
            Reason::BadRequest,
            "replay cursor is ahead of this node",
            "discard a cursor from another data directory and reconcile from REST",
        );
    }
    let next_seq = if page.truncated {
        page.events.last().map(|event| event.seq).unwrap_or(since)
    } else {
        page.latest_seq
    };
    Json(ReplayPage {
        events: page
            .events
            .iter()
            .map(|event| ReplayEvent::from(event.as_ref()))
            .collect(),
        latest_seq: page.latest_seq,
        oldest_seq: page.oldest_seq,
        next_seq,
        has_more: page.truncated,
        gap: page.gap,
        persistence: realtime.bus.journal_status(),
    })
    .into_response()
}

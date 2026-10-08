use std::io::Write;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::api_family::ApiFamily;
use crate::auth::ApiSecurity;
use crate::evidence::{
    CommittedEvidencePage, EvidenceCursor, EvidenceReadError, EvidenceReaderHandle,
    MAX_EVIDENCE_EVENTS, MAX_EVIDENCE_RESPONSE_BYTES, MAX_EVIDENCE_SEQUENCE,
};
use crate::traits::NodeReadState;

use super::route_registry::FamilyRouter;

#[derive(Clone)]
pub(super) struct EvidenceRouteState {
    reader: EvidenceReaderHandle,
    permits: Arc<Semaphore>,
}

pub(super) fn router(
    read: Arc<dyn NodeReadState>,
    security: Option<Arc<ApiSecurity>>,
) -> FamilyRouter {
    let (Some(reader), Some(security)) = (read.committed_evidence_reader(), security) else {
        return FamilyRouter::new(ApiFamily::Rust);
    };
    FamilyRouter::new(ApiFamily::Rust)
        .route(
            "/api/v1/evidence/committed",
            "/api/v1/evidence/committed",
            &["get"],
            get(read_with_empty_body),
        )
        .with_state(EvidenceRouteState {
            reader,
            permits: Arc::new(Semaphore::new(2)),
        })
        .route_layer(DefaultBodyLimit::max(0))
        .route_layer(axum::middleware::from_fn_with_state(
            security,
            crate::auth::require_api_key,
        ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageQuery {
    limit: Option<String>,
    after_archive_id: Option<String>,
    after_sequence: Option<String>,
    after_event_hash: Option<String>,
}

fn decimal(value: &str, maximum: u64) -> Option<u64> {
    if value.is_empty()
        || value.len() > 16
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|value| *value <= maximum)
}

fn identifier(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Serialize)]
struct ReadFailure<'a> {
    error: u16,
    reason: &'a str,
    detail: String,
}

fn failure(status: StatusCode, reason: &str, detail: &str) -> Response {
    let mut response = (
        status,
        axum::Json(ReadFailure {
            error: status.as_u16(),
            reason,
            detail: detail.chars().take(512).collect(),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

struct BoundedJson(Vec<u8>);
impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_EVIDENCE_RESPONSE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "evidence page exceeds response bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Consume the body through axum's zero-byte limit before the documented GET
// handler. This wrapper keeps a Bytes request body out of the OpenAPI contract.
async fn read_with_empty_body(
    state: State<EvidenceRouteState>,
    uri: Uri,
    _empty_body: Bytes,
) -> Response {
    committed_evidence(state, uri).await
}

#[utoipa::path(
    get,
    path = "/api/v1/evidence/committed",
    tag = "Applied evidence",
    security(("ApiKeyAuth" = [])),
    params(
        ("limit" = Option<String>, Query, description = "Canonical decimal event count 1..16; default 1"),
        ("afterArchiveId" = Option<String>, Query, description = "Complete cursor archive ID; supply all three cursor fields"),
        ("afterSequence" = Option<String>, Query, description = "Canonical decimal sequence 0..2^53-1"),
        ("afterEventHash" = Option<String>, Query, description = "Complete cursor lowercase BLAKE2b-256 event hash"),
    ),
    responses(
        (status = 200, description = "One committed redb snapshot, exact journal event JSON and source anchor", body = CommittedEvidencePage),
        (status = 400, description = "Invalid/oversized query or partial cursor"),
        (status = 403, description = "Missing or invalid api_key"),
        (status = 404, description = "Reader or API security not configured; route is absent"),
        (status = 409, description = "Cursor, journal, canonical tip or configured anchor requires reconstruction"),
        (status = 413, description = "GET body or complete page exceeds the bound"),
        (status = 503, description = "Reader unavailable or both bounded reader workers busy"),
    ),
)]
pub(super) async fn committed_evidence(
    State(state): State<EvidenceRouteState>,
    uri: Uri,
) -> Response {
    if uri.query().is_some_and(|query| query.len() > 512) {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "query exceeds 512 bytes",
        );
    }
    let Ok(Query(query)) = Query::<PageQuery>::try_from_uri(&uri) else {
        return failure(
            StatusCode::BAD_REQUEST,
            "invalid_cursor",
            "invalid page query",
        );
    };
    let limit = match query.limit {
        None => 1,
        Some(value) => match decimal(&value, MAX_EVIDENCE_EVENTS as u64) {
            Some(value @ 1..) => value as usize,
            _ => {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "invalid_limit",
                    "limit must be 1..16",
                )
            }
        },
    };
    let after = match (
        query.after_archive_id,
        query.after_sequence,
        query.after_event_hash,
    ) {
        (None, None, None) => None,
        (Some(archive_id), Some(sequence), Some(event_hash)) => {
            let Some(sequence) = decimal(&sequence, MAX_EVIDENCE_SEQUENCE) else {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "invalid_cursor",
                    "invalid sequence",
                );
            };
            if !identifier(&archive_id) || !identifier(&event_hash) {
                return failure(
                    StatusCode::BAD_REQUEST,
                    "invalid_cursor",
                    "invalid cursor identifier",
                );
            }
            Some(EvidenceCursor {
                archive_id,
                sequence,
                event_hash,
            })
        }
        _ => {
            return failure(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "complete cursor required",
            )
        }
    };
    let Ok(permit) = state.permits.try_acquire_owned() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "reader_busy",
            "reader concurrency bound reached",
        );
    };
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let page = state.reader.read_committed(after.as_ref(), limit)?;
        if page.events.len() > limit {
            return Err(EvidenceReadError::Unavailable(
                "reader exceeded requested count".into(),
            ));
        }
        let mut output = BoundedJson(Vec::new());
        serde_json::to_writer(&mut output, &page).map_err(|_| EvidenceReadError::TooLarge)?;
        Ok(output.0)
    })
    .await;
    match outcome {
        Ok(Ok(bytes)) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            Body::from(bytes),
        )
            .into_response(),
        Ok(Err(EvidenceReadError::ReconstructionRequired(detail))) => {
            failure(StatusCode::CONFLICT, "reconstruction_required", &detail)
        }
        Ok(Err(EvidenceReadError::TooLarge)) => failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "page_too_large",
            "reduce limit without advancing cursor; oversized single records require another transport",
        ),
        _ => failure(StatusCode::SERVICE_UNAVAILABLE, "reader_unavailable", "committed journal read failed"),
    }
}

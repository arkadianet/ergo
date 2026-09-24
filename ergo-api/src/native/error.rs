use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ergo_api_core::error::{ErrorKind, ServiceError};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub kind: &'static str,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

pub fn response(error: ServiceError) -> Response {
    let status = match error.kind() {
        ErrorKind::Validation => StatusCode::BAD_REQUEST,
        ErrorKind::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ErrorKind::NotFound => StatusCode::NOT_FOUND,
        ErrorKind::Conflict => StatusCode::CONFLICT,
        ErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
        ErrorKind::Forbidden => StatusCode::FORBIDDEN,
        ErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorKind::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let body = ErrorEnvelope {
        error: ErrorBody {
            kind: kind_name(error.kind()),
            code: error.code().to_string(),
            message: error.message().to_string(),
            detail: error.detail().map(str::to_string),
            retry_after_seconds: error.retry_after().map(|duration| duration.as_secs()),
        },
    };
    (status, Json(body)).into_response()
}

pub fn unavailable(code: &'static str, message: &'static str) -> Response {
    response(ServiceError::unavailable(code, message))
}

fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Validation => "validation",
        ErrorKind::PayloadTooLarge => "payload_too_large",
        ErrorKind::NotFound => "not_found",
        ErrorKind::Conflict => "conflict",
        ErrorKind::Unauthenticated => "unauthenticated",
        ErrorKind::Forbidden => "forbidden",
        ErrorKind::Unavailable => "unavailable",
        ErrorKind::Overloaded => "overloaded",
        ErrorKind::RateLimited => "rate_limited",
        ErrorKind::Timeout => "timeout",
        ErrorKind::Internal => "internal",
    }
}

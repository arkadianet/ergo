//! v1 extractor wrappers that keep EVERY request-parsing failure inside the v1
//! envelope (`v1-api-design.md` §1.4).
//!
//! Axum's stock [`Query`]/[`Json`] extractors answer a malformed query string or
//! request body with their own plain-text `400`, which bypasses the canonical
//! `{error:{reason,…}}` shape every v1 route otherwise guarantees. [`V1Query`]
//! and [`V1Json`] delegate to the stock extractors and map any rejection to
//! [`v1_error`] so a bad `?limit=abc` or unparseable POST body reads the same as
//! every other v1 `400`. Use these in place of `Query<T>`/`Json<T>` on every v1
//! handler (Path segments are single strings that do not reject, so bare
//! [`Path`](axum::extract::Path) stays).

use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::request::Parts;
use axum::response::Response;
use axum::Json;
use serde::de::DeserializeOwned;

use crate::v1::error::{v1_error, Reason};

/// `Query<T>` in the v1 envelope: a malformed query string is
/// `400 invalid_params` instead of Axum's default plain-text rejection.
pub(crate) struct V1Query<T>(pub T);

#[async_trait::async_trait]
impl<T, S> FromRequestParts<S> for V1Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(v)) => Ok(V1Query(v)),
            Err(e) => Err(v1_error(
                Reason::InvalidParams,
                "query parameters are malformed",
                e.to_string(),
            )),
        }
    }
}

/// `Json<T>` in the v1 envelope: a body that is not valid JSON for the target
/// type (or the wrong content-type) is `400 bad_request` instead of Axum's
/// default plain-text rejection.
pub(crate) struct V1Json<T>(pub T);

#[async_trait::async_trait]
impl<T, S> FromRequest<S> for V1Json<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(V1Json(v)),
            Err(e) => Err(v1_error(
                Reason::BadRequest,
                "request body is not valid JSON for this endpoint",
                e.to_string(),
            )),
        }
    }
}

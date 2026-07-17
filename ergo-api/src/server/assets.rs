//! Static-asset handlers for the operator dashboard SPA and the
//! Swagger/OpenAPI documents: index page, Swagger UIs, spec emitters,
//! self-hosted fonts, stylesheets, and JS modules. Route registration
//! stays in the parent module.

use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use utoipa::OpenApi;

use super::openapi::native_openapi_yaml;
use super::NativeOpenApi;
use crate::web::{
    COMPONENTS_CSS, DASHBOARD_CSS, INDEX_HTML, INTER_VARIABLE_WOFF2, JETBRAINS_MONO_WOFF2,
    NATIVE_SWAGGER_HTML, OPENAPI_YAML, SWAGGER_HTML, TOKENS_CSS, V1_SWAGGER_HTML,
};

pub(super) async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

pub(super) async fn swagger() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}

pub(super) async fn swagger_native() -> Html<&'static str> {
    Html(NATIVE_SWAGGER_HTML)
}

pub(super) async fn swagger_v1() -> Html<&'static str> {
    Html(V1_SWAGGER_HTML)
}

pub(super) async fn openapi_yaml() -> Response {
    ([(header::CONTENT_TYPE, "application/yaml")], OPENAPI_YAML).into_response()
}

/// Rust-native `/api/v1/*` OpenAPI spec as YAML, generated from the
/// [`NativeOpenApi`] derive. A separate surface from the Scala-parity
/// [`openapi_yaml`] above; both mounts coexist.
pub(super) async fn openapi_native_yaml() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/yaml")],
        native_openapi_yaml(),
    )
        .into_response()
}

/// Rust-native `/api/v1/*` OpenAPI spec as JSON.
pub(super) async fn openapi_native_json() -> Response {
    (StatusCode::OK, Json(NativeOpenApi::openapi())).into_response()
}

/// The v1 product-API OpenAPI spec as YAML, generated from
/// [`crate::v1::openapi::V1OpenApi`]. A separate document from
/// [`openapi_native_yaml`] above — see that derive's module docs for why.
pub(super) async fn openapi_v1_yaml_handler() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/yaml")],
        crate::v1::openapi::v1_openapi_yaml(),
    )
        .into_response()
}

/// The v1 product-API OpenAPI spec as JSON.
pub(super) async fn openapi_v1_json() -> Response {
    (
        StatusCode::OK,
        Json(crate::v1::openapi::V1OpenApi::openapi()),
    )
        .into_response()
}

pub(super) async fn jetbrains_mono_woff2() -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        JETBRAINS_MONO_WOFF2,
    )
        .into_response()
}

pub(super) async fn inter_variable_woff2() -> Response {
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        INTER_VARIABLE_WOFF2,
    )
        .into_response()
}

/// Serve a static JS module with the JavaScript content-type.
pub(super) fn js(body: &'static str) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

pub(super) async fn tokens_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        TOKENS_CSS,
    )
        .into_response()
}

pub(super) async fn components_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        COMPONENTS_CSS,
    )
        .into_response()
}

pub(super) async fn dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
        .into_response()
}

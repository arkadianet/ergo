/// GET /swagger — Serve Swagger UI HTML page.
pub(crate) async fn swagger_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(crate::web_ui::SWAGGER_HTML)
}

/// GET /panel — Serve the Node Panel admin dashboard.
pub(crate) async fn panel_handler() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    axum::response::Html<&'static str>,
) {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            "no-cache, no-store, must-revalidate",
        )],
        axum::response::Html(crate::web_ui::PANEL_HTML),
    )
}

/// GET /api-docs/openapi.yaml — Serve the OpenAPI specification.
pub(crate) async fn openapi_yaml_handler() -> (
    [(axum::http::header::HeaderName, &'static str); 1],
    &'static str,
) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        crate::web_ui::OPENAPI_YAML,
    )
}

/// GET / — Redirect to Swagger UI.
pub(crate) async fn root_redirect_handler() -> axum::response::Redirect {
    axum::response::Redirect::permanent("/swagger")
}

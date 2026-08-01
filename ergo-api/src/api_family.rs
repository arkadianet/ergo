//! Public API-family metadata.

/// The two API families served by the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiFamily {
    Scala,
    Rust,
}

/// User-facing metadata shared by the dashboard and API documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiFamilyDescriptor {
    pub family: ApiFamily,
    pub label: &'static str,
    pub swagger_url: &'static str,
    pub openapi_url: &'static str,
}

pub const SCALA_API: ApiFamilyDescriptor = ApiFamilyDescriptor {
    family: ApiFamily::Scala,
    label: "Scala API",
    swagger_url: "/swagger",
    openapi_url: "/api-docs/openapi-scala.yaml",
};

pub const RUST_API: ApiFamilyDescriptor = ApiFamilyDescriptor {
    family: ApiFamily::Rust,
    label: "RUST API",
    swagger_url: "/swagger/native",
    openapi_url: "/api-docs/openapi-rust.yaml",
};

pub const API_FAMILIES: [ApiFamilyDescriptor; 2] = [SCALA_API, RUST_API];

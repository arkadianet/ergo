//! `/api/v1/*` product-API shared primitives (design Appendix A, item **G2**).
//!
//! Infrastructure every future v1 endpoint depends on, built ONCE here
//! (`dev-docs/v1-api-design.md` §1–§2). Nothing here is mounted on a route;
//! the first route-group PR consumes it. The re-exports below are the stable
//! surface those groups import.
//!
//! * [`error`] — the nested error envelope `{error:{reason,message,detail}}`
//!   and the canonical [`error::Reason`] enum with its status mapping (§1.3–§1.4).

pub mod error;

pub use error::{v1_error, Reason, V1Error, V1ErrorInner};

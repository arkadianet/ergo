//! `/api/v1/*` product-API shared primitives (design Appendix A, item **G2**).
//!
//! Infrastructure every future v1 endpoint depends on, built ONCE here
//! (`dev-docs/v1-api-design.md` §1–§2). Nothing here is mounted on a route;
//! the first route-group PR consumes it. The re-exports below are the stable
//! surface those groups import.
//!
//! * [`error`] — the nested error envelope `{error:{reason,message,detail}}`
//!   and the canonical [`error::Reason`] enum with its status mapping (§1.3–§1.4).
//! * [`cursor`] — the one opaque, versioned cursor codec + `page` builder (§1.5).

pub mod cursor;
pub mod error;

pub use cursor::{
    clamp_limit, decode_cursor, decode_opt_cursor, encode_cursor, CursorError, CursorPayload, Page,
    CURSOR_VERSION, DEFAULT_LIMIT, MAX_LIMIT,
};
pub use error::{v1_error, Reason, V1Error, V1ErrorInner};

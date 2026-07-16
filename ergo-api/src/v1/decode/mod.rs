//! Semantic decode + the protocol registry.
//!
//! Turns a raw box into meaning ("this is a SigmaUSD bank box: reserve X,
//! circulating Y") via an **extensible registry** of [`registry::ProtocolEntry`]
//! matchers. The single seam is [`service::decode_box`], which every
//! box-returning surface calls to populate `V1Box.decoded`:
//! `boxes/{id}?decode=true`, the box list routes, `POST /boxes/decode`, and
//! (reused) tx-intelligence output previews.
//!
//! Design invariants:
//! * **no evaluation** — pure deserialization + register reads + ≤3 hash probes;
//! * **fail-soft** — a malformed tree or ill-typed register never errors the
//!   box, it yields `contract: null` / `confidence: heuristic`;
//! * **honest** — an unrecognized box gets `contract: null`; a recognized-but-
//!   not-yet-verified protocol is a discoverable stub, never fabricated state.
//!
//! Extending: add a `decoders/<family>.rs` renderer + one
//! [`registry::ProtocolEntry`] + a `test-vectors/decode/` oracle. No route or
//! envelope change.

pub mod decoders;
pub mod registry;
pub mod service;
pub mod value;

pub use registry::{entry_by_id, ProtocolEntry, REGISTRY};
pub use service::{decode_box, decode_box_bytes};
pub use value::decode_value;

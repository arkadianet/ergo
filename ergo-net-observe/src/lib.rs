//! Phase 0 network observation.
//!
//! Three consumers share this crate:
//!
//! * the standalone `observer` binary ([`runner`] + [`session`]) — an honest,
//!   read-mostly legacy peer that records announce/request/receive timing and
//!   connection lifecycle against a fixed peer list;
//! * the standalone `crawler` binary ([`crawler`] + [`session`]) — the same
//!   honest session, plus a bounded, rate-limited discovery walk over
//!   learned peer addresses;
//! * the node hook ([`sink`] + [`record`]) — emits transaction admission
//!   outcomes and header validation timings from a validating node.
//!
//! Output is line-delimited JSON (`ergo-observer/1`). See `docs/phase0-observer.md`.
//! The sink is bounded and non-blocking: observation never backpressures
//! consensus.

pub mod crawler;
pub mod pseudonym;
pub mod record;
pub mod runner;
pub mod session;
pub mod sink;
pub mod util;

pub use crawler::{
    AttemptOutcome, CrawlChannel, CrawlConfig, CrawlState, GossipReport, GossipSpec,
};
pub use pseudonym::Pseudonymizer;
pub use record::{BlockRef, Envelope, Event, GossipPeer, PeerRef, SCHEMA};
pub use runner::{run, RunnerConfig};
pub use session::{run_session, SessionConfig, Shared, SharedSeen};
pub use sink::{ObserverSink, SinkConfig};

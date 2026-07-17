//! Mode 2 (UTXO snapshot bootstrap) consume-side discovery reducer.
//!
//! Pure state machine: tracks per-peer `SnapshotsInfo` responses
//! and applies Scala's quorum selection rule — *the highest height
//! at which `>= MIN_MANIFEST_VOTES` peers agree on the same
//! manifest_id wins*.
//!
//! No I/O lives here. The ergo-node integration layer (sub-phase
//! 2f-2) calls [`SnapshotBootstrap::on_snapshots_info`] when an
//! inbound `SnapshotsInfo` (code 77) arrives, and queries
//! [`SnapshotBootstrap::state`] each tick to learn when a manifest
//! has been selected so it can transition to the manifest-download
//! phase (sub-phase 2g).
//!
//! **Eligibility filtering is the caller's responsibility.** The
//! reducer accepts every vote it's given; the integration layer
//! gates calls to peers that handshook as Mode 1/2/3 (peers with
//! UTXO state to serve). Votes from Mode 5/6 peers must not reach
//! the reducer.
//!
//! Scala parity reference:
//! * `MinManifestVotes = 3` (this crate's [`MIN_MANIFEST_VOTES`]).
//! * Highest *quorum* height wins — not the highest *advertised*
//!   height. A taller advertisement without supporting votes is
//!   ignored.
//!
//! Tie ambiguity (same height, two different manifest_ids both
//! reaching quorum) is intentionally left to natural iteration
//! order. Scala has no documented tie-break rule, and the part-2g
//! trust check against `header.state_root` at the snapshot height
//! rejects the wrong manifest_id regardless of which we pick, so
//! tie-breaking by hash here would be inventing policy.

mod chunks;
mod manifest;

pub use chunks::{ChunkAssembly, ChunkReceiveOutcome, CHUNK_REQUEST_TIMEOUT, MAX_INFLIGHT_CHUNKS};
pub use manifest::{
    verify_manifest_against_state_root, BootstrapState, ManifestVerifyError, SnapshotBootstrap,
    MANIFEST_REQUEST_TIMEOUT, MIN_MANIFEST_VOTES,
};

#[cfg(test)]
mod tests;

//! Ergo P2P protocol stack for the Rust node.
//!
//! Sits on top of [`ergo_primitives`] (Blake2b digests, VLQ codecs)
//! and [`ergo_ser`] (header / modifier wire types). Provides the
//! framed-message TCP connection pipeline, handshake, peer manager,
//! address book, and modifier-delivery bookkeeping that the sync
//! coordinator (`ergo-sync`) drives.
//!
//! Module map:
//!
//! * [`framing`] — wire-frame codec: `magic[4] || code[1] ||
//!   length[4 BE i32]` plus optional `checksum[4] || payload`.
//! * [`connection`] — async TCP `Connection` wrapper that buffers
//!   reads, drains complete frames, and rejects oversized payloads.
//! * [`handshake`] — version exchange + features negotiation; the
//!   gate before a peer is promoted to [`peer::Peer`].
//! * [`message`] — typed P2P message enum and parser/serializer
//!   matching Scala's `MessageSpec` registrations.
//! * [`peer`] — per-peer state machine (handshaking → handshaked →
//!   active → terminating).
//! * [`peer_manager`] — connection lifecycle: dial / accept,
//!   bucketed peer slots, eviction policy, address-book updates.
//! * [`address_book`] — redb-persisted peer-address store with
//!   bucket assignment, last-seen / failure tracking, and a
//!   re-discovery tax to slow churn.
//! * [`partition`] — throughput-aware partition layer that splits
//!   peers into front (delivering) and back (idle) groups.
//! * [`throttle`] — token-bucket request rate limiter applied
//!   per-peer.
//! * [`assembly`] — block-section reassembly: walks header →
//!   transactions / extension / AD-proofs and computes section ids.
//! * [`delivery`] — outstanding-modifier tracker: per-peer pending
//!   set + per-modifier expectation.
//! * [`sync`] — per-peer sync state used by the sync coordinator
//!   to plan inv / request batches.
//! * [`types`] — shared protocol types (`ModifierTypeId`, `InvData`,
//!   `ModifiersData`, `SnapshotsInfo`, `NipopowProofData`).

pub mod address_book;
pub mod assembly;
pub mod connection;
pub mod delivery;
pub mod framing;
pub mod handshake;
pub mod message;
pub mod partition;
pub mod peer;
pub mod peer_manager;
pub mod sync;
pub mod throttle;
pub mod types;

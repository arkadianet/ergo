//! Matrix (input blocks) processor and policy for the Ergo Rust node
//! (input blocks were earlier called "sub-blocks"). Implements the Matrix
//! spec's announcement validity rules (PoW against the multiplied target, the
//! extension proof reducing to and binding the header's extension root,
//! nBits agreement) as pure functions over the wire types `ergo-ser`
//! already codecs, plus per-ordering-block input chains and forks
//! ([`chain`], [`tree`]), transaction staging and weak-id resolution,
//! explicit resource [`bounds`], the ordering-announcement store
//! ([`ordering`]) and the single-writer state machine the node drives
//! from p2p and mining events ([`processor`]).
//!
//! Deliberately outside this crate: wire (de)serialization (`ergo-ser`),
//! p2p message dispatch and peer bookkeeping (`ergo-p2p`), wall-clock
//! time and any I/O — every time-dependent function here takes a `Tick`
//! (see [`types::Tick`]) from the caller, and every peer reference is the
//! opaque [`types::PeerTag`] the node maps to its own `PeerId`. PoW
//! target arithmetic, the Autolykos v2 hit function, and the extension
//! merkle primitives live in `ergo-crypto`; batch-merkle-proof reduction
//! lives in `ergo-validation`. This crate only composes those into the
//! policy decisions the spec describes.
//!
//! Pinned to the Scala `weak-blocks` branch (`org.ergoplatform.subblocks`
//! / `org.ergoplatform.mining.{InputBlockFields, AutolykosPowScheme}`).
//! Parity and deliberate divergences from that branch are tracked in
//! `test-vectors/weak-blocks/*.json` and cited from the tests that
//! consume them — see `announcement::validate_announcement_parity` vs
//! `announcement::validate_announcement` for the sharpest example
//! (finding F4/F4b: Scala's own field-binding check is weaker than the
//! extension-proof-reduces-to-root check alone implies).

pub mod announcement;
pub mod bounds;
pub mod chain;
pub mod ordering;
pub mod processor;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;
pub mod tree;
pub mod types;

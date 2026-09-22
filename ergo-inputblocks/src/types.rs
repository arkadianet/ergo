//! Core identifiers and handles the input-block processor works with.
//! Pure value types — no I/O, no clocks, no peer-networking types beyond
//! an opaque tag the node fills in.

use ergo_ser::weak_id::{weak_tx_id, WeakId};

/// An input block's id — its header id.
pub type InputBlockId = [u8; 32];
/// An ordering block's id — its header id.
pub type OrderingId = [u8; 32];

/// Transaction identity for input-block bodies: witness variants of the
/// same `tx_id` are distinct transactions for weak-id / staging purposes
/// (spec 7.5) even though they share the same on-chain transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxRef {
    pub tx_id: [u8; 32],
    pub witness_id: [u8; 31],
}

impl TxRef {
    /// The weak id used to reference this transaction over the wire:
    /// `tx_id[0..3] ++ witness_id[0..3]`.
    pub fn weak_id(&self) -> WeakId {
        weak_tx_id(&self.tx_id, &self.witness_id)
    }
}

/// Opaque peer handle; the node maps it to its own `PeerId` type. This
/// crate never dials, disconnects, or otherwise treats a peer as
/// anything but a key to route announcements by.
///
/// # Invariant
///
/// `0` is reserved for [`PeerTag::LOCAL`] and must never name a remote
/// peer. The distinction is load-bearing: `on_announcement` emits
/// [`crate::processor::Effect::RelayAnnouncement`] exactly when
/// `from == PeerTag::LOCAL`, so a remote peer mapped to `0` would have
/// its announcements relayed as if this node had mined them. Build
/// remote tags with [`PeerTag::remote`], which enforces this; the field
/// stays public only so the node's own mapping code can read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerTag(pub u64);

impl PeerTag {
    /// The reserved tag for a locally generated input block. Only blocks
    /// announced under this tag are relayed
    /// ([`crate::processor::Effect::RelayAnnouncement`]) — parity with
    /// Scala, which relays only its own input blocks and leaves remote
    /// relay as a TODO. The node must never map a real peer to `0`.
    pub const LOCAL: PeerTag = PeerTag(0);

    /// A tag for a **remote** peer. Returns `None` for `0`, which is
    /// [`PeerTag::LOCAL`]: the node's peer-id mapping must pick a
    /// different value rather than silently aliasing a peer onto the
    /// local-relay tag.
    pub const fn remote(tag: u64) -> Option<PeerTag> {
        if tag == PeerTag::LOCAL.0 {
            None
        } else {
            Some(PeerTag(tag))
        }
    }
}

/// A monotonic tick in milliseconds, supplied by the node. This crate has
/// no clock of its own — every time-dependent policy decision takes a
/// `Tick` from the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tick(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    // ----- error paths -----

    /// `0` is `PeerTag::LOCAL`; handing it to `remote` must fail rather
    /// than mint a remote tag whose announcements would be relayed as
    /// locally mined.
    #[test]
    fn peer_tag_remote_zero_is_rejected() {
        assert_eq!(PeerTag::remote(0), None);
        assert_eq!(PeerTag::remote(1), Some(PeerTag(1)));
        assert_eq!(PeerTag::remote(u64::MAX), Some(PeerTag(u64::MAX)));
    }
}

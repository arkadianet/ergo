//! Shared P2P protocol types: modifier type IDs and wire-payload
//! structs used by inventory / modifier / snapshot / NiPoPoW messages.

/// Network object type IDs assigned by the protocol. The `i8`
/// representation matches Scala's `NetworkObjectTypeId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i8)]
pub enum ModifierTypeId {
    /// Block header (id 101).
    Header = 101,
    /// Block transactions section (id 102).
    BlockTransactions = 102,
    /// Authenticated AVL+ proofs section (id 104).
    ADProofs = 104,
    /// Extension key-value section (id 108).
    Extension = 108,
    /// Mempool transaction (id 2 — auxiliary, not a block section).
    Transaction = 2,
}

impl ModifierTypeId {
    /// Parse a raw byte as a `ModifierTypeId`. Returns `None` for
    /// unknown ids — the caller decides whether to reject the message
    /// or skip the modifier.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b as i8 {
            101 => Some(Self::Header),
            102 => Some(Self::BlockTransactions),
            104 => Some(Self::ADProofs),
            108 => Some(Self::Extension),
            2 => Some(Self::Transaction),
            _ => None,
        }
    }

    /// Project to its raw wire byte.
    pub fn as_byte(self) -> u8 {
        self as i8 as u8
    }

    /// `true` if `type_id_byte` denotes a block-section modifier
    /// (id ≥ 50). Block sections are downloaded as part of full-block
    /// sync; auxiliary modifiers (transactions) are not.
    pub fn is_block_section(type_id_byte: u8) -> bool {
        (type_id_byte as i8) >= 50
    }
}

/// Inventory data — shared payload of `Inv` (code 55) and
/// `RequestModifier` (code 22). Capped at 400 items per message.
#[derive(Debug, Clone)]
pub struct InvData {
    /// Type id of the modifiers being announced / requested.
    pub type_id: u8,
    /// Modifier ids carried by this message.
    pub ids: Vec<[u8; 32]>,
}

/// Modifier data — payload of `Modifiers` (code 33), the response to
/// a `RequestModifier`.
#[derive(Debug, Clone)]
pub struct ModifiersData {
    /// Type id of the modifiers being delivered.
    pub type_id: u8,
    /// `(modifier_id, modifier_bytes)` pairs.
    pub modifiers: Vec<([u8; 32], Vec<u8>)>,
}

/// Snapshot info — payload of `SnapshotsInfo` (code 77), the response
/// to `GetSnapshotsInfo`. Lists the heights and manifest digests a
/// snapshot-providing peer can serve.
#[derive(Debug, Clone)]
pub struct SnapshotsInfo {
    /// Available `(block_height, manifest_digest)` pairs.
    pub available_manifests: Vec<(i32, [u8; 32])>,
}

/// NiPoPoW proof request data (code 90). Carries the `(m, k)` security
/// parameters and an optional anchor header id.
#[derive(Debug, Clone)]
pub struct NipopowProofData {
    /// NiPoPoW security parameter `m` (chain prefix length).
    pub m: i32,
    /// NiPoPoW security parameter `k` (suffix length).
    pub k: i32,
    /// Anchor header id. `None` means "from the requester's known tip".
    pub header_id_opt: Option<[u8; 32]>,
}

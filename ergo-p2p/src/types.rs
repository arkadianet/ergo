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

    /// `true` only for the three block-BODY sections
    /// (`BlockTransactions` 102, `ADProofs` 104, `Extension` 108) — the
    /// parts of a full block's body, EXCLUDING the header. Unlike
    /// [`Self::is_block_section`] (id ≥ 50, which also matches the header
    /// and any unknown high id), this is the strict body-only set used for
    /// body-download quality tracking, where a peer's reliability at
    /// delivering bodies must be measured separately from the fast,
    /// constantly-flowing header and mempool-tx streams.
    pub fn is_block_body_section(type_id_byte: u8) -> bool {
        matches!(
            Self::from_byte(type_id_byte),
            Some(Self::BlockTransactions | Self::ADProofs | Self::Extension)
        )
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

/// The only `(m, k)` parameters this node requests or serves over P2P —
/// Scala `ErgoHistoryUtils.scala:29,34` (`P2PNipopowProofM = 6`,
/// `P2PNipopowProofK = 10`). The serve side refuses other params
/// (`ErgoNodeViewSynchronizer.scala:1046-1058` warns and drops);
/// arbitrary params are a REST-only capability.
pub const P2P_NIPOPOW_PROOF_M: i32 = 6;
/// See [`P2P_NIPOPOW_PROOF_M`].
pub const P2P_NIPOPOW_PROOF_K: i32 = 10;

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

impl NipopowProofData {
    /// Whether the P2P serve side may answer this request — Scala
    /// `sendNipopowProof` (`ErgoNodeViewSynchronizer.scala:1047`):
    /// `data.m == P2PNipopowProofM && data.k == P2PNipopowProofK &&
    /// data.headerIdBytesOpt.isEmpty`. Anything else is warned and
    /// dropped, never answered with the default cached proof.
    pub fn p2p_servable(&self) -> bool {
        self.m == P2P_NIPOPOW_PROOF_M
            && self.k == P2P_NIPOPOW_PROOF_K
            && self.header_id_opt.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn is_block_body_section_matches_only_the_three_body_sections() {
        // The three block-body parts (BlockTransactions, ADProofs, Extension).
        assert!(ModifierTypeId::is_block_body_section(102));
        assert!(ModifierTypeId::is_block_body_section(104));
        assert!(ModifierTypeId::is_block_body_section(108));
        // Header (101) and mempool tx (2) are NOT block bodies.
        assert!(!ModifierTypeId::is_block_body_section(101));
        assert!(!ModifierTypeId::is_block_body_section(2));
        // Unknown ids.
        assert!(!ModifierTypeId::is_block_body_section(0));
        assert!(!ModifierTypeId::is_block_body_section(255));
    }

    #[test]
    fn is_block_body_section_is_stricter_than_is_block_section_for_header() {
        // The crucial distinction for body-only download tracking: the
        // header passes the broad `is_block_section` (id >= 50) but is NOT a
        // body section.
        assert!(ModifierTypeId::is_block_section(101));
        assert!(!ModifierTypeId::is_block_body_section(101));
    }
}

#[cfg(test)]
mod nipopow_guard_tests {
    use super::*;

    #[test]
    fn default_unanchored_request_is_servable() {
        assert!(NipopowProofData {
            m: P2P_NIPOPOW_PROOF_M,
            k: P2P_NIPOPOW_PROOF_K,
            header_id_opt: None,
        }
        .p2p_servable());
    }

    #[test]
    fn non_default_params_or_anchor_are_refused() {
        // Scala sendNipopowProof warns + drops all three of these.
        let cases = [
            (3, P2P_NIPOPOW_PROOF_K, None),
            (P2P_NIPOPOW_PROOF_M, 5, None),
            (P2P_NIPOPOW_PROOF_M, P2P_NIPOPOW_PROOF_K, Some([0u8; 32])),
        ];
        for (m, k, header_id_opt) in cases {
            assert!(
                !NipopowProofData {
                    m,
                    k,
                    header_id_opt
                }
                .p2p_servable(),
                "(m={m}, k={k}, anchored={}) must be refused",
                header_id_opt.is_some()
            );
        }
    }
}

//! Types for Non-Interactive Proofs of Proof-of-Work (NiPoPoW).

use crate::header::Header;
use crate::modifier_id::ModifierId;

/// A header augmented with interlink vector data for NiPoPoW proofs.
#[derive(Debug, Clone)]
pub struct PoPowHeader {
    /// The underlying block header.
    pub header: Header,
    /// Interlink vector: [genesis_id, level-1 id, level-2 id, ...]
    pub interlinks: Vec<ModifierId>,
    /// Merkle authentication path for the interlinks in the Extension block.
    /// Each entry is (digest_bytes, side_byte).
    pub interlinks_proof: Vec<(Vec<u8>, u8)>,
}

/// A Non-Interactive Proof of Proof-of-Work (KMZ17).
#[derive(Debug, Clone)]
pub struct NipopowProof {
    /// Security parameter: minimum superchain length.
    pub m: u32,
    /// Security parameter: suffix length.
    pub k: u32,
    /// Sparse superblock prefix chain.
    pub prefix: Vec<PoPowHeader>,
    /// First suffix header (with full interlinks).
    pub suffix_head: PoPowHeader,
    /// Remaining k-1 suffix headers (plain headers, no interlinks needed).
    pub suffix_tail: Vec<Header>,
}

//! Devnet genesis-block bootstrap. A private devnet starts at a bare genesis: the
//! UTXO state is seeded (`initialize_genesis`) but there is NO stored genesis
//! HEADER, so the candidate builder — which loads the parent header to build the
//! next block — cannot build block 1. This module supplies a SYNTHETIC height-0
//! genesis parent header so block 1 can be built on top of it. DEVNET-ONLY; the
//! stored chain state is left unchanged (best-full stays the zeroed genesis
//! sentinel) so the height-1-start header-chain invariants are not disturbed.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::Header;

/// Fixed devnet genesis timestamp (2020-01-01T00:00:00Z, ms). Constant so the
/// synthetic genesis header — hence block 1's parent — is deterministic.
pub const DEVNET_GENESIS_TIMESTAMP_MS: u64 = 1_577_836_800_000;

/// The synthetic genesis (height-0) parent header for a devnet. `state_root` is
/// the seeded genesis UTXO state digest; `n_bits` the genesis difficulty. The
/// Autolykos solution is a placeholder — genesis PoW is trusted, and block 1's
/// difficulty check reads the parent's `n_bits`, not its solution.
pub fn synthetic_genesis_header(state_root: ADDigest, n_bits: u32) -> Header {
    Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0u8; 32]),
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root: Digest32::from_bytes([0u8; 32]),
        state_root,
        timestamp: DEVNET_GENESIS_TIMESTAMP_MS,
        extension_root: Digest32::from_bytes([0u8; 32]),
        n_bits,
        height: 0,
        votes: [0u8; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0u8; 33]),
            nonce: [0u8; 8],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn synthetic_genesis_header_has_genesis_shape() {
        let state_root = ADDigest::from_bytes([0x07; 33]);
        let h = synthetic_genesis_header(state_root, 0x0101_0000);
        assert_eq!(h.height, 0, "genesis is height 0");
        assert_eq!(
            h.parent_id,
            ModifierId::from_bytes([0u8; 32]),
            "genesis has no parent"
        );
        assert_eq!(
            h.state_root, state_root,
            "state root = seeded genesis digest"
        );
        assert_eq!(h.n_bits, 0x0101_0000, "n_bits = genesis difficulty");
    }
}

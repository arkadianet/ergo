//! Devnet genesis-block bootstrap. A private devnet starts at a bare genesis: the
//! UTXO state is seeded (`initialize_genesis`) but there is NO stored genesis
//! HEADER, so the candidate builder — which loads the parent header to build the
//! next block — cannot build block 1. This module supplies a SYNTHETIC height-0
//! genesis parent header so block 1 can be built on top of it. DEVNET-ONLY; the
//! stored chain state is left unchanged (best-full stays the zeroed genesis
//! sentinel) so the height-1-start header-chain invariants are not disturbed.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::ergo_box::{read_ergo_box, ErgoBox};
use ergo_ser::header::Header;

use crate::error::MiningError;

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

/// True if `tree_bytes` are the serialized emission proposition
/// (`ErgoTreePredef.emissionBoxProp`). The emission tree is a
/// network-identical protocol constant (see
/// [`ergo_chain_spec::emission_tree_bytes`]), so this predicate
/// identifies the genesis emission box on mainnet, testnet, and devnet
/// alike — a byte-exact match against the one shared source, no
/// duplicated constant.
pub fn is_emission_box(tree_bytes: &[u8]) -> bool {
    tree_bytes == ergo_chain_spec::emission_tree_bytes().as_slice()
}

/// Resolve the genesis emission box from the seeded genesis box set.
/// Devnet mines block 1 by spending this box directly — there is no
/// parent block whose `BlockTransactions` section it could be derived
/// from (cf. [`crate::emission_box::lookup_tip_emission_box`]). Returns
/// the first genesis box whose `ErgoTree` is the emission proposition.
pub fn genesis_emission_box(genesis_boxes: &[([u8; 32], Vec<u8>)]) -> Result<ErgoBox, MiningError> {
    for (_id, box_bytes) in genesis_boxes {
        let mut r = VlqReader::new(box_bytes);
        let eb = read_ergo_box(&mut r).map_err(|e| MiningError::Decode {
            op: "genesis_emission_box",
            reason: format!("{e:?}"),
        })?;
        if is_emission_box(eb.candidate.ergo_tree_bytes()) {
            return Ok(eb);
        }
    }
    Err(MiningError::EmissionInvariant {
        op: "genesis_emission_box",
        reason: "no genesis box carries the emission proposition".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::ergo_box::{serialize_ergo_box, ErgoBoxCandidate};
    use ergo_ser::ergo_tree::read_ergo_tree;
    use ergo_ser::register::AdditionalRegisters;

    // ----- helpers -----

    /// Serialize a genesis box carrying `tree_bytes` as its script.
    fn serialized_box(tree_bytes: &[u8], value: u64) -> Vec<u8> {
        let mut r = VlqReader::new(tree_bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        let cand = ErgoBoxCandidate::from_trusted_raw_parts(
            value,
            tree,
            tree_bytes.to_vec(),
            1,
            Vec::new(),
            AdditionalRegisters::empty(),
            vec![0x00],
        );
        let eb = ErgoBox {
            candidate: cand,
            transaction_id: ModifierId::from_bytes([0u8; 32]),
            index: 0,
        };
        serialize_ergo_box(&eb).unwrap()
    }

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

    // ----- emission box resolution -----

    #[test]
    fn is_emission_box_matches_network_emission_tree() {
        let em = ergo_chain_spec::emission_tree_bytes();
        assert!(
            is_emission_box(&em),
            "the emission proposition IS the emission box"
        );
        // A trivial (non-emission) SigmaProp-rooted tree must not match.
        let trivial = [0x00u8, 0x08, 0xd3];
        assert!(
            !is_emission_box(&trivial),
            "a trivial tree is not the emission box"
        );
    }

    #[test]
    fn genesis_emission_box_finds_the_emission_output() {
        // Two seeded genesis boxes: a decoy (trivial tree) then the
        // emission box. The resolver must pick the emission one out of
        // the set by its script, not by position.
        let decoy = serialized_box(&[0x00u8, 0x08, 0xd3], 1_000);
        let emission = serialized_box(
            &ergo_chain_spec::emission_tree_bytes(),
            93_409_132_500_000_000,
        );
        let boxes = vec![([0x01u8; 32], decoy), ([0x02u8; 32], emission)];

        let eb = genesis_emission_box(&boxes).expect("emission box resolved");
        assert!(
            is_emission_box(eb.candidate.ergo_tree_bytes()),
            "resolved box carries the emission tree"
        );
        assert_eq!(
            eb.candidate.value, 93_409_132_500_000_000,
            "emission box value"
        );
    }

    // ----- error paths -----

    #[test]
    fn genesis_emission_box_absent_errors() {
        let decoy = serialized_box(&[0x00u8, 0x08, 0xd3], 1_000);
        let boxes = vec![([0x01u8; 32], decoy)];
        let err = genesis_emission_box(&boxes).expect_err("no emission box present");
        assert!(format!("{err:?}").contains("emission"), "{err:?}");
    }
}

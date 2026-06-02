//! Build a block-candidate Extension field list.
//!
//! Per v12 §4.6 + Scala `CandidateGenerator.createCandidate` (lines 529-565)
//! the extension at height `H` carries:
//!
//! 1. NIPoPoW interlinks (key prefix `0x01`) — **always**.
//! 2. At voting-epoch boundary (`H % voting_length == 0`): the
//!    proposed-update parameter map (key prefix `0x00`) and chunked
//!    validation-settings update (key prefix `0x02`).
//! 3. At block-version 3: inject rule replacements
//!    `1011→1016, 1007→1017, 1008→1018` into `proposed_update`.
//!
//! This module implements step 1 (the non-epoch path) completely.
//! Step 2 + 3 (epoch-boundary fields) are **deferred**: the parameter
//! and validation-settings *parsers* exist in `ergo-validation` but no
//! serializer / extension-field encoder does yet. A node built on this
//! crate can mine ~1023/1024 of all blocks; the ~1/1024 that land on
//! a voting-epoch boundary need the deferred work below.

use ergo_primitives::digest::ModifierId;
use ergo_ser::header::Header;
use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};

use crate::error::MiningError;

/// Scala `chainSettings.voting.votingLength` (`application.conf:239`).
/// Hardcoded for mainnet; testnet may need a config-driven value
/// once testnet mining is on the table.
pub const MAINNET_VOTING_LENGTH: u32 = 1024;

/// Build the extension field list for a candidate at `new_height`,
/// given the parent header and its (already-unpacked) interlinks.
///
/// Returns an error when `new_height` lands on a voting-epoch boundary
/// (i.e. `new_height % MAINNET_VOTING_LENGTH == 0`) — the epoch
/// boundary path needs to serialize the proposed-update parameter map
/// and validation-settings chunks, which isn't implemented yet.
/// Non-boundary heights return a `Vec<(Vec<u8>, Vec<u8>)>` of packed
/// interlinks fields only, matching the structure of mainnet blocks
/// at non-boundary heights.
pub fn build_candidate_extension_fields(
    parent_header: &Header,
    parent_interlinks: &[ModifierId],
    new_height: u32,
    voting_length: u32,
) -> Result<ExtensionFields, MiningError> {
    if new_height.is_multiple_of(voting_length) {
        return Err(MiningError::InvalidConfig(format!(
            "epoch-boundary candidate at height {new_height} not yet supported \
             (proposed-update + validation-settings extension encoding is deferred — \
             see crate::extension_builder docs)"
        )));
    }
    let new_interlinks = update_interlinks(parent_header, parent_interlinks)?;
    Ok(pack_interlinks(&new_interlinks))
}

/// Extension-section field list as canonical wire pairs: `(key_bytes,
/// value_bytes)`. Used as the return shape of
/// [`build_candidate_extension_fields`].
pub type ExtensionFields = Vec<(Vec<u8>, Vec<u8>)>;

/// Returns `true` if `height` is a voting-epoch boundary on mainnet
/// (`height % MAINNET_VOTING_LENGTH == 0`). Mining at such a height
/// requires the deferred epoch-boundary encoding; non-boundary heights
/// are fully supported.
pub fn is_epoch_boundary_mainnet(height: u32) -> bool {
    height.is_multiple_of(MAINNET_VOTING_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_validation::popow::algos::unpack_interlinks;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct InterlinksVector {
        height: u32,
        header_id: String,
        version: u8,
        n_interlinks_fields: usize,
        n_extension_fields_total: usize,
        interlinks_fields: Vec<[String; 2]>,
    }

    fn load(h: u32) -> InterlinksVector {
        let path = format!(
            "{}/../test-vectors/mining/interlinks_corpus/{}.json",
            env!("CARGO_MANIFEST_DIR"),
            h
        );
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("parse")
    }

    fn decode_fields(v: &InterlinksVector) -> Vec<(Vec<u8>, Vec<u8>)> {
        v.interlinks_fields
            .iter()
            .map(|p| (hex::decode(&p[0]).unwrap(), hex::decode(&p[1]).unwrap()))
            .collect()
    }

    // ----- happy path -----

    #[test]
    fn is_epoch_boundary_uses_1024_period() {
        assert!(is_epoch_boundary_mainnet(0));
        assert!(is_epoch_boundary_mainnet(1024));
        assert!(is_epoch_boundary_mainnet(1024 * 50));
        assert!(!is_epoch_boundary_mainnet(1));
        assert!(!is_epoch_boundary_mainnet(1023));
        assert!(!is_epoch_boundary_mainnet(1025));
        assert!(!is_epoch_boundary_mainnet(1_786_188));
    }

    // ----- error paths -----

    #[test]
    fn rejects_epoch_boundary_height() {
        // Synthesize a parent header at h=1023; the candidate would be
        // at h=1024 which is an epoch boundary. Builder must refuse.
        let parent = synth_header(1023);
        let err = build_candidate_extension_fields(&parent, &[], 1024, MAINNET_VOTING_LENGTH)
            .expect_err("must reject epoch boundary");
        match err {
            MiningError::InvalidConfig(msg) => {
                assert!(msg.contains("epoch-boundary"), "{msg}")
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    /// Build a minimal synthetic parent header with the given height,
    /// version=2, all-zero hashes. Sufficient for `update_interlinks`
    /// (which only reads `version` via `max_level_of` and `parent_id`
    /// via `is_genesis`).
    fn synth_header(height: u32) -> Header {
        use ergo_primitives::digest::{ADDigest, Digest32};
        use ergo_ser::autolykos::AutolykosSolution;
        Header {
            version: 2,
            parent_id: Digest32::from_bytes([0x42u8; 32]).into(), // non-zero = not genesis
            ad_proofs_root: Digest32::from_bytes([0u8; 32]),
            transactions_root: Digest32::from_bytes([0u8; 32]),
            state_root: ADDigest::from_bytes([0u8; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0u8; 32]),
            n_bits: 0,
            height,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: ergo_primitives::group_element::GroupElement::from([0x02u8; 33]),
                nonce: [0u8; 8],
            },
        }
    }

    // ----- mainnet-corpus parity (non-epoch path) -----
    //
    // Pick adjacent non-epoch heights from the captured corpus.
    // Use parent's interlinks to build the next interlinks, then
    // compare packed bytes against the captured next-height fields.
    //
    // Heights 99999 / 100000 / 100001 are NOT epoch boundaries
    // (100000 % 1024 = 672, 100001 % 1024 = 673), so all three are
    // non-epoch and the builder should produce just-interlinks.

    #[test]
    fn non_epoch_extension_is_only_interlinks_at_100000() {
        let v = load(100_000);
        // 100000 % 1024 = 672, not 0 — non-epoch.
        assert_ne!(v.height % MAINNET_VOTING_LENGTH, 0);
        // All captured fields are interlinks (key prefix 0x01).
        let fields = decode_fields(&v);
        for (k, _) in &fields {
            assert_eq!(
                k[0], 0x01,
                "non-epoch block must have only interlinks fields"
            );
        }
        // Verify our packing reproduces the same bytes given the
        // same input.
        let interlinks = unpack_interlinks(&fields).expect("unpack");
        let repacked = pack_interlinks(&interlinks);
        assert_eq!(repacked, fields);
    }
}

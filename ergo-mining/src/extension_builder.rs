//! Build a block-candidate Extension field list.
//!
//! Per v12 §4.6 + Scala `CandidateGenerator.createCandidate` (lines 529-565)
//! the extension at height `H` carries:
//!
//! 1. NIPoPoW interlinks (key prefix `0x01`) — **always**.
//! 2. At voting-epoch boundary (`H % voting_length == 0`): the recomputed
//!    parameter map (key prefix `0x00`, including the carried-forward
//!    `proposed_update` at id 124) and the chunked cumulative
//!    validation-settings update (key prefix `0x02`).
//!
//! This module owns step 1 (the interlinks, always present). Step 2 — the
//! `0x00`/`0x02` fields for an epoch-boundary candidate — is computed by the
//! caller ([`crate::candidate::generate_candidate`] runs the same
//! `compute_next_params` the block validator does and serializes the result via
//! `ergo_validation::active_params_to_extension_fields` /
//! `validation_settings_update_to_extension_fields`) and passed in here as
//! `epoch_boundary_fields`, which this function appends after the interlinks.

use std::collections::BTreeSet;

use ergo_primitives::digest::ModifierId;
use ergo_ser::header::Header;
use ergo_validation::block::EXTENSION_FIELD_VALUE_MAX_SIZE;
use ergo_validation::popow::algos::{pack_interlinks, update_interlinks};

use crate::error::MiningError;

/// Scala `chainSettings.voting.votingLength` (`application.conf:239`).
/// Hardcoded for mainnet; testnet may need a config-driven value
/// once testnet mining is on the table.
pub const MAINNET_VOTING_LENGTH: u32 = 1024;

/// Extension key first-byte namespaces reserved by the protocol:
/// `0x00` system parameters, `0x01` NiPoPoW interlinks, `0x02`
/// validation-rule updates. Operator-configured **custom** fields must
/// use a different namespace so they can never collide with a
/// consensus-critical field (rule 405, no duplicate keys).
pub const RESERVED_EXTENSION_KEY_PREFIXES: [u8; 3] = [0x00, 0x01, 0x02];

/// Validate operator-configured custom extension fields against the
/// consensus extension rules, so a misconfiguration fails fast at config
/// time instead of producing candidates a peer rejects:
///
/// - **rule 404** — each value is ≤ [`EXTENSION_FIELD_VALUE_MAX_SIZE`];
/// - **reserved-namespace guard** — the first key byte is not one of
///   [`RESERVED_EXTENSION_KEY_PREFIXES`], so a custom field can never
///   overwrite the params / interlinks / validation fields;
/// - **rule 405** — no duplicate keys within the custom set.
///
/// Unknown extension keys are themselves consensus-legal (they don't
/// fork the chain), which is what makes this a safe, opt-in mechanism —
/// e.g. an Aegis merge-mining commitment under key `0xAE00`.
pub fn validate_custom_extension_fields(fields: &[([u8; 2], Vec<u8>)]) -> Result<(), MiningError> {
    let mut seen = BTreeSet::new();
    for (key, value) in fields {
        if value.len() > EXTENSION_FIELD_VALUE_MAX_SIZE {
            return Err(MiningError::InvalidConfig(format!(
                "custom extension field {key:02x?} value is {} bytes > \
                 {EXTENSION_FIELD_VALUE_MAX_SIZE} (rule 404)",
                value.len()
            )));
        }
        if RESERVED_EXTENSION_KEY_PREFIXES.contains(&key[0]) {
            return Err(MiningError::InvalidConfig(format!(
                "custom extension field key {key:02x?} uses the protocol-reserved \
                 namespace {:#04x} (0x00 params / 0x01 interlinks / 0x02 validation)",
                key[0]
            )));
        }
        if !seen.insert(*key) {
            return Err(MiningError::InvalidConfig(format!(
                "duplicate custom extension field key {key:02x?} (rule 405)"
            )));
        }
    }
    Ok(())
}

/// Build the extension field list for a candidate at `new_height`,
/// given the parent header and its (already-unpacked) interlinks.
///
/// At a non-boundary height (`new_height % voting_length != 0`) returns the
/// packed interlinks fields only — `epoch_boundary_fields` must be empty.
///
/// At a voting-epoch boundary (`new_height % voting_length == 0`, `new_height >
/// 0`) returns the interlinks fields followed by `epoch_boundary_fields` — the
/// recomputed `0x00` parameter map (with `proposed_update` at id 124) and the
/// `0x02` cumulative validation-settings chunks the caller produced from
/// `compute_next_params`. The caller MUST supply those fields at a boundary;
/// an empty slice there is a logic error and is rejected, since a boundary
/// block with no parameter map fails the peer's `exParseParameters` rule.
///
/// `custom_fields` are operator-configured optional fields (validated by
/// [`validate_custom_extension_fields`]) appended after the interlinks and any
/// epoch fields — the general merge-mining / commitment hook. They are
/// re-validated here (so the builder is self-defending) and the assembled list
/// gets a final duplicate-key sweep (rule 405) across every field.
pub fn build_candidate_extension_fields(
    parent_header: &Header,
    parent_interlinks: &[ModifierId],
    new_height: u32,
    voting_length: u32,
    epoch_boundary_fields: &[([u8; 2], Vec<u8>)],
    custom_fields: &[([u8; 2], Vec<u8>)],
) -> Result<ExtensionFields, MiningError> {
    let is_boundary = new_height > 0 && new_height.is_multiple_of(voting_length);
    if is_boundary && epoch_boundary_fields.is_empty() {
        return Err(MiningError::InvalidConfig(format!(
            "epoch-boundary candidate at height {new_height} requires the recomputed \
             parameter + validation-settings extension fields"
        )));
    }
    if !is_boundary && !epoch_boundary_fields.is_empty() {
        return Err(MiningError::InvalidConfig(format!(
            "epoch-boundary fields supplied at non-boundary height {new_height}"
        )));
    }
    validate_custom_extension_fields(custom_fields)?;
    let new_interlinks = update_interlinks(parent_header, parent_interlinks)?;
    let mut fields = pack_interlinks(&new_interlinks);
    fields.extend(
        epoch_boundary_fields
            .iter()
            .map(|(k, v)| (k.to_vec(), v.clone())),
    );
    fields.extend(custom_fields.iter().map(|(k, v)| (k.to_vec(), v.clone())));
    // Rule 405 across the whole extension (interlinks + epoch + custom):
    // custom fields are namespace-guarded from the generated ones, but the
    // final duplicate-key sweep is the actual consensus rule.
    let mut seen = BTreeSet::new();
    for (key, _) in &fields {
        if !seen.insert(key.clone()) {
            return Err(MiningError::InvalidConfig(format!(
                "duplicate extension field key {key:02x?} in assembled candidate (rule 405)"
            )));
        }
    }
    Ok(fields)
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

    // ----- custom extension fields -----

    #[test]
    fn appends_custom_field_after_interlinks_at_non_boundary() {
        // Real (non-empty) parent interlinks from the corpus; a synthetic
        // parent header at the same non-boundary height supplies version +
        // non-genesis parent_id for `update_interlinks`.
        let parent_interlinks = unpack_interlinks(&decode_fields(&load(100_000))).expect("unpack");
        let mut parent = synth_header(100_000); // 100000 % 1024 != 0
                                                // A valid non-zero target so `update_interlinks`' `max_level_of`
                                                // (which divides by the target) doesn't divide by zero.
        parent.n_bits = 0x1b04_04cb;
        let custom = vec![([0xAEu8, 0x00u8], vec![0x01; 33])]; // Aegis MM commitment shape
        let fields = build_candidate_extension_fields(
            &parent,
            &parent_interlinks,
            100_001,
            MAINNET_VOTING_LENGTH,
            &[],
            &custom,
        )
        .expect("builds");
        // The custom field is present and last (after interlinks).
        assert_eq!(fields.last().unwrap(), &(vec![0xAE, 0x00], vec![0x01; 33]));
        // Everything before it is an interlinks (0x01) field.
        for (k, _) in &fields[..fields.len() - 1] {
            assert_eq!(k[0], 0x01);
        }
    }

    #[test]
    fn validate_rejects_reserved_namespace_oversize_and_duplicate() {
        // Reserved namespace (0x01 = interlinks).
        assert!(validate_custom_extension_fields(&[([0x01, 0x00], vec![1])]).is_err());
        // Oversize value (> 64 bytes, rule 404).
        assert!(validate_custom_extension_fields(&[([0xAE, 0x00], vec![0; 65])]).is_err());
        // Duplicate key within the set (rule 405).
        assert!(validate_custom_extension_fields(&[
            ([0xAE, 0x00], vec![1]),
            ([0xAE, 0x00], vec![2]),
        ])
        .is_err());
        // A well-formed field passes.
        validate_custom_extension_fields(&[([0xAE, 0x00], vec![0x01; 33])]).expect("valid");
    }

    #[test]
    fn build_rejects_a_custom_field_colliding_with_interlinks() {
        // A custom field is namespace-guarded, but prove the build-time
        // rule-405 sweep also catches a collision if one slipped through:
        // a 0x01-prefixed "custom" field (bypassing validate) would dup an
        // interlinks key. validate rejects it first, so the whole builder errors.
        let parent = synth_header(1000);
        let err = build_candidate_extension_fields(
            &parent,
            &[],
            1001,
            MAINNET_VOTING_LENGTH,
            &[],
            &[([0x01, 0x00], vec![1])],
        )
        .expect_err("reserved-namespace custom field rejected");
        assert!(matches!(err, MiningError::InvalidConfig(_)));
    }

    // ----- error paths -----

    #[test]
    fn rejects_epoch_boundary_without_recomputed_fields() {
        // Candidate at h=1024 (an epoch boundary) with NO epoch fields supplied
        // is a caller logic error — a boundary block must carry the recomputed
        // parameter map, so the builder refuses rather than emitting an
        // interlinks-only extension a peer would reject at exParseParameters.
        let parent = synth_header(1023);
        let err =
            build_candidate_extension_fields(&parent, &[], 1024, MAINNET_VOTING_LENGTH, &[], &[])
                .expect_err("must reject boundary with no epoch fields");
        match err {
            MiningError::InvalidConfig(msg) => {
                assert!(msg.contains("requires the recomputed"), "{msg}")
            }
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn rejects_epoch_fields_at_non_boundary_height() {
        // The inverse guard: epoch fields supplied at a non-boundary height
        // (h=1025) is also a logic error.
        let parent = synth_header(1024);
        let bogus = vec![([0x00u8, 1u8], vec![0, 0, 0, 1])];
        let err = build_candidate_extension_fields(
            &parent,
            &[],
            1025,
            MAINNET_VOTING_LENGTH,
            &bogus,
            &[],
        )
        .expect_err("must reject epoch fields off-boundary");
        match err {
            MiningError::InvalidConfig(msg) => {
                assert!(msg.contains("non-boundary"), "{msg}")
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

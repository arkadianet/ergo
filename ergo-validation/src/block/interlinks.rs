use ergo_ser::extension::Extension;
use ergo_ser::header::Header;

use super::error::BlockValidationError;

/// Scala-parity interlink validation for the extension section
/// (rules 401 + 402). Mirrors
/// `ergo-core/.../ExtensionValidator.scala:27-46`. Returns `Ok(())`
/// when there's no parent extension to compare against — that's
/// Scala's `exIlUnableToValidate` recoverable path; only the
/// non-genesis-with-parent-extension case enforces 401/402.
///
/// Behavior on per-input failure modes:
/// - Parent extension decode fails: surfaces rule 402
///   (`InterlinkStructureMismatch`) because the structures can't
///   match (Scala's `Failure(...) == Failure(...)` is always false,
///   so the inequality fires `exIlStructure`).
/// - Current extension decode fails: surfaces rule 401
///   (`InvalidInterlinkEncoding`).
/// - Decoded current != `update_interlinks(parent_header,
///   parent_decoded)`: surfaces rule 402.
pub fn validate_interlinks(
    extension: &Extension,
    parent_header: &Header,
    parent_extension: &Extension,
) -> Result<(), BlockValidationError> {
    let to_kv = |fields: &[ergo_ser::extension::ExtensionField]| -> Vec<(Vec<u8>, Vec<u8>)> {
        fields
            .iter()
            .map(|f| (f.key.to_vec(), f.value.clone()))
            .collect()
    };

    let current_links = crate::popow::algos::unpack_interlinks(&to_kv(&extension.fields))
        .map_err(|reason| BlockValidationError::InvalidInterlinkEncoding { reason })?;

    let parent_links =
        match crate::popow::algos::unpack_interlinks(&to_kv(&parent_extension.fields)) {
            Ok(v) => v,
            Err(decode_err) => {
                // Scala's `Failure` propagates into `expectedLinksTry` and
                // the `expected == current` check fires rule 402.
                return Err(BlockValidationError::InterlinkStructureMismatch {
                    expected_len: 0,
                    got_len: current_links.len(),
                    reason: format!("parent interlinks decode failed: {decode_err}"),
                });
            }
        };

    // Adversarial-input safety: an `Ok([])` parent vector on a
    // non-genesis parent would otherwise hit `update_interlinks`'s
    // `assert!(!prev_interlinks.is_empty(), ...)` and panic the
    // node. Scala's `require` would also raise, but the surrounding
    // `Try` lifts it to a structure mismatch in the validateInterlinks
    // composition. Convert to typed rule 402 reject here so a peer
    // shipping a malformed-but-decodable parent extension cannot
    // crash us.
    if parent_links.is_empty() && !crate::popow::algos::is_genesis(parent_header) {
        return Err(BlockValidationError::InterlinkStructureMismatch {
            expected_len: 0,
            got_len: current_links.len(),
            reason: "parent interlinks empty on non-genesis parent".to_string(),
        });
    }

    let expected_links = crate::popow::algos::update_interlinks(parent_header, &parent_links)
        .map_err(|e| BlockValidationError::InterlinkStructureMismatch {
            expected_len: 0,
            got_len: current_links.len(),
            reason: format!("parent header serialization failed: {e}"),
        })?;
    if expected_links != current_links {
        return Err(BlockValidationError::InterlinkStructureMismatch {
            expected_len: expected_links.len(),
            got_len: current_links.len(),
            reason: "length mismatch".to_string(),
        });
    }

    Ok(())
}

/// Rules 401 / 402 (`exIlEncoding` / `exIlStructure`) — interlink
/// validation against the parent extension.
#[cfg(test)]
mod interlinks_tests {
    use super::*;
    use crate::popow::algos::{update_interlinks, INTERLINKS_VECTOR_PREFIX};
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::extension::ExtensionField;

    fn test_header(height: u32, n_bits: u32) -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0; 32]),
            ad_proofs_root: Digest32::from_bytes([0; 32]),
            transactions_root: Digest32::from_bytes([0; 32]),
            state_root: ADDigest::from_bytes([0; 33]),
            timestamp: 0,
            extension_root: Digest32::from_bytes([0; 32]),
            n_bits,
            height,
            votes: [0; 3],
            unparsed_bytes: Vec::new(),
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0; 8],
            },
        }
    }

    /// Pack an interlinks vector into wire-form extension fields
    /// matching `unpack_interlinks` (RLE: first byte is the
    /// duplicate count of the following 32-byte id).
    fn interlinks_to_fields(links: &[ModifierId]) -> Vec<ExtensionField> {
        // Run-length encode consecutive duplicates.
        let mut out: Vec<ExtensionField> = Vec::new();
        let mut idx: u8 = 0;
        let mut i = 0;
        while i < links.len() {
            let mut run = 1usize;
            while i + run < links.len() && links[i + run] == links[i] && run < 255 {
                run += 1;
            }
            let mut value = Vec::with_capacity(33);
            value.push(run as u8);
            value.extend_from_slice(links[i].as_bytes());
            out.push(ExtensionField {
                key: [INTERLINKS_VECTOR_PREFIX, idx],
                value,
            });
            idx = idx.wrapping_add(1);
            i += run;
        }
        out
    }

    fn ext_with_links(header_id: [u8; 32], links: &[ModifierId]) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields: interlinks_to_fields(links),
        }
    }

    fn ext_with_fields(header_id: [u8; 32], fields: Vec<ExtensionField>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields,
        }
    }

    #[test]
    fn validate_interlinks_passes_when_current_matches_updated_parent() {
        // Set up: parent header with some parent interlinks.
        // Current interlinks must equal update_interlinks(parent_header,
        // parent_links).
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![
            ModifierId::from_bytes([0xAA; 32]),
            ModifierId::from_bytes([0xBB; 32]),
        ];
        let expected = update_interlinks(&parent, &parent_links)
            .expect("test fixture parent header serializes");

        let parent_ext = ext_with_links([0; 32], &parent_links);
        let current_ext = ext_with_links([1; 32], &expected);

        validate_interlinks(&current_ext, &parent, &parent_ext).unwrap();
    }

    #[test]
    fn validate_interlinks_rejects_structure_mismatch() {
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![ModifierId::from_bytes([0xAA; 32])];
        let expected = update_interlinks(&parent, &parent_links)
            .expect("test fixture parent header serializes");

        let parent_ext = ext_with_links([0; 32], &parent_links);
        // Wrong: drop the last expected entry to force a mismatch.
        let mangled: Vec<ModifierId> = expected[..expected.len().saturating_sub(1)].to_vec();
        let current_ext = ext_with_links([1; 32], &mangled);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        match err {
            BlockValidationError::InterlinkStructureMismatch {
                expected_len,
                got_len,
                reason,
            } => {
                assert_eq!(expected_len, expected.len());
                assert_eq!(got_len, mangled.len());
                assert_eq!(reason, "length mismatch");
            }
            other => panic!("expected InterlinkStructureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_interlinks_rejects_empty_parent_on_non_genesis_no_panic() {
        // Adversarial-input regression: parent extension has no
        // interlink fields, parent header is non-genesis. Before
        // the guard, this would hit `update_interlinks` `assert!`
        // and panic. Must surface as rule 402 with the named reason.
        let mut parent = test_header(10, 0x20000000);
        // Non-genesis: any non-zero parent_id byte breaks the
        // `parent_id == [0; 32]` test in `is_genesis`.
        parent.parent_id = ModifierId::from_bytes([0xFF; 32]);

        let parent_ext = ext_with_fields([0; 32], vec![]); // no interlink fields
        let current_ext = ext_with_links([1; 32], &[ModifierId::from_bytes([0xCC; 32])]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        match err {
            BlockValidationError::InterlinkStructureMismatch { reason, .. } => {
                assert!(
                    reason.contains("empty on non-genesis"),
                    "unexpected reason: {reason}",
                );
            }
            other => panic!("expected InterlinkStructureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_interlinks_rejects_encoding_failure() {
        // Current extension has an interlinks field whose value is
        // an invalid length (rule 401 — decode error).
        let parent = test_header(10, 0x20000000);
        let parent_links = vec![ModifierId::from_bytes([0xAA; 32])];
        let parent_ext = ext_with_links([0; 32], &parent_links);

        let bad_field = ExtensionField {
            key: [INTERLINKS_VECTOR_PREFIX, 0],
            value: vec![0x01, 0xCC], // 2 bytes, expected 33
        };
        let current_ext = ext_with_fields([1; 32], vec![bad_field]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::InvalidInterlinkEncoding { .. }
        ));
    }

    #[test]
    fn validate_interlinks_surfaces_structure_when_parent_decode_fails() {
        // Parent extension itself has malformed interlinks.
        // Scala's `Failure(...) == Failure(...)` is always false, so
        // rule 402 fires. We map that to InterlinkStructureMismatch.
        let parent = test_header(10, 0x20000000);
        let bad_parent_field = ExtensionField {
            key: [INTERLINKS_VECTOR_PREFIX, 0],
            value: vec![0x01], // 1 byte, expected 33
        };
        let parent_ext = ext_with_fields([0; 32], vec![bad_parent_field]);

        // Current has SOME valid links.
        let current_ext = ext_with_links([1; 32], &[ModifierId::from_bytes([0xCC; 32])]);

        let err = validate_interlinks(&current_ext, &parent, &parent_ext).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::InterlinkStructureMismatch { .. }
        ));
    }

    #[test]
    fn validate_interlinks_with_no_interlinks_in_either_extension() {
        // Both extensions carry zero interlink fields. Scala unpacks
        // each as `Success(Vec::empty())` and update_interlinks on a
        // non-genesis parent with empty prev would panic our impl —
        // but we never call update_interlinks here because the
        // parent isn't genesis. Pin behavior at the caller boundary:
        // this combination is what an early-NiPoPoW-disabled node
        // would have, and the check should treat it as
        // "current == expected" only when both are empty AND parent
        // is genesis. For non-genesis with empty interlinks, the
        // update_interlinks `require(prevInterlinks.nonEmpty)`
        // assertion fires — which is correct Scala behavior.
        //
        // Pin: this test only confirms the genesis case is graceful;
        // the assertion-on-empty-prev case is documented as caller
        // responsibility (Scala's `require` is the matching
        // behavior).
        let parent = test_header(0, 0x20000000); // genesis (height 0)
        let parent_ext = ext_with_fields([0; 32], vec![]);
        let expected =
            update_interlinks(&parent, &[]).expect("test fixture genesis header serializes");
        let current_ext = ext_with_links([1; 32], &expected);

        validate_interlinks(&current_ext, &parent, &parent_ext).unwrap();
    }
}

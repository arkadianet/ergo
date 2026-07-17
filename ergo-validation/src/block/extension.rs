use ergo_ser::extension::Extension;

use super::error::BlockValidationError;

/// Scala `Constants.MaxExtensionSize` — 32 KiB. Wire-form upper bound
/// for the entire serialized extension section (not just the fields).
pub const MAX_EXTENSION_SIZE: usize = 32 * 1024;

/// Scala `Extension.FieldValueMaxSize` — 64 bytes. Per-field value
/// cap. Our codec accepts up to 255 (u8 length-prefix wire form);
/// the validator enforces the tighter Scala cap so an oversize-but-
/// parseable value gets rejected at apply time rather than silently
/// passing.
pub const EXTENSION_FIELD_VALUE_MAX_SIZE: usize = 64;

/// VLQ-encoded byte length of a `u16` value as the `VlqWriter::put_u16`
/// emits it. 0..=127 → 1 byte; 128..=16383 → 2 bytes; 16384..=65535 →
/// 3 bytes. The Scala `ExtensionSerializer` uses the same VLQ shape
/// for the field count prefix.
fn vlq_u16_size(v: u16) -> usize {
    if v < 128 {
        1
    } else if v < 16_384 {
        2
    } else {
        3
    }
}

/// Compute the serialized byte-count of an `Extension` without
/// round-tripping through the writer. Mirrors `write_extension`
/// (`ergo-ser/src/extension.rs`) exactly:
/// `32 (header_id) + VLQ(count) + Σ (2 key bytes + 1 length byte +
/// value bytes)`.
///
/// The 32-byte `header_id` and the VLQ-encoded count must both be
/// included; the size cap bounds the FULL serialized section, so a
/// shorter accounting could let an adversarial extension crafted to
/// sit just above the cap slip past.
fn serialized_extension_size(extension: &Extension) -> usize {
    let count = extension.fields.len().min(u16::MAX as usize) as u16;
    let mut total: usize = 32; // header_id
    total = total.saturating_add(vlq_u16_size(count));
    for field in &extension.fields {
        // 2 key bytes + 1 length byte + value bytes
        total = total.saturating_add(3).saturating_add(field.value.len());
    }
    total
}

/// Scala-parity structural checks for an extension section
/// (rules 400 / 404 / 405 / 406). Runs on every block, not just
/// epoch boundaries; called from [`validate_full_block`](super::validate::validate_full_block)
/// between the extension-root match and the per-tx loop.
pub fn validate_extension_structural(
    extension: &Extension,
    block_height: u32,
) -> Result<(), BlockValidationError> {
    // 406: non-genesis block must carry at least one extension field.
    if block_height != 0 && extension.fields.is_empty() {
        return Err(BlockValidationError::ExtensionEmptyOnNonGenesis {
            height: block_height,
        });
    }

    // 400: total serialized size cap.
    let size = serialized_extension_size(extension);
    if size > MAX_EXTENSION_SIZE {
        return Err(BlockValidationError::ExtensionTooLarge {
            size,
            max: MAX_EXTENSION_SIZE,
        });
    }

    // 404: per-field value-length cap.
    for (index, field) in extension.fields.iter().enumerate() {
        if field.value.len() > EXTENSION_FIELD_VALUE_MAX_SIZE {
            return Err(BlockValidationError::ExtensionFieldValueTooLong {
                index,
                len: field.value.len(),
                max: EXTENSION_FIELD_VALUE_MAX_SIZE,
            });
        }
    }

    // 405: no two fields share a key. O(N²) over fields is fine —
    // mainnet extensions hold 4-30 entries, never enough to merit
    // a HashSet allocation.
    for first in 0..extension.fields.len() {
        let key = extension.fields[first].key;
        for second in (first + 1)..extension.fields.len() {
            if extension.fields[second].key == key {
                return Err(BlockValidationError::ExtensionDuplicateKey {
                    key: hex::encode(key),
                    first,
                    second,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod extension_structural_tests {
    //! Tests for `validate_extension_structural` (rules 400, 404, 405, 406).
    use super::*;
    use ergo_primitives::digest::ModifierId;
    use ergo_ser::extension::{Extension, ExtensionField};

    fn ext(header_id: [u8; 32], fields: Vec<ExtensionField>) -> Extension {
        Extension {
            header_id: ModifierId::from_bytes(header_id),
            fields,
        }
    }

    fn field(key: [u8; 2], value: Vec<u8>) -> ExtensionField {
        ExtensionField { key, value }
    }

    // ----- rule 406: exEmpty -----

    #[test]
    fn empty_extension_on_genesis_height_is_allowed() {
        let e = ext([0; 32], Vec::new());
        assert!(validate_extension_structural(&e, 0).is_ok());
    }

    #[test]
    fn empty_extension_on_non_genesis_height_is_rejected() {
        let e = ext([0; 32], Vec::new());
        let err = validate_extension_structural(&e, 1).unwrap_err();
        assert!(matches!(
            err,
            BlockValidationError::ExtensionEmptyOnNonGenesis { height: 1 }
        ));
    }

    // ----- rule 400: exSize -----

    #[test]
    fn extension_under_size_cap_passes() {
        let e = ext([0; 32], vec![field([0x00, 0x01], vec![0xAA; 32])]);
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn extension_over_size_cap_is_rejected() {
        // Construct an extension that overflows the 32 KiB cap.
        // Each entry contributes 2+1+value_len bytes; the count
        // prefix adds 2. With value_len = 60 (under the 404 cap),
        // each field is 63 wire bytes — so 600 fields yield 37+ KB.
        let fields: Vec<ExtensionField> = (0u16..600)
            .map(|i| field([(i >> 8) as u8, i as u8], vec![0xCC; 60]))
            .collect();
        let e = ext([0; 32], fields);
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionTooLarge { size, max } => {
                assert_eq!(max, MAX_EXTENSION_SIZE);
                assert!(
                    size > MAX_EXTENSION_SIZE,
                    "fixture must actually exceed cap, got size={size}",
                );
            }
            other => panic!("expected ExtensionTooLarge, got {other:?}"),
        }
    }

    // ----- rule 404: exValueLength -----

    #[test]
    fn field_value_at_cap_passes() {
        let e = ext(
            [0; 32],
            vec![field(
                [0x00, 0x01],
                vec![0xAA; EXTENSION_FIELD_VALUE_MAX_SIZE],
            )],
        );
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn field_value_one_byte_over_cap_is_rejected() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA; 32]),
                field([0x00, 0x02], vec![0xBB; EXTENSION_FIELD_VALUE_MAX_SIZE + 1]),
            ],
        );
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionFieldValueTooLong { index, len, max } => {
                assert_eq!(index, 1);
                assert_eq!(len, EXTENSION_FIELD_VALUE_MAX_SIZE + 1);
                assert_eq!(max, EXTENSION_FIELD_VALUE_MAX_SIZE);
            }
            other => panic!("expected ExtensionFieldValueTooLong, got {other:?}"),
        }
    }

    // ----- rule 405: exDuplicateKeys -----

    #[test]
    fn distinct_keys_pass() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA]),
                field([0x00, 0x02], vec![0xBB]),
                field([0x00, 0x03], vec![0xCC]),
            ],
        );
        assert!(validate_extension_structural(&e, 1).is_ok());
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let e = ext(
            [0; 32],
            vec![
                field([0x00, 0x01], vec![0xAA]),
                field([0x00, 0x02], vec![0xBB]),
                field([0x00, 0x01], vec![0xCC]), // duplicate of first
            ],
        );
        let err = validate_extension_structural(&e, 1).unwrap_err();
        match err {
            BlockValidationError::ExtensionDuplicateKey { key, first, second } => {
                assert_eq!(key, "0001");
                assert_eq!(first, 0);
                assert_eq!(second, 2);
            }
            other => panic!("expected ExtensionDuplicateKey, got {other:?}"),
        }
    }

    // ----- serialized_extension_size sanity -----

    #[test]
    fn serialized_extension_size_matches_write_extension_round_trip() {
        // The size helper must agree with the actual writer
        // byte-count. Walk a few cardinalities (0, 1, 127, 128,
        // 1000) so the VLQ count-prefix size changes are exercised.
        use ergo_primitives::writer::VlqWriter;
        for n in [0u16, 1, 127, 128, 1000] {
            let fields: Vec<ExtensionField> = (0..n)
                .map(|i| field([(i >> 8) as u8, i as u8], vec![0xAA; 4]))
                .collect();
            let e = ext([0xCC; 32], fields);
            let computed = serialized_extension_size(&e);
            let mut w = VlqWriter::new();
            ergo_ser::extension::write_extension(&mut w, &e).unwrap();
            let actual = w.result().len();
            assert_eq!(
                computed, actual,
                "size helper drift at n={n}: computed={computed}, actual={actual}",
            );
        }
    }

    #[test]
    fn serialized_extension_size_includes_header_id() {
        // Sanity: even an empty extension consumes 32 (header_id)
        // + 1 (VLQ-encoded count=0) = 33 bytes on the wire. An
        // earlier bug used 2 for the count and dropped the
        // header_id entirely, returning 2.
        let e = ext([0; 32], Vec::new());
        assert_eq!(serialized_extension_size(&e), 33);
    }
}

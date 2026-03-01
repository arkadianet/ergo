//! Extension block validation (rules 400, 403-406).
//!
//! Validates the Extension section of an Ergo block according to the
//! consensus rules defined in the Scala reference node's `ExtensionValidator`.

use std::collections::HashSet;

use ergo_types::extension::{Extension, FIELD_VALUE_MAX_SIZE};

/// Maximum serialized size of an extension section (32 KiB).
///
/// Corresponds to `Constants.MaxExtensionSize` in the Scala node.
pub const MAX_EXTENSION_SIZE: usize = 32 * 1024;

/// Required key length for extension fields (2 bytes).
const FIELD_KEY_SIZE: usize = 2;

/// Errors from extension validation.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionValidationError {
    /// Rule 400 (exSize): extension serialized size exceeds `MAX_EXTENSION_SIZE`.
    #[error("extension too large: {size} bytes (max {MAX_EXTENSION_SIZE})")]
    TooLarge { size: usize },

    /// Rule 403 (exKeyLength): a field key has wrong length.
    #[error("extension key wrong length: {len} (expected {FIELD_KEY_SIZE})")]
    KeyLength { len: usize },

    /// Rule 404 (exValueLength): a field value exceeds `FIELD_VALUE_MAX_SIZE`.
    #[error("extension value too large: {len} bytes (max {FIELD_VALUE_MAX_SIZE})")]
    ValueLength { len: usize },

    /// Rule 405 (exDuplicateKeys): duplicate key found.
    #[error("duplicate extension key: [{}, {}]", key[0], key[1])]
    DuplicateKey { key: [u8; 2] },

    /// Rule 406 (exEmpty): non-genesis block has empty extension.
    #[error("non-genesis block has empty extension")]
    Empty,

    /// Rule 401 (exIlEncoding): interlinks encoding is invalid.
    #[error("interlinks encoding error: {0}")]
    InterlinkEncoding(String),

    /// Rule 402 (exIlStructure): interlinks structure doesn't match expected.
    #[error("interlinks structure mismatch: expected {expected} entries, got {got}")]
    InterlinkMismatch { expected: usize, got: usize },
}

/// Validate an Extension block section.
///
/// Implements rules 400, 403-406 from the Scala reference `ExtensionValidator`
/// and `ErgoStateContext`.
///
/// # Arguments
///
/// * `ext` - The extension to validate.
/// * `is_genesis` - Whether this is the genesis block (height 0 or 1).
/// * `serialized_size` - The byte length of the serialized extension on the wire.
///   In the Scala node this is `extension.size` (the serialized byte length).
pub fn validate_extension(
    ext: &Extension,
    is_genesis: bool,
    serialized_size: usize,
) -> Result<(), ExtensionValidationError> {
    // Rule 400 (exSize): total serialized size <= MAX_EXTENSION_SIZE
    if serialized_size > MAX_EXTENSION_SIZE {
        return Err(ExtensionValidationError::TooLarge {
            size: serialized_size,
        });
    }

    // Rule 403 (exKeyLength): all keys must be exactly 2 bytes.
    // Already enforced by the Rust type system ([u8; 2]), but we keep
    // the check for completeness with the Scala validation rules.
    // (This is a no-op for our type-safe representation.)

    // Rule 404 (exValueLength): all values <= FIELD_VALUE_MAX_SIZE (64 bytes)
    for (_, value) in &ext.fields {
        if value.len() > FIELD_VALUE_MAX_SIZE {
            return Err(ExtensionValidationError::ValueLength { len: value.len() });
        }
    }

    // Rule 405 (exDuplicateKeys): no duplicate keys
    let mut seen = HashSet::new();
    for (key, _) in &ext.fields {
        if !seen.insert(*key) {
            return Err(ExtensionValidationError::DuplicateKey { key: *key });
        }
    }

    // Rule 406 (exEmpty): non-genesis blocks must have at least one field
    if !is_genesis && ext.fields.is_empty() {
        return Err(ExtensionValidationError::Empty);
    }

    Ok(())
}

/// Compute the serialized byte size of an Extension.
///
/// Wire layout (matching `ExtensionSerializer` in Scala):
/// ```text
/// [32 bytes: header_id]
/// [VLQ UShort: field_count]
/// for each field:
///   [2 bytes: key]
///   [1 byte UByte: value_length]
///   [value_length bytes: value]
/// ```
///
/// The VLQ UShort for `field_count` is 1 byte when count < 128, 2 bytes
/// when < 16384, etc. We compute the exact VLQ size.
pub fn compute_extension_serialized_size(ext: &Extension) -> usize {
    let mut size: usize = 32; // header_id

    // VLQ UShort for field count
    size += vlq_ushort_size(ext.fields.len() as u16);

    // Each field: 2 (key) + 1 (value length byte) + value.len()
    for (_, value) in &ext.fields {
        size += 2 + 1 + value.len();
    }

    size
}

/// Returns the number of bytes needed to VLQ-encode a u16 value.
fn vlq_ushort_size(value: u16) -> usize {
    if value < 128 {
        1
    } else if value < 16384 {
        2
    } else {
        3
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::modifier_id::ModifierId;

    fn make_ext(fields: Vec<([u8; 2], Vec<u8>)>) -> Extension {
        Extension {
            header_id: ModifierId([0u8; 32]),
            fields,
        }
    }

    #[test]
    fn valid_extension_passes() {
        let ext = make_ext(vec![([0x00, 0x01], vec![1, 2, 3, 4])]);
        assert!(validate_extension(&ext, false, 10).is_ok());
    }

    #[test]
    fn empty_extension_rejected_for_non_genesis() {
        let ext = make_ext(vec![]);
        assert!(validate_extension(&ext, false, 0).is_err());
    }

    #[test]
    fn empty_extension_allowed_for_genesis() {
        let ext = make_ext(vec![]);
        assert!(validate_extension(&ext, true, 0).is_ok());
    }

    #[test]
    fn duplicate_keys_rejected() {
        let ext = make_ext(vec![([0x00, 0x01], vec![1]), ([0x00, 0x01], vec![2])]);
        let err = validate_extension(&ext, false, 20).unwrap_err();
        assert!(
            matches!(err, ExtensionValidationError::DuplicateKey { key } if key == [0x00, 0x01])
        );
    }

    #[test]
    fn value_too_large_rejected() {
        let ext = make_ext(vec![([0x00, 0x01], vec![0u8; 65])]);
        let err = validate_extension(&ext, false, 70).unwrap_err();
        assert!(matches!(err, ExtensionValidationError::ValueLength { len } if len == 65));
    }

    #[test]
    fn value_at_max_size_passes() {
        let ext = make_ext(vec![([0x00, 0x01], vec![0u8; 64])]);
        assert!(validate_extension(&ext, false, 100).is_ok());
    }

    #[test]
    fn extension_too_large_rejected() {
        let ext = make_ext(vec![([0x00, 0x01], vec![1])]);
        let err = validate_extension(&ext, false, 33 * 1024).unwrap_err();
        assert!(matches!(err, ExtensionValidationError::TooLarge { .. }));
    }

    #[test]
    fn extension_at_max_size_passes() {
        let ext = make_ext(vec![([0x00, 0x01], vec![1])]);
        assert!(validate_extension(&ext, false, MAX_EXTENSION_SIZE).is_ok());
    }

    #[test]
    fn compute_serialized_size_empty() {
        let ext = make_ext(vec![]);
        // 32 (header_id) + 1 (VLQ for 0 fields) = 33
        assert_eq!(compute_extension_serialized_size(&ext), 33);
    }

    #[test]
    fn compute_serialized_size_one_field() {
        let ext = make_ext(vec![([0x00, 0x01], vec![0x10, 0x20])]);
        // 32 (header_id) + 1 (VLQ for 1 field) + 2 (key) + 1 (val_len) + 2 (value) = 38
        assert_eq!(compute_extension_serialized_size(&ext), 38);
    }

    #[test]
    fn compute_serialized_size_multiple_fields() {
        let ext = make_ext(vec![
            ([0x00, 0x01], vec![0x10]),     // 2 + 1 + 1 = 4
            ([0x01, 0x00], vec![0xFF; 32]), // 2 + 1 + 32 = 35
            ([0x02, 0x05], vec![0x42]),     // 2 + 1 + 1 = 4
        ]);
        // 32 (header_id) + 1 (VLQ for 3 fields) + 4 + 35 + 4 = 76
        assert_eq!(compute_extension_serialized_size(&ext), 76);
    }

    #[test]
    fn vlq_ushort_size_values() {
        assert_eq!(vlq_ushort_size(0), 1);
        assert_eq!(vlq_ushort_size(127), 1);
        assert_eq!(vlq_ushort_size(128), 2);
        assert_eq!(vlq_ushort_size(16383), 2);
        assert_eq!(vlq_ushort_size(16384), 3);
        assert_eq!(vlq_ushort_size(u16::MAX), 3);
    }

    #[test]
    fn multiple_unique_keys_pass() {
        let ext = make_ext(vec![
            ([0x00, 0x01], vec![1]),
            ([0x00, 0x02], vec![2]),
            ([0x01, 0x01], vec![3]),
        ]);
        assert!(validate_extension(&ext, false, 50).is_ok());
    }

    #[test]
    fn error_display_too_large() {
        let err = ExtensionValidationError::TooLarge { size: 40000 };
        assert!(err.to_string().contains("40000"));
        assert!(err.to_string().contains("32768"));
    }

    #[test]
    fn error_display_duplicate_key() {
        let err = ExtensionValidationError::DuplicateKey { key: [0x01, 0x02] };
        assert!(err.to_string().contains("1"));
        assert!(err.to_string().contains("2"));
    }

    #[test]
    fn error_display_empty() {
        let err = ExtensionValidationError::Empty;
        assert!(err.to_string().contains("empty"));
    }
}

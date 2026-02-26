use crate::modifier_id::ModifierId;

/// Maximum size in bytes for a single field value in an extension section.
pub const FIELD_VALUE_MAX_SIZE: usize = 64;

/// Size in bytes of each field key (fixed 2-byte key).
pub const FIELD_KEY_SIZE: usize = 2;

/// First byte prefix for system parameter keys.
pub const SYSTEM_PARAMETERS_PREFIX: u8 = 0x00;

/// First byte prefix for interlinks vector keys.
pub const INTERLINKS_VECTOR_PREFIX: u8 = 0x01;

/// First byte prefix for validation rules keys.
pub const VALIDATION_RULES_PREFIX: u8 = 0x02;

/// The extension section of a block, containing key-value data
/// such as system parameters, interlinks, and validation rules.
///
/// Corresponds to `Extension` (modifier type ID 108) in the Scala Ergo node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The ID of the header this extension belongs to.
    pub header_id: ModifierId,
    /// Key-value fields where each key is exactly 2 bytes.
    pub fields: Vec<([u8; 2], Vec<u8>)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_value_max_size_constant() {
        assert_eq!(FIELD_VALUE_MAX_SIZE, 64);
    }

    #[test]
    fn field_key_size_constant() {
        assert_eq!(FIELD_KEY_SIZE, 2);
    }

    #[test]
    fn system_parameters_prefix_value() {
        assert_eq!(SYSTEM_PARAMETERS_PREFIX, 0x00);
    }

    #[test]
    fn interlinks_vector_prefix_value() {
        assert_eq!(INTERLINKS_VECTOR_PREFIX, 0x01);
    }

    #[test]
    fn validation_rules_prefix_value() {
        assert_eq!(VALIDATION_RULES_PREFIX, 0x02);
    }

    #[test]
    fn create_extension_with_empty_fields() {
        let ext = Extension {
            header_id: ModifierId([0xaa; 32]),
            fields: Vec::new(),
        };
        assert_eq!(ext.header_id, ModifierId([0xaa; 32]));
        assert!(ext.fields.is_empty());
    }

    #[test]
    fn create_extension_with_fields() {
        let fields = vec![
            ([SYSTEM_PARAMETERS_PREFIX, 0x01], vec![0x10, 0x20]),
            ([INTERLINKS_VECTOR_PREFIX, 0x00], vec![0xff; 32]),
            ([VALIDATION_RULES_PREFIX, 0x05], vec![0x01]),
        ];
        let ext = Extension {
            header_id: ModifierId([0xbb; 32]),
            fields,
        };
        assert_eq!(ext.fields.len(), 3);
        assert_eq!(ext.fields[0].0[0], SYSTEM_PARAMETERS_PREFIX);
        assert_eq!(ext.fields[1].0[0], INTERLINKS_VECTOR_PREFIX);
        assert_eq!(ext.fields[2].0[0], VALIDATION_RULES_PREFIX);
        assert_eq!(ext.fields[0].1, vec![0x10, 0x20]);
    }

    #[test]
    fn extension_clone_and_eq() {
        let ext = Extension {
            header_id: ModifierId([0x01; 32]),
            fields: vec![([0x00, 0x01], vec![0x42])],
        };
        let cloned = ext.clone();
        assert_eq!(ext, cloned);
    }
}

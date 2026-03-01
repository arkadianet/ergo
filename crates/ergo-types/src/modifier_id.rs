use std::fmt;

/// A 32-byte identifier for block modifiers (headers, transactions, etc.).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModifierId(pub [u8; 32]);

impl ModifierId {
    /// The parent ID used for the genesis block header.
    pub const GENESIS_PARENT: Self = Self([0u8; 32]);

    /// Returns the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ModifierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ModifierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ModifierId({})", self)
    }
}

/// A 32-byte cryptographic digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Digest32(pub [u8; 32]);

/// A 33-byte authenticated data structure digest (used for state root).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ADDigest(pub [u8; 33]);

/// Identifies the type of a block modifier.
#[repr(i8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModifierTypeId {
    Transaction = 2,
    Header = 101,
    BlockTransactions = 102,
    ADProofs = 104,
    Extension = 108,
}

impl ModifierTypeId {
    /// Attempts to convert a raw byte value into a `ModifierTypeId`.
    pub fn from_byte(value: i8) -> Option<Self> {
        match value {
            2 => Some(Self::Transaction),
            101 => Some(Self::Header),
            102 => Some(Self::BlockTransactions),
            104 => Some(Self::ADProofs),
            108 => Some(Self::Extension),
            _ => None,
        }
    }

    /// Returns true if the given type byte represents a block section (value >= 50).
    pub fn is_block_section(value: i8) -> bool {
        value >= 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifier_id_from_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0xcd;
        let id = ModifierId(bytes);
        assert_eq!(id.as_bytes()[0], 0xab);
        assert_eq!(id.as_bytes()[31], 0xcd);
    }

    #[test]
    fn display_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xff;
        bytes[1] = 0x01;
        let id = ModifierId(bytes);
        let hex = format!("{}", id);
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("ff01"));
    }

    #[test]
    fn digest32_from_slice() {
        let bytes = [0x42u8; 32];
        let digest = Digest32(bytes);
        assert_eq!(digest.0.len(), 32);
        assert_eq!(digest.0[0], 0x42);
    }

    #[test]
    fn ad_digest_size() {
        let digest = ADDigest([0u8; 33]);
        assert_eq!(digest.0.len(), 33);
    }

    #[test]
    fn genesis_parent_id() {
        let parent = ModifierId::GENESIS_PARENT;
        assert_eq!(parent.0, [0u8; 32]);
    }

    #[test]
    fn modifier_type_id_values() {
        assert_eq!(
            ModifierTypeId::from_byte(2),
            Some(ModifierTypeId::Transaction)
        );
        assert_eq!(ModifierTypeId::from_byte(101), Some(ModifierTypeId::Header));
        assert_eq!(
            ModifierTypeId::from_byte(102),
            Some(ModifierTypeId::BlockTransactions)
        );
        assert_eq!(
            ModifierTypeId::from_byte(104),
            Some(ModifierTypeId::ADProofs)
        );
        assert_eq!(
            ModifierTypeId::from_byte(108),
            Some(ModifierTypeId::Extension)
        );
        assert_eq!(ModifierTypeId::from_byte(0), None);
        assert_eq!(ModifierTypeId::from_byte(99), None);

        // Block section checks
        assert!(!ModifierTypeId::is_block_section(2));
        assert!(!ModifierTypeId::is_block_section(49));
        assert!(ModifierTypeId::is_block_section(50));
        assert!(ModifierTypeId::is_block_section(101));
        assert!(ModifierTypeId::is_block_section(108));
    }
}

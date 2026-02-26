/// Length of hash function output (Blake2b-256) used throughout Ergo
pub const HASH_LENGTH: usize = 32;

/// Modifier (block section) ID size in bytes
pub const MODIFIER_ID_SIZE: usize = HASH_LENGTH;

/// nanoERG per ERG
pub const COINS_IN_ONE_ERG: u64 = 1_000_000_000;

/// Target: one block every 2 minutes
pub const BLOCKS_PER_HOUR: u32 = 30;
pub const BLOCKS_PER_DAY: u32 = BLOCKS_PER_HOUR * 24;
pub const BLOCKS_PER_WEEK: u32 = BLOCKS_PER_DAY * 7;
pub const BLOCKS_PER_MONTH: u32 = BLOCKS_PER_DAY * 30;
pub const BLOCKS_PER_YEAR: u32 = BLOCKS_PER_DAY * 365;

/// Boxes can exist for 4 years without paying storage rent
pub const STORAGE_PERIOD: u32 = 4 * BLOCKS_PER_YEAR;

/// Cost per byte per storage period in nanoERG
pub const STORAGE_CONTRACT_COST: u64 = 50;

/// Number of last block headers available in scripts
pub const LAST_HEADERS_IN_CONTEXT: u32 = 10;

/// Soft fork voting epochs (~45.5 days)
pub const SOFT_FORK_EPOCHS: u32 = 32;

/// Maximum extension section size (bytes)
pub const MAX_EXTENSION_SIZE: usize = 32 * 1024;

/// Maximum extension size during parsing (bytes)
pub const MAX_EXTENSION_SIZE_MAX: usize = 1024 * 1024;

/// P2P message magic bytes length
pub const MAGIC_LENGTH: usize = 4;

/// P2P message checksum length (first 4 bytes of blake2b256)
pub const CHECKSUM_LENGTH: usize = 4;

/// P2P message header length: magic(4) + code(1) + length(4) = 9
pub const MESSAGE_HEADER_LENGTH: usize = MAGIC_LENGTH + 5;

/// Maximum handshake message size (bytes)
pub const MAX_HANDSHAKE_SIZE: usize = 8096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coins_in_one_erg() {
        assert_eq!(COINS_IN_ONE_ERG, 1_000_000_000);
    }

    #[test]
    fn hash_length() {
        assert_eq!(HASH_LENGTH, 32);
    }

    #[test]
    fn blocks_per_hour() {
        assert_eq!(BLOCKS_PER_HOUR, 30);
    }

    #[test]
    fn blocks_per_day() {
        assert_eq!(BLOCKS_PER_DAY, 720);
    }

    #[test]
    fn blocks_per_year() {
        assert_eq!(BLOCKS_PER_YEAR, 262_800);
    }

    #[test]
    fn storage_period() {
        assert_eq!(STORAGE_PERIOD, 1_051_200);
    }

    #[test]
    fn modifier_id_size() {
        assert_eq!(MODIFIER_ID_SIZE, 32);
    }
}

use crate::modifier_id::{ADDigest, Digest32, ModifierId};

/// Version byte for the initial Ergo protocol.
pub const INITIAL_VERSION: u8 = 1;

/// Version byte after the hardening hard-fork.
pub const HARDENING_VERSION: u8 = 2;

/// Version byte introducing interpreter 5.0.
pub const INTERPRETER_50_VERSION: u8 = 3;

/// Version byte introducing interpreter 6.0.
pub const INTERPRETER_60_VERSION: u8 = 4;

/// The Autolykos proof-of-work solution attached to a block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutolykosSolution {
    /// Miner public key (compressed, 33 bytes).
    pub miner_pk: [u8; 33],
    /// One-time public key `w` (compressed, 33 bytes).
    pub w: [u8; 33],
    /// 8-byte nonce.
    pub nonce: [u8; 8],
    /// Big-integer `d` value (variable length).
    pub d: Vec<u8>,
}

/// An Ergo block header containing all consensus-critical fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Protocol version byte.
    pub version: u8,
    /// ID of the parent header.
    pub parent_id: ModifierId,
    /// Merkle root of AD proofs.
    pub ad_proofs_root: Digest32,
    /// Merkle root of transactions.
    pub transactions_root: Digest32,
    /// State root after applying this block (33-byte AD digest).
    pub state_root: ADDigest,
    /// Block timestamp in milliseconds since epoch.
    pub timestamp: u64,
    /// Merkle root of the extension section.
    pub extension_root: Digest32,
    /// Encoded required difficulty.
    pub n_bits: u64,
    /// Block height (genesis = 1).
    pub height: u32,
    /// Three miner voting bytes.
    pub votes: [u8; 3],
    /// Any bytes after the known fields (forward-compatibility).
    pub unparsed_bytes: Vec<u8>,
    /// Proof-of-work solution.
    pub pow_solution: AutolykosSolution,
}

impl Header {
    /// Returns true if this is the genesis block (height == 1).
    pub fn is_genesis(&self) -> bool {
        self.height == 1
    }

    /// Creates a zeroed-out header for use in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn default_for_test() -> Self {
        Self {
            version: INITIAL_VERSION,
            parent_id: ModifierId::GENESIS_PARENT,
            ad_proofs_root: Digest32([0u8; 32]),
            transactions_root: Digest32([0u8; 32]),
            state_root: ADDigest([0u8; 33]),
            timestamp: 0,
            extension_root: Digest32([0u8; 32]),
            n_bits: 0,
            height: 0,
            votes: [0u8; 3],
            unparsed_bytes: Vec::new(),
            pow_solution: AutolykosSolution {
                miner_pk: [0u8; 33],
                w: [0u8; 33],
                nonce: [0u8; 8],
                d: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_version_constants() {
        assert_eq!(INITIAL_VERSION, 1);
        assert_eq!(HARDENING_VERSION, 2);
        assert_eq!(INTERPRETER_50_VERSION, 3);
        assert_eq!(INTERPRETER_60_VERSION, 4);
    }

    #[test]
    fn autolykos_v2_solution_size() {
        let solution = AutolykosSolution {
            miner_pk: [0u8; 33],
            w: [0u8; 33],
            nonce: [0u8; 8],
            d: Vec::new(),
        };
        assert_eq!(solution.miner_pk.len(), 33);
        assert_eq!(solution.w.len(), 33);
        assert_eq!(solution.nonce.len(), 8);
    }

    #[test]
    fn header_is_genesis() {
        let mut header = Header::default_for_test();
        header.height = 1;
        assert!(header.is_genesis());
    }

    #[test]
    fn header_not_genesis() {
        let mut header = Header::default_for_test();
        header.height = 100;
        assert!(!header.is_genesis());

        header.height = 0;
        assert!(!header.is_genesis());
    }

    #[test]
    fn votes_array_size() {
        let header = Header::default_for_test();
        assert_eq!(header.votes.len(), 3);
    }
}

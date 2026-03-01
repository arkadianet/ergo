use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

// ── Constants ───────────────────────────────────────────────────────

/// Mainnet network prefix (upper nibble).
const MAINNET_PREFIX: u8 = 0x00;

/// Testnet network prefix (upper nibble).
const TESTNET_PREFIX: u8 = 0x10;

/// P2PK address type (lower nibble).
const P2PK_TYPE: u8 = 0x01;

/// P2SH address type (lower nibble).
const P2SH_TYPE: u8 = 0x02;

/// P2S address type (lower nibble).
const P2S_TYPE: u8 = 0x03;

/// Number of checksum bytes appended to the raw address payload.
const CHECKSUM_LEN: usize = 4;

// ── Error ───────────────────────────────────────────────────────────

/// Errors that can occur during address encoding or decoding.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("base58 decode failed: {0}")]
    Base58Decode(String),

    #[error("decoded address is too short (need at least {min} bytes, got {got})")]
    TooShort { min: usize, got: usize },

    #[error("checksum mismatch: expected {expected:02x?}, got {got:02x?}")]
    ChecksumMismatch { expected: [u8; 4], got: [u8; 4] },

    #[error("unknown network prefix: 0x{0:02x}")]
    UnknownNetwork(u8),

    #[error("invalid hex string: {0}")]
    InvalidHex(String),
}

// ── Enums ───────────────────────────────────────────────────────────

/// Ergo address type encoded in the lower nibble of the prefix byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-Public-Key (compressed 33-byte public key).
    P2PK,
    /// Pay-to-Script-Hash (blake2b256 hash of script bytes).
    P2SH,
    /// Pay-to-Script (full script bytes).
    P2S,
}

impl AddressType {
    /// Returns the byte value for this address type.
    fn to_byte(self) -> u8 {
        match self {
            Self::P2PK => P2PK_TYPE,
            Self::P2SH => P2SH_TYPE,
            Self::P2S => P2S_TYPE,
        }
    }

    /// Parses the lower nibble of a prefix byte into an `AddressType`.
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            P2PK_TYPE => Some(Self::P2PK),
            P2SH_TYPE => Some(Self::P2SH),
            P2S_TYPE => Some(Self::P2S),
            _ => None,
        }
    }
}

/// Ergo network prefix encoded in the upper nibble of the prefix byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPrefix {
    Mainnet,
    Testnet,
}

impl NetworkPrefix {
    /// Returns the byte value for this network prefix.
    fn to_byte(self) -> u8 {
        match self {
            Self::Mainnet => MAINNET_PREFIX,
            Self::Testnet => TESTNET_PREFIX,
        }
    }

    /// Parses the upper nibble of a prefix byte into a `NetworkPrefix`.
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            MAINNET_PREFIX => Some(Self::Mainnet),
            TESTNET_PREFIX => Some(Self::Testnet),
            _ => None,
        }
    }
}

// ── Decoded address ─────────────────────────────────────────────────

/// A decoded Ergo address with its network, type, and raw content bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    pub network: NetworkPrefix,
    pub address_type: AddressType,
    pub content_bytes: Vec<u8>,
}

// ── Helper ──────────────────────────────────────────────────────────

/// Computes a Blake2b-256 hash and returns the full 32-byte digest.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).unwrap();
    out
}

// ── Public API ──────────────────────────────────────────────────────

/// Encodes an Ergo address from network, address type, and content bytes.
///
/// The encoding is: `Base58(prefix_byte || content || checksum)` where
/// `prefix_byte = network | addr_type` and `checksum = blake2b256(prefix_byte || content)[0..4]`.
pub fn encode_address(network: NetworkPrefix, addr_type: AddressType, content: &[u8]) -> String {
    let prefix_byte = network.to_byte() | addr_type.to_byte();

    let mut raw = Vec::with_capacity(1 + content.len());
    raw.push(prefix_byte);
    raw.extend_from_slice(content);

    let hash = blake2b256(&raw);
    let mut with_checksum = raw;
    with_checksum.extend_from_slice(&hash[..CHECKSUM_LEN]);

    bs58::encode(with_checksum).into_string()
}

/// Decodes a Base58-encoded Ergo address, verifying its checksum.
///
/// Returns the network prefix, address type, and raw content bytes.
pub fn decode_address(address: &str) -> Result<DecodedAddress, AddressError> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| AddressError::Base58Decode(e.to_string()))?;

    let min_len = 1 + CHECKSUM_LEN;
    if decoded.len() < min_len {
        return Err(AddressError::TooShort {
            min: min_len,
            got: decoded.len(),
        });
    }

    let payload_end = decoded.len() - CHECKSUM_LEN;
    let payload = &decoded[..payload_end];
    let provided_checksum: [u8; 4] = decoded[payload_end..].try_into().unwrap();

    let hash = blake2b256(payload);
    let expected_checksum: [u8; 4] = hash[..CHECKSUM_LEN].try_into().unwrap();

    if provided_checksum != expected_checksum {
        return Err(AddressError::ChecksumMismatch {
            expected: expected_checksum,
            got: provided_checksum,
        });
    }

    let prefix_byte = payload[0];
    let network_nibble = prefix_byte & 0xF0;
    let type_nibble = prefix_byte & 0x0F;

    let network = NetworkPrefix::from_byte(network_nibble)
        .ok_or(AddressError::UnknownNetwork(network_nibble))?;

    let address_type =
        AddressType::from_byte(type_nibble).ok_or(AddressError::UnknownNetwork(type_nibble))?;

    let content_bytes = payload[1..].to_vec();

    Ok(DecodedAddress {
        network,
        address_type,
        content_bytes,
    })
}

/// Validates a Base58-encoded Ergo address (alias for `decode_address`).
pub fn validate_address(address: &str) -> Result<DecodedAddress, AddressError> {
    decode_address(address)
}

/// Derives an Ergo address from an ErgoTree byte sequence.
///
/// If the ErgoTree starts with `[0x00, 0x08, 0xcd]`, the next 33 bytes are
/// treated as a compressed public key and encoded as a P2PK address.
/// Otherwise the full ErgoTree is encoded as a P2S address.
pub fn ergo_tree_to_address(ergo_tree: &[u8], network: NetworkPrefix) -> String {
    if ergo_tree.len() >= 36 && ergo_tree[0] == 0x00 && ergo_tree[1] == 0x08 && ergo_tree[2] == 0xcd
    {
        let pk = &ergo_tree[3..36];
        encode_address(network, AddressType::P2PK, pk)
    } else {
        encode_address(network, AddressType::P2S, ergo_tree)
    }
}

/// Creates a P2PK address from a hex-encoded compressed public key (33 bytes).
pub fn raw_to_address(pubkey_hex: &str, network: NetworkPrefix) -> Result<String, AddressError> {
    let pk_bytes = hex::decode(pubkey_hex).map_err(|e| AddressError::InvalidHex(e.to_string()))?;

    Ok(encode_address(network, AddressType::P2PK, &pk_bytes))
}

/// Decodes an address and returns the hex-encoded content bytes.
pub fn address_to_raw(address: &str) -> Result<String, AddressError> {
    let decoded = decode_address(address)?;
    Ok(hex::encode(&decoded.content_bytes))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_p2pk_mainnet() {
        let pk = [0xAA; 33];
        let addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2PK, &pk);
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, NetworkPrefix::Mainnet);
        assert_eq!(decoded.address_type, AddressType::P2PK);
        assert_eq!(decoded.content_bytes, pk);
    }

    #[test]
    fn roundtrip_p2sh_testnet() {
        let script_hash = [0xBB; 32];
        let addr = encode_address(NetworkPrefix::Testnet, AddressType::P2SH, &script_hash);
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, NetworkPrefix::Testnet);
        assert_eq!(decoded.address_type, AddressType::P2SH);
        assert_eq!(decoded.content_bytes, script_hash);
    }

    #[test]
    fn roundtrip_p2s_mainnet() {
        let script = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2S, &script);
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.network, NetworkPrefix::Mainnet);
        assert_eq!(decoded.address_type, AddressType::P2S);
        assert_eq!(decoded.content_bytes, script);
    }

    #[test]
    fn checksum_mismatch_detected() {
        let pk = [0xCC; 33];
        let addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2PK, &pk);

        // Decode, corrupt the last byte (part of checksum), re-encode
        let mut raw = bs58::decode(&addr).into_vec().unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        let corrupted = bs58::encode(&raw).into_string();

        let err = decode_address(&corrupted).unwrap_err();
        assert!(matches!(err, AddressError::ChecksumMismatch { .. }));
    }

    #[test]
    fn too_short_address() {
        // Encode only 3 bytes (less than 1 prefix + 4 checksum)
        let short = bs58::encode(&[0x01, 0x02, 0x03]).into_string();
        let err = decode_address(&short).unwrap_err();
        assert!(matches!(err, AddressError::TooShort { .. }));
    }

    #[test]
    fn prefix_byte_values() {
        let pk = [0xDD; 33];

        let mainnet_addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2PK, &pk);
        let mainnet_raw = bs58::decode(&mainnet_addr).into_vec().unwrap();
        assert_eq!(mainnet_raw[0], MAINNET_PREFIX | P2PK_TYPE);
        assert_eq!(mainnet_raw[0], 0x01);

        let testnet_addr = encode_address(NetworkPrefix::Testnet, AddressType::P2SH, &pk);
        let testnet_raw = bs58::decode(&testnet_addr).into_vec().unwrap();
        assert_eq!(testnet_raw[0], TESTNET_PREFIX | P2SH_TYPE);
        assert_eq!(testnet_raw[0], 0x12);

        let p2s_addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2S, &pk);
        let p2s_raw = bs58::decode(&p2s_addr).into_vec().unwrap();
        assert_eq!(p2s_raw[0], MAINNET_PREFIX | P2S_TYPE);
        assert_eq!(p2s_raw[0], 0x03);
    }

    #[test]
    fn ergo_tree_p2pk_detection() {
        // ErgoTree with P2PK prefix: 0x00 0x08 0xcd followed by 33-byte public key
        let pk = [0xEE; 33];
        let mut ergo_tree = vec![0x00, 0x08, 0xcd];
        ergo_tree.extend_from_slice(&pk);

        let addr = ergo_tree_to_address(&ergo_tree, NetworkPrefix::Mainnet);
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2PK);
        assert_eq!(decoded.content_bytes, pk);
    }

    #[test]
    fn ergo_tree_p2s_fallback() {
        // ErgoTree without P2PK prefix falls back to P2S
        let ergo_tree = vec![0x10, 0x04, 0x00, 0x05, 0x00];
        let addr = ergo_tree_to_address(&ergo_tree, NetworkPrefix::Testnet);
        let decoded = decode_address(&addr).unwrap();
        assert_eq!(decoded.address_type, AddressType::P2S);
        assert_eq!(decoded.content_bytes, ergo_tree);
    }

    #[test]
    fn raw_to_address_and_back() {
        let pk_hex = "02".to_string() + &"ab".repeat(32);
        let addr = raw_to_address(&pk_hex, NetworkPrefix::Mainnet).unwrap();
        let raw_back = address_to_raw(&addr).unwrap();
        assert_eq!(raw_back, pk_hex);
    }

    #[test]
    fn raw_to_address_invalid_hex() {
        let err = raw_to_address("not_hex!", NetworkPrefix::Mainnet).unwrap_err();
        assert!(matches!(err, AddressError::InvalidHex(_)));
    }

    #[test]
    fn validate_address_is_alias() {
        let pk = [0x55; 33];
        let addr = encode_address(NetworkPrefix::Mainnet, AddressType::P2PK, &pk);
        let decoded = validate_address(&addr).unwrap();
        assert_eq!(decoded.network, NetworkPrefix::Mainnet);
        assert_eq!(decoded.address_type, AddressType::P2PK);
        assert_eq!(decoded.content_bytes, pk);
    }

    #[test]
    fn base58_decode_error() {
        let err = decode_address("0OIl").unwrap_err();
        assert!(matches!(err, AddressError::Base58Decode(_)));
    }

    #[test]
    fn ergo_tree_too_short_for_p2pk() {
        // ErgoTree with P2PK prefix but not enough bytes for full 33-byte key
        let ergo_tree = vec![0x00, 0x08, 0xcd, 0x01, 0x02];
        let addr = ergo_tree_to_address(&ergo_tree, NetworkPrefix::Mainnet);
        let decoded = decode_address(&addr).unwrap();
        // Should fall back to P2S since there aren't enough bytes
        assert_eq!(decoded.address_type, AddressType::P2S);
    }
}

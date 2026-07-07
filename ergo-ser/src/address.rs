//! Ergo address encoding from raw `ErgoTree` bytes.
//!
//! Mirrors Scala's `ErgoAddressEncoder.fromProposition` semantics:
//! - A tree whose body is exactly a constant `SigmaProp(ProveDlog(ge))` and
//!   carries no segregated constants encodes as **P2PK** — `[network|0x01] ||
//!   pubkey(33B) || blake2b256(prefix||pubkey)[..4]`, base58.
//! - Anything else (including soft-fork-unparsed trees, `Cand`/`Cor`/`Cthreshold`,
//!   and any non-`SigmaPropConst` body) falls through to **P2S** —
//!   `[network|0x03] || ergoTreeBytes || blake2b256(prefix||ergoTreeBytes)[..4]`,
//!   base58.
//!
//! P2SH (low nibble 0x02) is never produced by Scala's `fromProposition`, so
//! the node's address surfaces here don't route to it either. The COMPILER
//! path (`ergo-compiler`'s `compile()`) DOES construct it deliberately via
//! [`encode_p2sh`], mirroring `Pay2SHAddress.apply` (sigma-state 6.0.2,
//! `ErgoAddress.scala:201-218`): content = `blake2b256(proposition_bytes)[..24]`
//! (Scala `hash192`).
//!
//! References:
//! - [`ErgoAddressEncoder.scala`](https://github.com/ergoplatform/ergo/blob/master/ergo-core/src/main/scala/org/ergoplatform/ErgoAddressEncoder.scala)
//! - [`P2PKAddress` / `Pay2SAddress`](https://github.com/ergoplatform/sigma-rust/blob/develop/ergotree-ir/src/chain/address.rs)

use ergo_primitives::digest::blake2b256;
use ergo_primitives::group_element::GroupElement;

use crate::ergo_tree::ErgoTree;
use crate::opcode::Expr;
use crate::sigma_type::SigmaType;
use crate::sigma_value::{SigmaBoolean, SigmaValue};

/// Network selector for the address prefix byte (Scala's
/// `NetworkPrefix`: high-nibble of the header byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPrefix {
    /// Mainnet — high nibble `0x00`.
    Mainnet = 0x00,
    /// Testnet — high nibble `0x10`.
    Testnet = 0x10,
}

impl NetworkPrefix {
    fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Address class — low nibble of the header byte.
const TYPE_P2PK: u8 = 0x01;
const TYPE_P2SH: u8 = 0x02;
const TYPE_P2S: u8 = 0x03;

const CHECKSUM_LEN: usize = 4;

/// Encode an `ErgoTree` as a base58 Ergo address string.
///
/// Routing rule mirrors Scala `fromProposition`: P2PK if the tree is a
/// bare `SigmaPropConst(ProveDlog(_))` with no segregated constants,
/// otherwise P2S over the verbatim `ergo_tree_bytes`.
///
/// `ergo_tree_bytes` must be the canonical wire bytes of `tree` (the
/// caller normally has these from `ErgoBoxCandidate::ergo_tree_bytes`).
pub fn encode_address(network: NetworkPrefix, tree: &ErgoTree, ergo_tree_bytes: &[u8]) -> String {
    if let Some(pubkey) = detect_p2pk(tree) {
        encode_p2pk(network, pubkey)
    } else {
        encode_p2s(network, ergo_tree_bytes)
    }
}

/// P2PK detection: tree must have no segregated constants and a body that
/// is a constant `SigmaProp(ProveDlog(ge))` (Scala `SigmaPropConstant`).
fn detect_p2pk(tree: &ErgoTree) -> Option<&GroupElement> {
    if !tree.constants.is_empty() {
        return None;
    }
    match &tree.body {
        Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(ge)),
        } => Some(ge),
        _ => None,
    }
}

fn encode_p2pk(network: NetworkPrefix, pubkey: &GroupElement) -> String {
    let header = network.as_byte() | TYPE_P2PK;
    let mut buf = Vec::with_capacity(1 + 33 + CHECKSUM_LEN);
    buf.push(header);
    buf.extend_from_slice(pubkey.as_bytes());
    append_checksum(&mut buf);
    bs58::encode(&buf).into_string()
}

/// Encode arbitrary bytes as a P2S Ergo address (header ++ bytes ++ checksum).
/// Does NOT validate that `ergo_tree_bytes` is a parseable ErgoTree — the caller
/// owns that. Useful for re-encoding already-validated tree bytes without a
/// re-parse, and for tests that need a P2S address over a deliberately
/// malformed script.
pub fn encode_p2s(network: NetworkPrefix, ergo_tree_bytes: &[u8]) -> String {
    let header = network.as_byte() | TYPE_P2S;
    let mut buf = Vec::with_capacity(1 + ergo_tree_bytes.len() + CHECKSUM_LEN);
    buf.push(header);
    buf.extend_from_slice(ergo_tree_bytes);
    append_checksum(&mut buf);
    bs58::encode(&buf).into_string()
}

/// P2SH content length: 24 bytes = 192 bits, Scala `ErgoAddressEncoder.hash192`
/// (`Blake2b256` truncated), `ErgoAddress.scala:214-216`.
const P2SH_CONTENT_LEN: usize = 24;

/// Encode a serialized PROPOSITION as a P2SH Ergo address
/// (`[network|0x02] || blake2b256(proposition_bytes)[..24] || checksum4`, base58).
///
/// Mirrors Scala `Pay2SHAddress.apply(prop: SigmaPropValue)` (sigma-state
/// 6.0.2, `ErgoAddress.scala:210-218`): `contentBytes =
/// hash192(ValueSerializer.serialize(prop))`. `proposition_bytes` must be the
/// serialized ROOT EXPRESSION only — no ErgoTree header byte, no constants
/// table (contrast [`encode_p2s`], which takes the full tree bytes).
///
/// The caller owns the constant-inlining contract: for a constant-segregated
/// tree, Scala's `Pay2SHAddress.apply(script: ErgoTree)` overload first
/// substitutes placeholders back into the body
/// (`script.toProposition(replaceConstants = script.isConstantSegregation)`,
/// `ErgoAddress.scala:201-204`) and hashes THAT — hashing a body that still
/// contains `ConstPlaceholder` nodes yields a different (wrong) address.
pub fn encode_p2sh(network: NetworkPrefix, proposition_bytes: &[u8]) -> String {
    let header = network.as_byte() | TYPE_P2SH;
    let digest = blake2b256(proposition_bytes);
    let mut buf = Vec::with_capacity(1 + P2SH_CONTENT_LEN + CHECKSUM_LEN);
    buf.push(header);
    buf.extend_from_slice(&digest.as_bytes()[..P2SH_CONTENT_LEN]);
    append_checksum(&mut buf);
    bs58::encode(&buf).into_string()
}

/// Append `blake2b256(buf)[..4]` to `buf`. Scala hashes the
/// header-plus-content prefix before appending — our `buf` is exactly
/// that prefix at call time, so this is in-place.
fn append_checksum(buf: &mut Vec<u8>) {
    let digest = blake2b256(buf);
    buf.extend_from_slice(&digest.as_bytes()[..CHECKSUM_LEN]);
}

/// Decode failures on `decode_address_to_tree_bytes`. Each variant maps
/// to a wire-distinguishable client error; the API layer converts these
/// into `400 invalid-address` envelopes (Scala collapses every parse
/// failure to a single 400 — we surface the variant for telemetry only).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressDecodeError {
    #[error("invalid base58: {0}")]
    Base58(String),
    #[error("address too short ({0} bytes; need at least 5)")]
    TooShort(usize),
    #[error("invalid checksum")]
    BadChecksum,
    #[error("network mismatch: expected {expected:?}, header byte 0x{actual:02x}")]
    NetworkMismatch { expected: NetworkPrefix, actual: u8 },
    #[error("unsupported address type 0x{0:02x} (P2SH not supported)")]
    UnsupportedType(u8),
    #[error("invalid P2PK pubkey length: expected 33, got {0}")]
    BadPubkeyLength(usize),
    #[error("encoding error: {0}")]
    BadEncoding(String),
}

const P2PK_BODY_PREFIX: [u8; 3] = [0x00, 0x08, 0xCD];
const P2PK_PUBKEY_LEN: usize = 33;

/// Decode an Ergo address string into its canonical `ErgoTree` bytes.
///
/// - **P2PK** (`type=0x01`): bytes are reconstructed as the canonical
///   `[0x00, 0x08, 0xCD, ...pubkey_33B]` (no version, no size, no
///   segregation, body = `SigmaPropConst(ProveDlog(pubkey))`). This
///   matches the bytes [`encode_address`] consumes for the inverse.
/// - **P2S** (`type=0x03`): the embedded `ergo_tree_bytes` are returned
///   verbatim — Scala's `Pay2SAddress` stores them inline and our
///   apply path indexes addresses by `blake2b256` of those bytes.
/// - **P2SH** (`type=0x02`): rejected with `UnsupportedType`. Scala's
///   `fromString` accepts P2SH but its synthetic `script` (a
///   pre-image hash check) never matches any indexed address record —
///   accepting silently would return zero balance for what looks like a
///   valid address. Surfacing the type explicitly is honest.
pub fn decode_address_to_tree_bytes(
    s: &str,
    network: NetworkPrefix,
) -> Result<Vec<u8>, AddressDecodeError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| AddressDecodeError::Base58(e.to_string()))?;
    if raw.len() < 1 + CHECKSUM_LEN {
        return Err(AddressDecodeError::TooShort(raw.len()));
    }
    let payload_end = raw.len() - CHECKSUM_LEN;
    let expected = blake2b256(&raw[..payload_end]);
    if raw[payload_end..] != expected.as_bytes()[..CHECKSUM_LEN] {
        return Err(AddressDecodeError::BadChecksum);
    }
    let header = raw[0];
    let net_nibble = header & 0xF0;
    if net_nibble != network.as_byte() {
        return Err(AddressDecodeError::NetworkMismatch {
            expected: network,
            actual: header,
        });
    }
    let type_nibble = header & 0x0F;
    match type_nibble {
        TYPE_P2PK => {
            let pubkey = &raw[1..payload_end];
            if pubkey.len() != P2PK_PUBKEY_LEN {
                return Err(AddressDecodeError::BadPubkeyLength(pubkey.len()));
            }
            let mut tree_bytes = Vec::with_capacity(P2PK_BODY_PREFIX.len() + P2PK_PUBKEY_LEN);
            tree_bytes.extend_from_slice(&P2PK_BODY_PREFIX);
            tree_bytes.extend_from_slice(pubkey);
            Ok(tree_bytes)
        }
        TYPE_P2S => Ok(raw[1..payload_end].to_vec()),
        other => Err(AddressDecodeError::UnsupportedType(other)),
    }
}

/// Decode an address and return its `tree_hash` — the blake2b256 of the
/// canonical `ErgoTree` bytes. This is the redb key for the indexer's
/// `INDEXED_ADDRESS` table; the balance / byAddress routes look up
/// records by this hash.
///
/// Equivalent to `blake2b256(decode_address_to_tree_bytes(s, network)?)`,
/// but kept as one call so the API layer does not need to depend on
/// `ergo-primitives` for the hash primitive.
pub fn decode_address_to_tree_hash(
    s: &str,
    network: NetworkPrefix,
) -> Result<[u8; 32], AddressDecodeError> {
    let bytes = decode_address_to_tree_bytes(s, network)?;
    Ok(*blake2b256(&bytes).as_bytes())
}

/// Scala-parity `/utils/addressToRaw/{address}` content-bytes view.
///
/// Returns the address's *content* bytes — what Scala
/// `ErgoAddress.contentBytes` yields. For P2PK that's the 33-byte
/// compressed pubkey only (not the wrapper `0x0008cd<pubkey>` tree
/// form returned by [`decode_address_to_tree_bytes`]); for P2SH that's
/// the 24-byte script hash; for P2S that's the full embedded
/// `ergo_tree_bytes`.
///
/// Unlike [`decode_address_to_tree_bytes`] (which is the indexer
/// path and intentionally refuses P2SH because there's no
/// indexable tree behind it), the `/utils/*` surface is address-
/// class-agnostic: Scala's `ErgoAddressEncoder.fromString` accepts
/// every address class and the `addressToRaw` / `address` validity
/// routes inherit that breadth.
pub fn decode_address_content_bytes(
    s: &str,
    network: NetworkPrefix,
) -> Result<Vec<u8>, AddressDecodeError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| AddressDecodeError::Base58(e.to_string()))?;
    if raw.len() < 1 + CHECKSUM_LEN {
        return Err(AddressDecodeError::TooShort(raw.len()));
    }
    let payload_end = raw.len() - CHECKSUM_LEN;
    let expected = blake2b256(&raw[..payload_end]);
    if raw[payload_end..] != expected.as_bytes()[..CHECKSUM_LEN] {
        return Err(AddressDecodeError::BadChecksum);
    }
    let header = raw[0];
    let net_nibble = header & 0xF0;
    if net_nibble != network.as_byte() {
        return Err(AddressDecodeError::NetworkMismatch {
            expected: network,
            actual: header,
        });
    }
    let type_nibble = header & 0x0F;
    match type_nibble {
        TYPE_P2PK => {
            let pubkey = &raw[1..payload_end];
            if pubkey.len() != P2PK_PUBKEY_LEN {
                return Err(AddressDecodeError::BadPubkeyLength(pubkey.len()));
            }
            Ok(pubkey.to_vec())
        }
        // P2SH content bytes are the embedded script hash; P2S content
        // bytes are the full ergo_tree. Both are the bytes between the
        // header byte and the 4-byte checksum, so the slice is the same
        // shape and we let the caller (or Scala consumer) interpret.
        TYPE_P2SH | TYPE_P2S => Ok(raw[1..payload_end].to_vec()),
        other => Err(AddressDecodeError::UnsupportedType(other)),
    }
}

/// Decode a P2PK address string and return the 33-byte compressed
/// pubkey embedded in it. Returns an error if the address is not
/// a valid P2PK address (wrong network or type byte, bad checksum,
/// etc.). The same wallet keys are valid on every network, so without
/// the network check a testnet address would decode to a tracked
/// pubkey on a mainnet node; Scala's `ErgoAddressEncoder.fromString`
/// rejects the mismatch at parse and so do the sibling decoders here.
/// Remaining gap vs Scala: the 33 bytes are not validated as a curve
/// point (Scala's `P2PKAddress` parses a `ProveDlog`); see the
/// curve-dep trade-off note on [`encode_p2pk_from_pubkey`].
///
/// Used by the wallet's `POST /wallet/updateChangeAddress` handler
/// to validate that the address decodes to a real pubkey before
/// checking tracked-pubkey membership.
pub fn decode_p2pk_address(
    s: &str,
    network: NetworkPrefix,
) -> Result<[u8; 33], AddressDecodeError> {
    let raw = bs58::decode(s)
        .into_vec()
        .map_err(|e| AddressDecodeError::Base58(e.to_string()))?;
    if raw.len() < 1 + CHECKSUM_LEN {
        return Err(AddressDecodeError::TooShort(raw.len()));
    }
    let payload_end = raw.len() - CHECKSUM_LEN;
    let expected = blake2b256(&raw[..payload_end]);
    if raw[payload_end..] != expected.as_bytes()[..CHECKSUM_LEN] {
        return Err(AddressDecodeError::BadChecksum);
    }
    let header = raw[0];
    let net_nibble = header & 0xF0;
    if net_nibble != network.as_byte() {
        return Err(AddressDecodeError::NetworkMismatch {
            expected: network,
            actual: header,
        });
    }
    let type_nibble = header & 0x0F;
    if type_nibble != TYPE_P2PK {
        return Err(AddressDecodeError::UnsupportedType(type_nibble));
    }
    let pubkey = &raw[1..payload_end];
    if pubkey.len() != P2PK_PUBKEY_LEN {
        return Err(AddressDecodeError::BadPubkeyLength(pubkey.len()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(pubkey);
    Ok(out)
}

/// Scala-parity `/utils/rawToAddress/{pubkeyHex}` encoder.
///
/// Wraps a 33-byte compressed secp256k1 pubkey into the P2PK
/// `ErgoTree` byte sequence `[0x00, 0x08, 0xCD, ...pubkey]` and
/// encodes it as a network-prefixed P2PK address. Returns the
/// canonical Ergo address string.
///
/// # `[proposed]` divergence from Scala
///
/// Scala's route runs the pubkey through
/// `GroupElementSerializer.parseTry`, which fails if the bytes don't
/// decode to a valid point on the secp256k1 curve. We only check
/// `length == 33`. Pulling a curve-arithmetic dep into `ergo-ser`
/// (currently dep-free of `k256` / `secp256k1`) for one route's
/// shape parity is disproportionate to the failure mode: bad bytes
/// produce a base58 string that no other peer or wallet will
/// recognize, but neither does Scala's accept-then-fail-on-use
/// behavior end up materially different. Tracked as a future
/// hardening if/when `ergo-ser` gains curve deps for another reason.
pub fn encode_p2pk_from_pubkey(
    network: NetworkPrefix,
    pubkey: &[u8],
) -> Result<String, AddressDecodeError> {
    if pubkey.len() != P2PK_PUBKEY_LEN {
        return Err(AddressDecodeError::BadPubkeyLength(pubkey.len()));
    }
    let header = network.as_byte() | TYPE_P2PK;
    let mut buf = Vec::with_capacity(1 + P2PK_PUBKEY_LEN + CHECKSUM_LEN);
    buf.push(header);
    buf.extend_from_slice(pubkey);
    append_checksum(&mut buf);
    Ok(bs58::encode(&buf).into_string())
}

/// Build the canonical P2PK ErgoTree byte encoding for the given
/// 33-byte compressed pubkey. Used by the wallet's apply hook to
/// classify outputs by tree-byte membership. The encoding matches
/// Scala `ErgoAddressEncoder` — header byte (always 0x00 for P2PK
/// bare-shape tree), `SigmaPropConst(ProveDlog(pubkey))` body.
pub fn build_p2pk_tree_bytes(pubkey: &[u8; 33]) -> Result<Vec<u8>, AddressDecodeError> {
    use crate::ergo_tree::ErgoTree;
    use crate::opcode::Expr;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{SigmaBoolean, SigmaValue};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;

    let tree = ErgoTree {
        version: 0,
        has_size: false,
        constant_segregation: false,
        constants: Vec::new(),
        body: Expr::Const {
            tpe: SigmaType::SSigmaProp,
            val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(*pubkey))),
        },
    };
    let mut w = VlqWriter::new();
    crate::ergo_tree::write_ergo_tree(&mut w, &tree)
        .map_err(|e| AddressDecodeError::BadEncoding(format!("ergotree write: {e:?}")))?;
    Ok(w.result())
}

/// Scala-parity `/utils/ergoTreeToAddress/{hex}` encoder.
///
/// Inspects the `ergo_tree_bytes` for a P2PK pattern (no segregated
/// constants, body = `SigmaPropConst(ProveDlog(_))`); on match emits
/// a P2PK address, else a P2S address wrapping the verbatim bytes.
/// Matches Scala `ErgoAddressEncoder.fromProposition` routing.
pub fn encode_address_from_tree_bytes(
    network: NetworkPrefix,
    ergo_tree_bytes: &[u8],
) -> Result<String, ergo_primitives::reader::ReadError> {
    use ergo_primitives::reader::VlqReader;
    let mut r = VlqReader::new(ergo_tree_bytes);
    let tree = crate::ergo_tree::read_ergo_tree(&mut r)?;
    Ok(encode_address(network, &tree, ergo_tree_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::Expr;
    use crate::sigma_type::SigmaType;
    use crate::sigma_value::{SigmaBoolean, SigmaValue};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::reader::VlqReader;
    use ergo_primitives::writer::VlqWriter;

    use crate::ergo_tree::{read_ergo_tree, write_ergo_tree};

    // ----- helpers -----

    #[test]
    fn build_p2pk_tree_bytes_produces_canonical_shape() {
        let pubkey: [u8; 33] =
            hex::decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")
                .unwrap()
                .try_into()
                .unwrap();
        let bytes = super::build_p2pk_tree_bytes(&pubkey).expect("build must succeed");
        assert!(!bytes.is_empty());
        // The canonical P2PK tree starts with the version byte = 0
        assert_eq!(bytes[0], 0x00);
        // And contains the pubkey somewhere in the body.
        assert!(bytes.windows(33).any(|w| w == pubkey));
    }

    fn p2pk_tree(pubkey: [u8; 33]) -> (ErgoTree, Vec<u8>) {
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: false,
            constants: Vec::new(),
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    pubkey,
                ))),
            },
        };
        let mut w = VlqWriter::new();
        write_ergo_tree(&mut w, &tree).expect("write p2pk tree");
        let bytes = w.result();
        (tree, bytes)
    }

    // ----- happy path -----

    #[test]
    fn p2pk_roundtrip_mainnet() {
        // A canonical P2PK tree byte sequence: `0008cd<33B pubkey>`.
        let pubkey = [0x02; 33];
        let (tree, bytes) = p2pk_tree(pubkey);
        assert_eq!(bytes[0], 0x00, "P2PK tree header byte");
        assert_eq!(bytes[1], 0x08, "SSigmaProp type tag");
        assert_eq!(bytes[2], 0xcd, "ProveDlog constant tag");

        let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        // Round-trip via bs58 decode and verify shape.
        let decoded = bs58::decode(&addr).into_vec().expect("base58 decode");
        assert_eq!(decoded.len(), 1 + 33 + 4);
        assert_eq!(decoded[0], 0x01, "mainnet P2PK header");
        assert_eq!(&decoded[1..34], &pubkey);
        let expected_csum = blake2b256(&decoded[..34]);
        assert_eq!(&decoded[34..38], &expected_csum.as_bytes()[..4]);
    }

    #[test]
    fn p2pk_testnet_uses_high_nibble() {
        let (tree, bytes) = p2pk_tree([0x03; 33]);
        let addr = encode_address(NetworkPrefix::Testnet, &tree, &bytes);
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded[0], 0x11);
    }

    #[test]
    fn p2s_for_constant_segregated_tree() {
        // A trivial size-flagged tree with one segregated constant — the
        // segregation flag alone disqualifies P2PK, so this must round to
        // P2S even if the body would otherwise look like a SigmaPropConst.
        let tree_bytes_hex = "100204a00b08cd";
        // We don't need to actually parse this — encode_address works off
        // both `tree` and `ergo_tree_bytes`. Construct a minimal tree
        // marked as having segregated constants so detect_p2pk bails.
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![(
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    [0x02; 33],
                ))),
            )],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    [0x02; 33],
                ))),
            },
        };
        let bytes = hex::decode(tree_bytes_hex).unwrap();
        let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded[0], 0x03, "P2S header");
        assert_eq!(&decoded[1..1 + bytes.len()], bytes.as_slice());
    }

    #[test]
    fn p2pk_reparsed_tree_still_detected() {
        // Build a P2PK tree, serialize, re-parse, and confirm the
        // reparsed form is still recognized as P2PK.
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let (_, original_bytes) = p2pk_tree(pubkey);

        let mut r = VlqReader::new(&original_bytes);
        let parsed = read_ergo_tree(&mut r).expect("parse p2pk tree");
        let addr_orig = encode_address(NetworkPrefix::Mainnet, &parsed, &original_bytes);

        // Sanity: encoder agrees with itself across original and parsed inputs.
        let (built_again, _) = p2pk_tree(pubkey);
        let addr_built = encode_address(NetworkPrefix::Mainnet, &built_again, &original_bytes);
        assert_eq!(addr_orig, addr_built);
    }

    // ----- round-trips -----
    //
    // Decode-side tests: the decoder is invoked on encoder output and
    // the recovered tree bytes are compared against what went in.

    #[test]
    fn decode_p2pk_returns_canonical_tree_bytes() {
        let pubkey = [0x02; 33];
        let (tree, bytes) = p2pk_tree(pubkey);
        let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        let recovered = decode_address_to_tree_bytes(&addr, NetworkPrefix::Mainnet).unwrap();
        // Canonical P2PK tree bytes: 0x00 0x08 0xCD ++ pubkey.
        assert_eq!(recovered, bytes);
    }

    #[test]
    fn decode_p2pk_roundtrips_on_random_pubkey() {
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        let (tree, bytes) = p2pk_tree(pubkey);
        let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        let recovered = decode_address_to_tree_bytes(&addr, NetworkPrefix::Mainnet).unwrap();
        assert_eq!(recovered, bytes);
        // Tree-hash invariant: blake2b256 of the recovered bytes must
        // equal the apply-path's `tree_hash_from_bytes(box.ergo_tree_bytes)`
        // for any box paying to this address.
        assert_eq!(blake2b256(&recovered), blake2b256(&bytes));
    }

    #[test]
    fn decode_p2pk_address_enforces_network_prefix() {
        let pubkey = [0x02; 33];
        let testnet_addr =
            encode_p2pk_from_pubkey(NetworkPrefix::Testnet, &pubkey).expect("encode P2PK");
        // The same pubkey is a tracked wallet key on both networks, so
        // the prefix is the only thing distinguishing this from a valid
        // mainnet change address.
        assert!(matches!(
            decode_p2pk_address(&testnet_addr, NetworkPrefix::Mainnet),
            Err(AddressDecodeError::NetworkMismatch {
                expected: NetworkPrefix::Mainnet,
                actual: 0x11,
            })
        ));
        assert_eq!(
            decode_p2pk_address(&testnet_addr, NetworkPrefix::Testnet).expect("matching network"),
            pubkey
        );
    }

    #[test]
    fn decode_p2s_returns_inline_tree_bytes() {
        // P2S address built from a fixed segregated tree. The decoder
        // returns the same bytes the encoder consumed.
        let tree_bytes_hex = "100204a00b08cd";
        let tree = ErgoTree {
            version: 0,
            has_size: false,
            constant_segregation: true,
            constants: vec![(
                SigmaType::SSigmaProp,
                SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    [0x02; 33],
                ))),
            )],
            body: Expr::Const {
                tpe: SigmaType::SSigmaProp,
                val: SigmaValue::SigmaProp(SigmaBoolean::ProveDlog(GroupElement::from_bytes(
                    [0x02; 33],
                ))),
            },
        };
        let bytes = hex::decode(tree_bytes_hex).unwrap();
        let addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        let recovered = decode_address_to_tree_bytes(&addr, NetworkPrefix::Mainnet).unwrap();
        assert_eq!(recovered, bytes);
    }

    // ----- error paths -----

    #[test]
    fn decode_rejects_invalid_base58() {
        let err = decode_address_to_tree_bytes("not-a-valid-base58!!!", NetworkPrefix::Mainnet)
            .unwrap_err();
        assert!(matches!(err, AddressDecodeError::Base58(_)));
    }

    #[test]
    fn decode_rejects_too_short_payload() {
        // 4 raw bytes < 1 (header) + 4 (checksum).
        let raw = [0xAA, 0xBB, 0xCC, 0xDD];
        let s = bs58::encode(&raw).into_string();
        let err = decode_address_to_tree_bytes(&s, NetworkPrefix::Mainnet).unwrap_err();
        assert!(matches!(err, AddressDecodeError::TooShort(4)));
    }

    #[test]
    fn decode_rejects_bad_checksum() {
        let pubkey = [0x02; 33];
        let (tree, bytes) = p2pk_tree(pubkey);
        let mut addr = encode_address(NetworkPrefix::Mainnet, &tree, &bytes);
        // Flip the last base58 char — perturbs the checksum bytes after
        // decode, so the recomputed prefix-hash no longer matches.
        let last = addr.pop().unwrap();
        addr.push(if last == 'a' { 'b' } else { 'a' });
        let err = decode_address_to_tree_bytes(&addr, NetworkPrefix::Mainnet).unwrap_err();
        assert!(matches!(err, AddressDecodeError::BadChecksum));
    }

    #[test]
    fn decode_rejects_network_mismatch() {
        let pubkey = [0x02; 33];
        let (tree, bytes) = p2pk_tree(pubkey);
        let testnet_addr = encode_address(NetworkPrefix::Testnet, &tree, &bytes);
        let err = decode_address_to_tree_bytes(&testnet_addr, NetworkPrefix::Mainnet).unwrap_err();
        match err {
            AddressDecodeError::NetworkMismatch { expected, actual } => {
                assert_eq!(expected, NetworkPrefix::Mainnet);
                assert_eq!(actual & 0xF0, 0x10);
            }
            other => panic!("expected NetworkMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_p2sh_address_type() {
        // Manually construct a P2SH-shaped raw byte sequence (header
        // 0x02 mainnet, 24B script hash, then valid checksum). We
        // don't expect to roundtrip; just verify the decoder rejects.
        let mut raw = vec![0x02u8]; // mainnet P2SH header.
        raw.extend_from_slice(&[0x55u8; 24]);
        let csum = blake2b256(&raw);
        raw.extend_from_slice(&csum.as_bytes()[..CHECKSUM_LEN]);
        let s = bs58::encode(&raw).into_string();
        let err = decode_address_to_tree_bytes(&s, NetworkPrefix::Mainnet).unwrap_err();
        assert!(matches!(err, AddressDecodeError::UnsupportedType(0x02)));
    }

    #[test]
    fn encode_p2sh_mainnet_shape_and_checksum() {
        // Structural check independent of any oracle: 29 raw bytes,
        // header = mainnet|0x02, content = blake2b256(prop)[..24],
        // checksum = blake2b256(prefix||content)[..4].
        let prop = [0xD1u8, 0x91, 0xA3, 0x04, 0xC8, 0x01];
        let addr = encode_p2sh(NetworkPrefix::Mainnet, &prop);
        let raw = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(raw.len(), 1 + P2SH_CONTENT_LEN + CHECKSUM_LEN);
        assert_eq!(raw[0], 0x02, "mainnet P2SH header");
        let digest = blake2b256(&prop);
        assert_eq!(&raw[1..25], &digest.as_bytes()[..P2SH_CONTENT_LEN]);
        let csum = blake2b256(&raw[..25]);
        assert_eq!(&raw[25..29], &csum.as_bytes()[..CHECKSUM_LEN]);
    }

    // ----- oracle parity -----

    #[test]
    fn encode_p2sh_matches_scala_pay2sh_oracle_vector() {
        // Oracle: TyperOracle.scala `cc` verb (sigma-state 6.0.2 SigmaCompiler +
        // Pay2SHAddress, ORACLE_NETWORK=testnet), captured 2026-07-04
        // (.superpowers/sdd/task-1-report.md, Step-4 smoke, line 2):
        //   cc PK("3WwXpssaZwcNzaGMv3AgxBdTPJQBt5gCmqBsg3DykQ39bYdhJBsN")
        //   → OK 0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        //        5AgXz2KadZrAXE86MMjVQ7UAWeRFbhBZcQms4j2RgBuHNrVRwY7xvp2S
        //        qETVgcEctaXurNbFRgGUcZEGg4EKa8R4a5UNHY7
        // The proposition Scala hashes is the tree body WITHOUT the 0x00
        // header byte (bare SigmaPropConstant, no segregated constants).
        let prop =
            hex::decode("08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        assert_eq!(
            encode_p2sh(NetworkPrefix::Testnet, &prop),
            "qETVgcEctaXurNbFRgGUcZEGg4EKa8R4a5UNHY7"
        );
    }

    #[test]
    fn encode_p2sh_matches_scala_inlined_proposition_oracle_vector() {
        // Oracle: same capture, line 1: cc sigmaProp(HEIGHT > 100)
        //   → OK 100104c801d191a37300 Xw4DF8oEhUcUi3f7LAHt
        //        qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S
        // Scala's P2SH hashes the CONSTANT-INLINED proposition of that
        // segregated tree — placeholder 0x7300 substituted with constant
        // 0x04c801 — i.e. `d191a304c801` (BoolToSigmaProp(GT(Height, 100))).
        // Pins the caller-inlines-first contract in the fn doc.
        let prop = hex::decode("d191a304c801").unwrap();
        assert_eq!(
            encode_p2sh(NetworkPrefix::Testnet, &prop),
            "qT5wgrLU3mrxjSQ8FLdaxK3TYcHcHsSLizxPe4S"
        );
    }
}

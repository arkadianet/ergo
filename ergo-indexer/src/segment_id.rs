//! Segment-id and tree-hash derivations.
//!
//! All formulas are `[inherited]` from Scala — segment ids are part of
//! the API surface (clients can derive them locally to fetch a parent's
//! spill segments) and tree hashes are the keys under `INDEXED_ADDRESS`.
//! Getting a single byte wrong here silently produces an index whose
//! records can't be looked up by Scala-compatible callers.
//!
//! The derivations are pure functions of their inputs and live at the
//! crate root because both the apply path (writes) and the query path
//! (reads) need them.

use ergo_primitives::digest::{blake2b256, Digest32};
use ergo_primitives::reader::ReadError;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ergo_tree::{write_ergo_tree, ErgoTree};

use ergo_indexer_types::TokenId;

/// Separator for box-list spill segments.
///
/// The leading and trailing spaces are part of the literal — Scala's
/// `Segment.scala:379` interpolates `s"$parentHex box segment $segNum"`
/// which produces exactly this byte sequence around the segment number.
const BOX_SEGMENT_SEP: &str = " box segment ";

/// Separator for tx-list spill segments. Same layout as
/// `BOX_SEGMENT_SEP`; cf. `Segment.scala:388`.
const TX_SEGMENT_SEP: &str = " tx segment ";

/// Suffix for `IndexedToken.uniqueId`. Scala
/// `IndexedToken.scala:127` does `ModifierId + "token"` — a **string**
/// concat where `ModifierId` is the 64-char lowercase hex of the
/// 32-byte tokenId. The literal has **no** leading or trailing spaces,
/// in contrast to the segment separators above.
const TOKEN_UNIQUE_SUFFIX: &str = "token";

/// `boxSegmentId(parent, segNum) = blake2b256(utf8(parent_hex) ‖ utf8(" box segment ") ‖ utf8(segNum_dec))`.
///
/// `parent_hex` is the lowercase 64-char hex representation of `parent`.
/// `segNum_dec` is the standard ASCII decimal of `seg_num` (no padding,
/// no sign for non-negatives — matches Scala's `Int.toString`).
pub fn box_segment_id(parent: &Digest32, seg_num: i32) -> Digest32 {
    derive_segment_id(parent, BOX_SEGMENT_SEP, seg_num)
}

/// `txSegmentId(parent, segNum) = blake2b256(utf8(parent_hex) ‖ utf8(" tx segment ") ‖ utf8(segNum_dec))`.
pub fn tx_segment_id(parent: &Digest32, seg_num: i32) -> Digest32 {
    derive_segment_id(parent, TX_SEGMENT_SEP, seg_num)
}

fn derive_segment_id(parent: &Digest32, sep: &str, seg_num: i32) -> Digest32 {
    let parent_hex = hex::encode(parent.as_bytes());
    let mut buf = String::with_capacity(parent_hex.len() + sep.len() + 11);
    buf.push_str(&parent_hex);
    buf.push_str(sep);
    // `i32::to_string()` produces the standard ASCII decimal form; for
    // negative values (Scala `Int` is also signed) it prefixes "-".
    // Negative segNums never occur in practice (the counter is
    // monotonic, starts at 0) but matching the formula exactly keeps
    // the function total.
    buf.push_str(&seg_num.to_string());
    blake2b256(buf.as_bytes())
}

/// `treeHash(tree) = blake2b256(write_ergo_tree(tree))`. Mirrors Scala's
/// `IndexedErgoAddressSerializer.hashErgoTree(tree: ErgoTree)` which
/// hashes `tree.bytes` (the canonical serialized form).
///
/// Returns the same hash as [`tree_hash_from_bytes`] would on the
/// canonically-serialized output. Use this when you only have the
/// parsed `ErgoTree`; prefer `tree_hash_from_bytes` on the hot apply
/// path where you already have the original tree bytes from box
/// deserialization.
pub fn tree_hash(tree: &ErgoTree) -> Result<Digest32, ReadError> {
    let mut w = VlqWriter::new();
    write_ergo_tree(&mut w, tree)?;
    Ok(blake2b256(&w.result()))
}

/// `treeHash` from already-serialized bytes. Avoids the re-serialization
/// allocation when the caller already has the canonical bytes (e.g.
/// preserved during box deserialization).
pub fn tree_hash_from_bytes(tree_bytes: &[u8]) -> Digest32 {
    blake2b256(tree_bytes)
}

/// `uniqueId(tokenId) = blake2b256(utf8(token_id_hex) ‖ utf8("token"))`.
///
/// `token_id_hex` is the lowercase 64-char hex of the 32-byte token
/// id. This is the redb key under `INDEXED_TOKEN` — getting it wrong
/// silently produces records that Scala-compatible callers cannot look
/// up. The string concat (vs byte concat) is `[inherited]` from
/// `IndexedToken.scala:127` (`ModifierId + "token"`).
pub fn token_unique_id(token_id: &TokenId) -> Digest32 {
    let token_hex = hex::encode(token_id.as_bytes());
    let mut buf = String::with_capacity(token_hex.len() + TOKEN_UNIQUE_SUFFIX.len());
    buf.push_str(&token_hex);
    buf.push_str(TOKEN_UNIQUE_SUFFIX);
    blake2b256(buf.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;
    use ergo_ser::ergo_tree::read_ergo_tree;

    fn d(hex_str: &str) -> Digest32 {
        let bytes = hex::decode(hex_str).expect("valid hex");
        let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
        Digest32::from_bytes(arr)
    }

    fn assert_seg(actual: Digest32, expected_hex: &str, label: &str) {
        assert_eq!(
            hex::encode(actual.as_bytes()),
            expected_hex,
            "{label} mismatch — Scala oracle is the authoritative reference",
        );
    }

    // Vectors below were independently computed in Python against the
    // spec formula and cross-checked against the byte-for-byte
    // separator in `Segment.scala:379, 388`. Any change here means
    // we've broken parity with the Scala explorer API.

    // ----- happy path -----

    #[test]
    fn box_segment_id_zero_parent_seg_zero() {
        let zero = Digest32::ZERO;
        assert_seg(
            box_segment_id(&zero, 0),
            "4360c138405e66ccd9b337a0441e3b150dfa1e514172836b4f1e142e9ac73fb2",
            "box_segment_id(zero, 0)",
        );
    }

    #[test]
    fn tx_segment_id_zero_parent_seg_zero() {
        let zero = Digest32::ZERO;
        assert_seg(
            tx_segment_id(&zero, 0),
            "38795a06670aeb7ac4ae0e51e5de0f9682253604e769c1626f14a98dc6e72958",
            "tx_segment_id(zero, 0)",
        );
    }

    #[test]
    fn box_segment_id_ab_parent_seg_zero() {
        let ab = Digest32::from_bytes([0xAB; 32]);
        assert_seg(
            box_segment_id(&ab, 0),
            "70a7d1cd8c0f94c3467057d593184395163617ee361a343b70bcb87f690c0dab",
            "box_segment_id(ab, 0)",
        );
    }

    #[test]
    fn box_segment_id_ab_parent_seg_one() {
        // Confirms segNum_dec is "1" not "01" or anything else.
        let ab = Digest32::from_bytes([0xAB; 32]);
        assert_seg(
            box_segment_id(&ab, 1),
            "fe8ca41cc6fb02657c7197bec73afcdea464a985137b649c5c1ff7553d420153",
            "box_segment_id(ab, 1)",
        );
    }

    #[test]
    fn tx_segment_id_ab_parent_seg_zero() {
        // Confirms box vs tx separator literals are distinct.
        let ab = Digest32::from_bytes([0xAB; 32]);
        assert_seg(
            tx_segment_id(&ab, 0),
            "5fb838f436ed547e29d23b33b043838836ec8a080cccf60ceb00b3f8a0971f2e",
            "tx_segment_id(ab, 0)",
        );
    }

    #[test]
    fn box_segment_id_inc_parent_seg_twelve() {
        // Multi-digit segNum, asymmetric parent bytes — guards against
        // accidental endian flips and zero-pad quirks.
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let inc = Digest32::from_bytes(bytes);
        assert_seg(
            box_segment_id(&inc, 12),
            "c408061288b886e22a5071f8ae208cc5f956ff3210dd1452882df927a5f9b5be",
            "box_segment_id(inc, 12)",
        );
    }

    #[test]
    fn box_segment_id_inc_parent_seg_1024() {
        // Four-digit segNum; same parent as above so the only delta
        // from the previous test is the segNum encoding.
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let inc = Digest32::from_bytes(bytes);
        assert_seg(
            box_segment_id(&inc, 1024),
            "41c7fa075abc21b8364b971cc3de71f5c749128271804f0015a4348dd501f051",
            "box_segment_id(inc, 1024)",
        );
    }

    #[test]
    fn box_and_tx_separators_produce_distinct_ids() {
        // Sanity: `" box segment "` and `" tx segment "` must not
        // collide for any (parent, seg) pair.
        let parent = d("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        for seg in [0i32, 1, 7, 99, 1024] {
            assert_ne!(
                box_segment_id(&parent, seg),
                tx_segment_id(&parent, seg),
                "box and tx segment ids collided at seg={seg}",
            );
        }
    }

    #[test]
    fn tree_hash_matches_blake2b256_of_serialized_bytes() {
        // Smallest valid mainnet ErgoTree: the always-true placeholder
        // body that we use for soft-fork wraps. Two paths must agree:
        // `tree_hash(parsed_tree)` must equal
        // `tree_hash_from_bytes(original_bytes)`.
        // Header 0x00 + body "0101" = SBoolean Const true.
        let bytes = hex::decode("000101").unwrap();
        let mut r = VlqReader::new(&bytes);
        let tree = read_ergo_tree(&mut r).unwrap();
        let from_parsed = tree_hash(&tree).unwrap();
        let from_bytes = tree_hash_from_bytes(&bytes);
        assert_eq!(
            from_parsed, from_bytes,
            "tree_hash and tree_hash_from_bytes diverged on a roundtripped tree"
        );
        // Independent ground truth: blake2b256 of the literal bytes.
        let direct = blake2b256(&bytes);
        assert_eq!(from_parsed, direct);
    }

    #[test]
    fn token_unique_id_zero() {
        // Vector independently computed via Python:
        //   blake2b256(utf8("00"*32) ++ utf8("token"))
        let zero = TokenId::ZERO;
        assert_seg(
            token_unique_id(&zero),
            "d63e8e9407db2bce7acc018e30295bea195df2b7ebaf1785ec4b8fc4f54ec2e9",
            "token_unique_id(zero)",
        );
    }

    #[test]
    fn token_unique_id_all_ab() {
        // Confirms hex encoding is lowercase ("ab"*32 not "AB"*32) — a
        // hex-case flip changes the input bytes to blake2b and produces
        // a different digest, which would break Scala-compat lookup.
        let ab = TokenId::from_bytes([0xAB; 32]);
        assert_seg(
            token_unique_id(&ab),
            "305942f651986baf2bad81802e3dec7ec3c844f2c0bac4782d5e26eb859dd5ad",
            "token_unique_id(0xAB...)",
        );
    }

    #[test]
    fn token_unique_id_incrementing() {
        // Asymmetric input bytes — guards against accidental endian
        // flips inside hex::encode.
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let inc = TokenId::from_bytes(bytes);
        assert_seg(
            token_unique_id(&inc),
            "9d645517f5602aa23a9f5cd0b175a7096b61a9fbb90cd6ba1a3fe19452953077",
            "token_unique_id(0..31)",
        );
    }

    #[test]
    fn token_unique_id_deadbeef_pattern() {
        // Stable mainnet-shaped vector — `deadbeef` repeated 8× is a
        // common smoke-test input and confirms the suffix has no
        // leading/trailing whitespace (a single space would shift every
        // byte of the digest).
        let id = d("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert_seg(
            token_unique_id(&id),
            "388ebb68ec24156f79150de596d75ec03ae0167bfcbfdc6725e4104ae78f2d14",
            "token_unique_id(deadbeef×8)",
        );
    }

    #[test]
    fn tree_hash_emission_contract_matches_known_blake2b() {
        // The mainnet emission contract — same hex as the
        // `trace_emission_contract` test in ergo-ser. We re-parse and
        // serialize it here to confirm the roundtrip preserves bytes
        // (so tree_hash is stable across parse+serialize).
        let original = hex::decode("101004020e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a7017300730110010204020404040004c0fd4f05808c82f5f6030580b8c9e5ae040580f882ad16040204c0944004c0f407040004000580f882ad16d19683030191a38cc7a7019683020193c2b2a57300007473017302830108cdeeac93a38cc7b2a573030001978302019683040193b1a5730493c2a7c2b2a573050093958fa3730673079973089c73097e9a730a9d99a3730b730c0599c1a7c1b2a5730d00938cc7b2a5730e0001a390c1a7730f").unwrap();
        let mut r = VlqReader::new(&original);
        let tree = read_ergo_tree(&mut r).unwrap();
        let h_parsed = tree_hash(&tree).unwrap();
        let h_bytes = tree_hash_from_bytes(&original);
        assert_eq!(
            h_parsed, h_bytes,
            "emission contract: tree_hash(parsed) != tree_hash_from_bytes(original)",
        );
    }
}

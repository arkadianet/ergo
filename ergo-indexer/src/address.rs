//! `IndexedErgoAddress` parent record + `BalanceInfo`. Mirrors Scala
//! `IndexedErgoAddress.scala:117-128` and `BalanceInfo.scala:91-112`.
//!
//! An address record is keyed by `treeHash = blake2b256(tree.bytes)` —
//! one record per *tree-hash*, not per Base58 address. The body wire
//! format is:
//!
//! ```text
//! [serializedId (treeHash): 32 bytes raw]
//! [balanceInfo: option<BalanceInfo>]      // 1-byte presence + body if Some
//! [segment body]                          // see `crate::segment`
//! ```
//!
//! Spill segments under the same `treeHash` parent are stored as
//! standalone `Segment` rows under `SEGMENTS`, keyed by the derived
//! `box_segment_id` / `tx_segment_id` (see `crate::segment_id`). They
//! carry no per-type prefix and no `BalanceInfo` — only the segment
//! body.
//!
//! `BalanceInfo` itself is the running per-address accumulator:
//! - `nano_ergs`: total ERG balance for this address (sum of unspent
//!   box values minus spent box values).
//! - `tokens`: an ordered list of `(token_id, amount)` pairs. Order
//!   matches insertion order in Scala (`ArrayBuffer.append`), so the
//!   wire format is order-preserving — an `add(box)` on a token first
//!   seen here pushes to the back; `subtract(box)` either decrements
//!   in place or removes when the entry hits zero. Two functionally
//!   equivalent balance histories that differ in token-touch order
//!   produce different bytes; this is `[inherited]` because external
//!   callers diff `BalanceInfo.bytes` byte-for-byte against Scala.

use ergo_primitives::digest::Digest32;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::segment::{read_segment, write_segment, Segment};

/// Per-address running balance. Mirrors Scala `BalanceInfo.scala:18-23`.
///
/// Token amounts are stored as signed `i64` because Scala uses
/// `Long` — but in practice values are non-negative. Box values are
/// `Long` on chain, and `subtract` clamps `nano_ergs` to `>= 0`
/// (`BalanceInfo.scala:73`); we preserve that semantic in the apply
/// path, not the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BalanceInfo {
    pub nano_ergs: i64,
    /// Token bundle, order-preserving. Each entry is
    /// `(token_id, amount)` — `token_id` is the 32-byte modifier id of
    /// the token (raw bytes, NOT the `IndexedToken.uniqueId`).
    pub tokens: Vec<(Digest32, i64)>,
}

impl BalanceInfo {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Mirror of Scala `BalanceInfo.add(box)` (`BalanceInfo.scala:48-67`):
    /// add `nano_ergs_delta` to the ERG total and merge each token into
    /// the bundle. Existing token entries are summed in place; first-
    /// touch tokens are appended at the back. The append-on-first-touch
    /// rule is what makes the bundle order-preserving.
    pub fn add_box(&mut self, nano_ergs_delta: i64, tokens: &[(Digest32, i64)]) {
        self.nano_ergs += nano_ergs_delta;
        for (id, amount) in tokens {
            match self.tokens.iter_mut().find(|(tid, _)| tid == id) {
                Some(entry) => entry.1 += amount,
                None => self.tokens.push((*id, *amount)),
            }
        }
    }

    /// Mirror of Scala `BalanceInfo.subtract(box)` (`BalanceInfo.scala:69-87`):
    /// subtract `nano_ergs_delta` from the ERG total — clamped to `>= 0`
    /// per `BalanceInfo.scala:73` — and decrement each token entry in
    /// place. An entry whose remaining amount is `<= 0` is removed
    /// (preserves the order-preserving invariant: tokens that hit zero
    /// disappear, surviving tokens keep their relative position).
    pub fn subtract_box(&mut self, nano_ergs_delta: i64, tokens: &[(Digest32, i64)]) {
        self.nano_ergs = (self.nano_ergs - nano_ergs_delta).max(0);
        for (id, amount) in tokens {
            if let Some(pos) = self.tokens.iter().position(|(tid, _)| tid == id) {
                self.tokens[pos].1 -= amount;
                if self.tokens[pos].1 <= 0 {
                    self.tokens.remove(pos);
                }
            }
        }
    }
}

/// Serialize a `BalanceInfo` body. Order and types match
/// `BalanceInfoSerializer.serialize` (`BalanceInfo.scala:93-100`).
pub fn write_balance_info(w: &mut VlqWriter, b: &BalanceInfo) {
    w.put_i64(b.nano_ergs);
    w.put_i32(b.tokens.len() as i32);
    for (id, amount) in &b.tokens {
        w.put_bytes(id.as_bytes());
        w.put_i64(*amount);
    }
}

/// Parse a `BalanceInfo` body. Inverse of [`write_balance_info`].
pub fn read_balance_info(r: &mut VlqReader) -> Result<BalanceInfo, ReadError> {
    let nano_ergs = r.get_i64()?;
    let tokens_len = r.get_i32()?;
    if tokens_len < 0 {
        return Err(ReadError::InvalidData(format!(
            "BalanceInfo tokens length is negative: {tokens_len}"
        )));
    }
    let mut tokens = Vec::with_capacity(tokens_len as usize);
    for _ in 0..tokens_len {
        let id_bytes = r.get_bytes(32)?;
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(id_bytes);
        let amount = r.get_i64()?;
        tokens.push((Digest32::from_bytes(id_arr), amount));
    }
    Ok(BalanceInfo { nano_ergs, tokens })
}

/// Parent record under `INDEXED_ADDRESS`, keyed by `tree_hash`.
///
/// `tree_hash` is the same value used as the redb key — it is stored
/// in the body too because Scala's `IndexedErgoAddress.parse` reads
/// the 32-byte prefix back. We preserve the redundancy for byte-for-
/// byte parity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedAddress {
    pub tree_hash: Digest32,
    /// `None` only on spill construction (`factory(segmentId)` creates
    /// records without balance) — but spills don't go under
    /// `INDEXED_ADDRESS`. For `INDEXED_ADDRESS` rows, expect `Some`
    /// once the apply path has touched the address at least once.
    pub balance: Option<BalanceInfo>,
    pub segment: Segment,
}

impl IndexedAddress {
    /// New empty parent record — no balance, empty segment buffers,
    /// zero spill counters. Mirrors Scala's `new IndexedErgoAddress`
    /// before the first `add`.
    pub fn empty(tree_hash: Digest32) -> Self {
        Self {
            tree_hash,
            balance: Some(BalanceInfo::empty()),
            segment: Segment::empty(),
        }
    }
}

/// Serialize an `IndexedErgoAddress` parent record. Layout matches
/// `IndexedErgoAddressSerializer.serialize`
/// (`IndexedErgoAddress.scala:116-120`).
pub fn write_indexed_address(w: &mut VlqWriter, a: &IndexedAddress) {
    w.put_bytes(a.tree_hash.as_bytes());
    write_option_balance(w, a.balance.as_ref());
    write_segment(w, &a.segment);
}

/// Parse an `IndexedErgoAddress` parent record. Inverse of
/// [`write_indexed_address`].
pub fn read_indexed_address(r: &mut VlqReader) -> Result<IndexedAddress, ReadError> {
    let tree_bytes = r.get_bytes(32)?;
    let mut tree_arr = [0u8; 32];
    tree_arr.copy_from_slice(tree_bytes);
    let tree_hash = Digest32::from_bytes(tree_arr);
    let balance = read_option_balance(r)?;
    let segment = read_segment(r)?;
    Ok(IndexedAddress {
        tree_hash,
        balance,
        segment,
    })
}

/// Scorex `Writer.putOption` shape — a 1-byte presence flag (`0x01`
/// for Some, `0x00` for None) followed by the inner content if Some.
fn write_option_balance(w: &mut VlqWriter, b: Option<&BalanceInfo>) {
    match b {
        Some(bi) => {
            w.put_u8(0x01);
            write_balance_info(w, bi);
        }
        None => w.put_u8(0x00),
    }
}

fn read_option_balance(r: &mut VlqReader) -> Result<Option<BalanceInfo>, ReadError> {
    let flag = r.get_u8()?;
    match flag {
        0x00 => Ok(None),
        0x01 => Ok(Some(read_balance_info(r)?)),
        other => Err(ReadError::InvalidData(format!(
            "BalanceInfo Option presence flag must be 0x00 or 0x01, got 0x{other:02x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(hex_str: &str) -> Digest32 {
        let bytes = hex::decode(hex_str).expect("valid hex");
        let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
        Digest32::from_bytes(arr)
    }

    fn balance_roundtrip(b: &BalanceInfo) {
        let mut w = VlqWriter::new();
        write_balance_info(&mut w, b);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_balance_info(&mut r).unwrap();
        assert!(r.is_empty(), "leftover bytes after BalanceInfo roundtrip");
        assert_eq!(&parsed, b);
    }

    fn address_roundtrip(a: &IndexedAddress) -> Vec<u8> {
        let mut w = VlqWriter::new();
        write_indexed_address(&mut w, a);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let parsed = read_indexed_address(&mut r).unwrap();
        assert!(
            r.is_empty(),
            "leftover bytes after IndexedAddress roundtrip"
        );
        assert_eq!(&parsed, a);
        bytes
    }

    // ----- happy path -----

    #[test]
    fn empty_balance_info_roundtrips() {
        let b = BalanceInfo::empty();
        balance_roundtrip(&b);
    }

    #[test]
    fn balance_info_with_tokens_roundtrips() {
        let b = BalanceInfo {
            nano_ergs: 1_000_000_000,
            tokens: vec![
                (
                    d("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    42,
                ),
                (
                    d("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                    i64::MAX,
                ),
            ],
        };
        balance_roundtrip(&b);
    }

    #[test]
    fn balance_info_token_order_is_preserved() {
        // Two BalanceInfos with the same set of (id, amount) entries
        // but different orderings must serialize to different bytes.
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let id_b = d("0202020202020202020202020202020202020202020202020202020202020202");
        let b1 = BalanceInfo {
            nano_ergs: 0,
            tokens: vec![(id_a, 7), (id_b, 11)],
        };
        let b2 = BalanceInfo {
            nano_ergs: 0,
            tokens: vec![(id_b, 11), (id_a, 7)],
        };
        let bytes1 = {
            let mut w = VlqWriter::new();
            write_balance_info(&mut w, &b1);
            w.result()
        };
        let bytes2 = {
            let mut w = VlqWriter::new();
            write_balance_info(&mut w, &b2);
            w.result()
        };
        assert_ne!(
            bytes1, bytes2,
            "token order must be byte-significant (matches Scala ArrayBuffer)",
        );
    }

    #[test]
    fn balance_info_negative_token_count_rejected() {
        let mut w = VlqWriter::new();
        w.put_i64(0);
        w.put_i32(-1);
        let bytes = w.result();
        let mut r = VlqReader::new(&bytes);
        let err = read_balance_info(&mut r).unwrap_err();
        match err {
            ReadError::InvalidData(msg) => assert!(msg.contains("negative")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn empty_indexed_address_roundtrips() {
        let a = IndexedAddress::empty(Digest32::ZERO);
        address_roundtrip(&a);
    }

    #[test]
    fn indexed_address_with_balance_and_segment_roundtrips() {
        let a = IndexedAddress {
            tree_hash: d("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            balance: Some(BalanceInfo {
                nano_ergs: 999,
                tokens: vec![(
                    d("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"),
                    50,
                )],
            }),
            segment: Segment {
                txs: vec![1, 2, 3],
                boxes: vec![10, -20, 30],
                box_segment_count: 1,
                tx_segment_count: 0,
            },
        };
        address_roundtrip(&a);
    }

    #[test]
    fn indexed_address_with_no_balance_roundtrips() {
        // Spill records are constructed without balance; the wire
        // format must accept None too (1-byte 0x00 instead of 0x01 +
        // BalanceInfo body).
        let a = IndexedAddress {
            tree_hash: d("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            balance: None,
            segment: Segment::empty(),
        };
        let bytes = address_roundtrip(&a);
        // 32B tree_hash + 1B None flag + 4B empty Segment = 37B
        assert_eq!(bytes.len(), 32 + 1 + 4);
        // The presence flag must be exactly 0x00 right after the hash.
        assert_eq!(bytes[32], 0x00);
    }

    #[test]
    fn indexed_address_with_balance_starts_with_0x01_after_hash() {
        // Defensive: confirm the Option encoding matches Scorex
        // putOption (0x01 for Some, 0x00 for None) byte-for-byte.
        let a = IndexedAddress::empty(Digest32::from_bytes([0xCC; 32]));
        let mut w = VlqWriter::new();
        write_indexed_address(&mut w, &a);
        let bytes = w.result();
        assert_eq!(&bytes[..32], &[0xCC; 32], "tree_hash prefix");
        assert_eq!(bytes[32], 0x01, "Some(balance) flag");
    }

    #[test]
    fn indexed_address_invalid_option_flag_rejected() {
        let mut bytes = vec![0u8; 32];
        bytes.push(0x77);
        let mut r = VlqReader::new(&bytes);
        let err = read_indexed_address(&mut r).unwrap_err();
        match err {
            ReadError::InvalidData(msg) => assert!(msg.contains("0x77")),
            other => panic!("expected InvalidData, got {other:?}"),
        }
    }

    #[test]
    fn add_box_appends_first_touch_tokens_at_back() {
        let mut b = BalanceInfo::empty();
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let id_b = d("0202020202020202020202020202020202020202020202020202020202020202");
        b.add_box(100, &[(id_a, 5)]);
        b.add_box(200, &[(id_b, 7)]);
        assert_eq!(b.nano_ergs, 300);
        assert_eq!(b.tokens, vec![(id_a, 5), (id_b, 7)]);
    }

    #[test]
    fn add_box_increments_existing_token_in_place() {
        let mut b = BalanceInfo::empty();
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let id_b = d("0202020202020202020202020202020202020202020202020202020202020202");
        b.add_box(0, &[(id_a, 5), (id_b, 7)]);
        b.add_box(0, &[(id_a, 3)]);
        // id_a stays at position 0, amount summed.
        assert_eq!(b.tokens, vec![(id_a, 8), (id_b, 7)]);
    }

    #[test]
    fn subtract_box_clamps_nano_ergs_at_zero() {
        let mut b = BalanceInfo {
            nano_ergs: 50,
            tokens: vec![],
        };
        b.subtract_box(80, &[]);
        assert_eq!(
            b.nano_ergs, 0,
            "subtract must clamp at 0 per BalanceInfo.scala:73"
        );
    }

    #[test]
    fn subtract_box_drops_tokens_at_zero() {
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let id_b = d("0202020202020202020202020202020202020202020202020202020202020202");
        let mut b = BalanceInfo {
            nano_ergs: 100,
            tokens: vec![(id_a, 5), (id_b, 7)],
        };
        b.subtract_box(0, &[(id_a, 5)]);
        // id_a hits zero exactly and is removed; id_b unchanged.
        assert_eq!(b.tokens, vec![(id_b, 7)]);
    }

    #[test]
    fn subtract_box_drops_tokens_when_overshooting_zero() {
        // Should-not-happen-in-practice, but the rule is `<= 0 ⇒ remove`,
        // not `== 0 ⇒ remove` (`BalanceInfo.scala:81-82`).
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let mut b = BalanceInfo {
            nano_ergs: 0,
            tokens: vec![(id_a, 3)],
        };
        b.subtract_box(0, &[(id_a, 10)]);
        assert!(b.tokens.is_empty());
    }

    #[test]
    fn add_then_subtract_box_returns_to_starting_state() {
        // The apply→rollback symmetry that the indexer relies on: any
        // (value, tokens) tuple that `add_box` accepts must roundtrip
        // through `subtract_box` to the original state, provided the
        // starting state has enough margin (no clamp).
        let id_a = d("0101010101010101010101010101010101010101010101010101010101010101");
        let id_b = d("0202020202020202020202020202020202020202020202020202020202020202");
        let starting = BalanceInfo {
            nano_ergs: 1000,
            tokens: vec![(id_a, 50), (id_b, 70)],
        };
        let mut b = starting.clone();
        let delta_value = 200_i64;
        let delta_tokens = [(id_a, 5)];
        b.add_box(delta_value, &delta_tokens);
        b.subtract_box(delta_value, &delta_tokens);
        assert_eq!(b, starting);
    }
}

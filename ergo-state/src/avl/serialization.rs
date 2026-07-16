//! AVL+ node and allocator-metadata byte codecs.
//!
//! Persisted layouts (any change here is consensus-affecting):
//!
//! * Leaf:        `0x00 || key[32] || value_len[4] || value[var] || next_key[32]`
//! * Internal v2: `0x02 || key[32] || left[8] || right[8] || balance[1]
//!                 || left_label[32] || right_label[32]`
//! * Internal v1: `0x01 || key[32] || left[8] || right[8] || balance[1]`
//!   (legacy, **read-only**: `node_from_bytes` still hydrates it but no
//!   v2-capable writer produces child-labelless nodes anymore)
//!
//! `AllocMeta` is `next_id[8]` big-endian under `STATE_META["allocator"]`,
//! kept separate from consensus state so `committed_root` stays purely
//! about consensus data.
//!
//! `node_to_bytes` and `node_from_bytes` panic on malformed input today.
//! The write path's `expect(...)` on missing child labels is an
//! *internal mutation invariant*, not a corrupt-DB path: every mutation
//! site (insert, delete, rotate, rebalance) must populate child labels
//! before handing a node to the writer. That panic is a bug trap and
//! stays.

use ergo_primitives::digest::Digest32;

use super::node::AvlNode;
use crate::store::StateError;

/// Serialize an `AvlNode` to bytes. Structural fields only — the cached
/// self-label is derived data and never persisted. See module docs for
/// the layout.
///
/// Panics if an `Internal` is serialized with `left_label` or
/// `right_label` still `None`. That is an internal mutation invariant,
/// not a corrupt-input path.
pub fn node_to_bytes(node: &AvlNode) -> Vec<u8> {
    let mut buf = Vec::new();
    match node {
        AvlNode::Leaf {
            key,
            value,
            next_key,
            ..
        } => {
            buf.push(0x00);
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
            buf.extend_from_slice(value);
            buf.extend_from_slice(next_key);
        }
        AvlNode::Internal {
            key,
            left,
            right,
            balance,
            left_label,
            right_label,
            ..
        } => {
            buf.push(0x02);
            buf.extend_from_slice(key);
            buf.extend_from_slice(&left.to_be_bytes());
            buf.extend_from_slice(&right.to_be_bytes());
            buf.push(*balance as u8);
            buf.extend_from_slice(
                left_label
                    .as_ref()
                    .expect("node_to_bytes: Internal.left_label must be Some — mutation path forgot to populate")
                    .as_bytes(),
            );
            buf.extend_from_slice(
                right_label
                    .as_ref()
                    .expect("node_to_bytes: Internal.right_label must be Some — mutation path forgot to populate")
                    .as_bytes(),
            );
        }
    }
    buf
}

/// Deserialize an `AvlNode` from bytes. Accepts:
/// - Leaf tag `0x00`
/// - Internal tag `0x01` (v1): no child labels — `left_label`/`right_label` = `None`
/// - Internal tag `0x02` (v2): child labels present after the balance byte
///
/// The self-label field is always discarded on read; it is recomputed
/// lazily from structural fields and the hydrated child labels.
///
/// Returns `StateError::Serialization` on any of:
/// - empty input,
/// - unknown tag byte,
/// - leaf truncation before key/value-len/value/next_key,
/// - leaf `value_len` overflowing or running past the slice,
/// - v1 internal truncation before key/left/right/balance,
/// - v2 internal truncation before child labels.
pub fn node_from_bytes(data: &[u8]) -> Result<AvlNode, StateError> {
    let bad = |msg: String| StateError::Serialization(msg);
    let tag = *data
        .first()
        .ok_or_else(|| bad("avl node: empty bytes".to_string()))?;
    match tag {
        0x00 => {
            if data.len() < 37 {
                return Err(bad(format!(
                    "avl node leaf: header truncated ({} bytes, need >=37)",
                    data.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[1..33]);
            let value_len = u32::from_be_bytes(data[33..37].try_into().unwrap()) as usize;
            let value_end = 37usize
                .checked_add(value_len)
                .ok_or_else(|| bad(format!("avl node leaf: value_len overflow ({value_len})")))?;
            let next_key_end = value_end
                .checked_add(32)
                .ok_or_else(|| bad("avl node leaf: next_key offset overflow".to_string()))?;
            if data.len() < next_key_end {
                return Err(bad(format!(
                    "avl node leaf: body truncated (have {}, need >={} for value_len={})",
                    data.len(),
                    next_key_end,
                    value_len
                )));
            }
            let value = data[37..value_end].to_vec();
            let mut next_key = [0u8; 32];
            next_key.copy_from_slice(&data[value_end..next_key_end]);
            // Any trailing bytes (v2 label suffix) are ignored.
            Ok(AvlNode::Leaf {
                key,
                value,
                next_key,
                label: None,
            })
        }
        0x01 => {
            // Legacy internal — child labels unknown.
            if data.len() < 50 {
                return Err(bad(format!(
                    "avl node v1 internal: truncated ({} bytes, need >=50)",
                    data.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[1..33]);
            let left = u64::from_be_bytes(data[33..41].try_into().unwrap());
            let right = u64::from_be_bytes(data[41..49].try_into().unwrap());
            let balance = data[49] as i8;
            // AVL+ invariant: internal balance is `{-1, 0, 1}`. The
            // on-disk byte is `i8` so it can carry `[-128, 127]`.
            // Without this gate, a corrupt-DB read (filesystem
            // corruption, in-place format rewrite gone wrong, etc.)
            // feeds the out-of-range value to AVL rotations at
            // `tree.rs::double_left_rotate` / `double_right_rotate`
            // where the match arm panics. Mirrors the ingress-side
            // gate in `snapshot_codec.rs` as defense-in-depth.
            if !matches!(balance, -1..=1) {
                return Err(bad(format!(
                    "avl node v1 internal: balance {balance} out of {{-1, 0, 1}}"
                )));
            }
            Ok(AvlNode::Internal {
                key,
                left,
                right,
                balance,
                left_label: None,
                right_label: None,
                label: None,
            })
        }
        0x02 => {
            // v2 internal — child labels present.
            if data.len() < 114 {
                return Err(bad(format!(
                    "avl node v2 internal: truncated ({} bytes, need >=114)",
                    data.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[1..33]);
            let left = u64::from_be_bytes(data[33..41].try_into().unwrap());
            let right = u64::from_be_bytes(data[41..49].try_into().unwrap());
            let balance = data[49] as i8;
            // Same AVL+ {-1, 0, 1} invariant as v1; see v1 arm above.
            if !matches!(balance, -1..=1) {
                return Err(bad(format!(
                    "avl node v2 internal: balance {balance} out of {{-1, 0, 1}}"
                )));
            }
            let mut ll = [0u8; 32];
            ll.copy_from_slice(&data[50..82]);
            let mut rl = [0u8; 32];
            rl.copy_from_slice(&data[82..114]);
            Ok(AvlNode::Internal {
                key,
                left,
                right,
                balance,
                left_label: Some(Digest32::from_bytes(ll)),
                right_label: Some(Digest32::from_bytes(rl)),
                label: None,
            })
        }
        other => Err(bad(format!("avl node: unknown tag 0x{other:02x}"))),
    }
}

/// Allocator metadata stored under `STATE_META["allocator"]`. Separate
/// from consensus state (`StateMeta` at `"root"`) so `committed_root`
/// remains purely about consensus data.
#[derive(Debug)]
pub(crate) struct AllocMeta {
    pub next_id: u64,
}

impl AllocMeta {
    pub fn serialize(&self) -> [u8; 8] {
        self.next_id.to_be_bytes()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, StateError> {
        if data.len() < 8 {
            return Err(StateError::Serialization(format!(
                "AllocMeta: truncated input (have {} bytes, need 8)",
                data.len()
            )));
        }
        // Slice has been bounds-checked to length 8; `try_into` cannot fail.
        let next_id = u64::from_be_bytes(data[0..8].try_into().unwrap());
        Ok(Self { next_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn node_from_bytes_v1_internal_parses_without_child_labels() {
        let mut buf = vec![0x01];
        buf.extend_from_slice(&[0x42; 32]);
        buf.extend_from_slice(&100u64.to_be_bytes());
        buf.extend_from_slice(&200u64.to_be_bytes());
        buf.push(0);
        let node = node_from_bytes(&buf).expect("v1 internal parses");
        match node {
            AvlNode::Internal {
                left,
                right,
                left_label,
                right_label,
                ..
            } => {
                assert_eq!(left, 100);
                assert_eq!(right, 200);
                assert!(left_label.is_none());
                assert!(right_label.is_none());
            }
            _ => panic!("expected Internal"),
        }
    }

    // ----- error paths -----

    #[test]
    fn node_from_bytes_empty_input_errors() {
        let err = node_from_bytes(&[]).expect_err("empty must reject");
        match err {
            StateError::Serialization(msg) => assert!(msg.contains("empty bytes"), "{msg}"),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn node_from_bytes_unknown_tag_errors() {
        let err = node_from_bytes(&[0xFF, 0, 0, 0]).expect_err("unknown tag must reject");
        match err {
            StateError::Serialization(msg) => assert!(msg.contains("unknown tag 0xff"), "{msg}"),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn node_from_bytes_leaf_truncated_header_errors() {
        // 0x00 tag + only 5 bytes after = 6 total, need >= 37.
        let err = node_from_bytes(&[0x00, 0, 0, 0, 0, 0]).expect_err("truncated leaf rejects");
        match err {
            StateError::Serialization(msg) => {
                assert!(msg.contains("leaf") && msg.contains("truncated"), "{msg}")
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn node_from_bytes_leaf_value_len_overruns_slice_errors() {
        // Tag + 32-byte key + value_len=u32::MAX-10. Body cannot be 4 GiB.
        let mut buf = vec![0x00];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&(u32::MAX - 10).to_be_bytes());
        buf.extend_from_slice(&[0u8; 32]); // not enough for the claimed value_len
        let err = node_from_bytes(&buf).expect_err("oversized value_len rejects");
        match err {
            StateError::Serialization(msg) => assert!(msg.contains("body truncated"), "{msg}"),
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn node_from_bytes_v1_internal_truncated_errors() {
        // 0x01 tag + only 40 bytes total, need >= 50.
        let mut buf = vec![0x01];
        buf.extend_from_slice(&[0u8; 39]);
        let err = node_from_bytes(&buf).expect_err("truncated v1 internal rejects");
        match err {
            StateError::Serialization(msg) => {
                assert!(
                    msg.contains("v1 internal") && msg.contains("truncated"),
                    "{msg}"
                )
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn node_from_bytes_v2_internal_truncated_errors() {
        // 0x02 tag + 60 bytes total, need >= 114.
        let mut buf = vec![0x02];
        buf.extend_from_slice(&[0u8; 59]);
        let err = node_from_bytes(&buf).expect_err("truncated v2 internal rejects");
        match err {
            StateError::Serialization(msg) => {
                assert!(
                    msg.contains("v2 internal") && msg.contains("truncated"),
                    "{msg}"
                )
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }

    #[test]
    fn alloc_meta_roundtrips_through_serialize_then_deserialize() {
        for next_id in [0u64, 1, 42, u64::MAX / 2, u64::MAX] {
            let bytes = AllocMeta { next_id }.serialize();
            let parsed = AllocMeta::deserialize(&bytes).expect("8 bytes is valid");
            assert_eq!(parsed.next_id, next_id);
        }
    }

    // ----- error paths -----

    #[test]
    fn alloc_meta_deserialize_truncated_input_errors() {
        for n in 0..8 {
            let buf = vec![0u8; n];
            let err = AllocMeta::deserialize(&buf).expect_err("must reject truncation");
            match err {
                StateError::Serialization(msg) => {
                    assert!(
                        msg.contains("AllocMeta") && msg.contains(&format!("have {n} bytes")),
                        "unexpected message: {msg}"
                    );
                }
                other => panic!("expected Serialization, got {other:?}"),
            }
        }
    }

    #[test]
    fn alloc_meta_deserialize_oversize_input_succeeds_and_ignores_trailing() {
        // The on-disk layout is fixed at 8 bytes; trailing bytes from a
        // future-format extension or accidental concatenation must be
        // tolerated, mirroring the leaf-trailing-byte tolerance for AVL
        // node bytes.
        let mut buf = 0x00_00_00_00_00_00_00_2A_u64.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xFF; 16]);
        let parsed = AllocMeta::deserialize(&buf).expect("trailing bytes are tolerated");
        assert_eq!(parsed.next_id, 42);
    }
}

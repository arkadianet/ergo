//! Single-node byte codec: [`serialize_prover_node`] /
//! [`parse_prover_node`] over the Scala `ProverNodeSerializer` wire
//! format (see the module docs in `mod.rs`).
//!
//! Sibling of `mod.rs`; pure impl relocation.

use crate::avl::node::AvlNode;
use crate::store::StateError;

use super::{ChildLabels, INTERNAL_NODE_PREFIX, KEY_SIZE, LABEL_SIZE, LEAF_PREFIX};

/// Serialize a single AVL+ prover node into the Scala-compatible
/// wire format. Internal nodes need both child labels supplied via
/// `labels`; leaf nodes ignore the `labels` arg (each leaf is
/// self-describing).
pub fn serialize_prover_node(
    node: &AvlNode,
    labels: &dyn ChildLabels,
) -> Result<Vec<u8>, StateError> {
    let mut out = Vec::new();
    match node {
        AvlNode::Internal { key, balance, .. } => {
            out.push(INTERNAL_NODE_PREFIX);
            out.push(*balance as u8);
            out.extend_from_slice(key);
            let left = labels.left_label(node)?;
            let right = labels.right_label(node)?;
            out.extend_from_slice(left.as_bytes());
            out.extend_from_slice(right.as_bytes());
            debug_assert_eq!(out.len(), 1 + 1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE);
        }
        AvlNode::Leaf {
            key,
            value,
            next_key,
            ..
        } => {
            out.push(LEAF_PREFIX);
            out.extend_from_slice(key);
            // Scala `Ints.toByteArray` = 4 bytes big-endian.
            let value_len: u32 = value.len().try_into().map_err(|_| {
                StateError::Serialization(format!(
                    "AVL leaf value too large for u32 prefix: {} bytes",
                    value.len(),
                ))
            })?;
            out.extend_from_slice(&value_len.to_be_bytes());
            out.extend_from_slice(value);
            out.extend_from_slice(next_key);
        }
    }
    Ok(out)
}

/// Parsed AVL+ prover-node body. Internal nodes carry their child
/// labels as bytes; the caller stitches them into a tree by matching
/// labels to the next-parsed nodes. Leaves are fully self-contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedProverNode {
    Internal {
        balance: i8,
        key: [u8; KEY_SIZE],
        left_label: [u8; LABEL_SIZE],
        right_label: [u8; LABEL_SIZE],
    },
    Leaf {
        key: [u8; KEY_SIZE],
        value: Vec<u8>,
        next_leaf_key: [u8; KEY_SIZE],
    },
}

/// Parse a single AVL+ prover-node body. Returns the parsed node plus
/// the number of bytes consumed (so a caller can read a sequence of
/// concatenated nodes without external framing).
pub fn parse_prover_node(payload: &[u8]) -> Result<(ParsedProverNode, usize), StateError> {
    if payload.is_empty() {
        return Err(StateError::Serialization(
            "prover-node payload is empty".into(),
        ));
    }
    let prefix = payload[0];
    let body = &payload[1..];
    match prefix {
        INTERNAL_NODE_PREFIX => {
            const NEED: usize = 1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE;
            if body.len() < NEED {
                return Err(StateError::Serialization(format!(
                    "internal-node payload truncated: need {NEED} body bytes, got {}",
                    body.len(),
                )));
            }
            let balance = body[0] as i8;
            // AVL+ invariant: internal-node balance is structurally
            // restricted to {-1, 0, 1}. The on-wire byte is `i8` so
            // it can carry any value in `[-128, 127]`. Without this
            // gate, an adversarial Mode-2 UTXO snapshot can satisfy
            // the manifest's root-digest check (manifest verifies
            // root, not per-node invariants) while embedding a node
            // whose `balance` byte is later fed to AVL rotations at
            // `tree.rs::double_left_rotate` / `double_right_rotate`,
            // where the match arm `0 | -1 | 1 => …, _ => panic!(...)`
            // takes down the install thread.
            //
            // Scope of the fix: this gate closes the peer-attack
            // Mode-2 surface — bad bytes can't reach `AVL_NODES`
            // because reconstruction errors out before any write.
            // The corrupt-disk surface at `arena.rs:344`
            // (`.expect("node_from_bytes failed on persisted bytes")`)
            // is unchanged and intentional per the comment there:
            // returning `None` for a corrupt-but-present row would
            // silently violate the digest invariant, so a corrupt
            // disk row must fail loud rather than fail-soft.
            if !matches!(balance, -1..=1) {
                return Err(StateError::Serialization(format!(
                    "internal-node balance {balance} out of {{-1, 0, 1}}"
                )));
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&body[1..1 + KEY_SIZE]);
            let mut left_label = [0u8; LABEL_SIZE];
            left_label.copy_from_slice(&body[1 + KEY_SIZE..1 + KEY_SIZE + LABEL_SIZE]);
            let mut right_label = [0u8; LABEL_SIZE];
            right_label.copy_from_slice(
                &body[1 + KEY_SIZE + LABEL_SIZE..1 + KEY_SIZE + LABEL_SIZE + LABEL_SIZE],
            );
            Ok((
                ParsedProverNode::Internal {
                    balance,
                    key,
                    left_label,
                    right_label,
                },
                1 + NEED,
            ))
        }
        LEAF_PREFIX => {
            if body.len() < KEY_SIZE + 4 {
                return Err(StateError::Serialization(format!(
                    "leaf-node header truncated: need {} body bytes, got {}",
                    KEY_SIZE + 4,
                    body.len(),
                )));
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&body[..KEY_SIZE]);
            let value_len =
                u32::from_be_bytes(body[KEY_SIZE..KEY_SIZE + 4].try_into().unwrap()) as usize;
            let value_start = KEY_SIZE + 4;
            let value_end = value_start + value_len;
            let next_start = value_end;
            let next_end = next_start + KEY_SIZE;
            if body.len() < next_end {
                return Err(StateError::Serialization(format!(
                    "leaf-node body truncated: need {next_end} body bytes, got {}",
                    body.len(),
                )));
            }
            let value = body[value_start..value_end].to_vec();
            let mut next_leaf_key = [0u8; KEY_SIZE];
            next_leaf_key.copy_from_slice(&body[next_start..next_end]);
            Ok((
                ParsedProverNode::Leaf {
                    key,
                    value,
                    next_leaf_key,
                },
                1 + next_end,
            ))
        }
        other => Err(StateError::Serialization(format!(
            "unknown prover-node prefix byte: 0x{other:02x} (expected 0x00 internal or 0x01 leaf)",
        ))),
    }
}

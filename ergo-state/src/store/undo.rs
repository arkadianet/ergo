//! `UndoEntry` — the reverse delta written for every applied block,
//! plus its byte codec and the `undo_log` row-key helper. Reorg
//! recovery deserializes one of these per rolled-back block to
//! rebuild AVL+ structure and the box-level UTXO mutations.

use ergo_primitives::digest::ADDigest;

use crate::avl::changelog::{ChangeLog, NodeChange};
use crate::avl::serialization::{node_from_bytes, node_to_bytes};

use super::error::StateError;

/// Records the reverse delta for one block application.
///
/// Contains both box-level changes (for UtxoView consumers) and node-level
/// before-images (for exact structural rollback of the AVL+ tree).
#[derive(Debug)]
pub struct UndoEntry {
    pub digest_before: ADDigest,
    /// Root node ID before this block was applied.
    pub root_node_id_before: u64,
    /// Tree height before this block was applied.
    pub tree_height_before: u8,
    /// Before-image change log for exact structural rollback.
    /// Contains every node modified or created during this block's application.
    pub change_log: ChangeLog,
    /// Boxes that were removed (spent) — stored as (box_id, serialized_box)
    pub removed: Vec<([u8; 32], Vec<u8>)>,
    /// Box IDs that were created (outputs)
    pub created: Vec<[u8; 32]>,
}

impl UndoEntry {
    pub(super) fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.digest_before.as_bytes());
        buf.extend_from_slice(&self.root_node_id_before.to_be_bytes());
        buf.push(self.tree_height_before);

        // Serialize change_log
        let changes = self.change_log.changes();
        buf.extend_from_slice(&(changes.len() as u32).to_be_bytes());
        for change in changes {
            match change {
                NodeChange::Modified(id, node) => {
                    buf.push(0x00); // tag: modified
                    buf.extend_from_slice(&id.to_be_bytes());
                    let node_bytes = node_to_bytes(node);
                    buf.extend_from_slice(&(node_bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&node_bytes);
                }
                NodeChange::Created(id) => {
                    buf.push(0x01); // tag: created
                    buf.extend_from_slice(&id.to_be_bytes());
                }
            }
        }

        // Box-level removed
        buf.extend_from_slice(&(self.removed.len() as u32).to_be_bytes());
        for (box_id, box_bytes) in &self.removed {
            buf.extend_from_slice(box_id);
            buf.extend_from_slice(&(box_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(box_bytes);
        }
        // Box-level created
        buf.extend_from_slice(&(self.created.len() as u32).to_be_bytes());
        for box_id in &self.created {
            buf.extend_from_slice(box_id);
        }
        buf
    }

    pub(super) fn deserialize(data: &[u8]) -> Result<Self, StateError> {
        // Length-checked cursor advance: returns the byte slice
        // [pos..pos+n] and bumps pos. Errors on overflow or truncation
        // so a corrupt undo row never panics in slice arithmetic.
        fn take<'a>(
            data: &'a [u8],
            pos: &mut usize,
            n: usize,
            what: &'static str,
        ) -> Result<&'a [u8], StateError> {
            let end = pos.checked_add(n).ok_or_else(|| {
                StateError::Serialization(format!(
                    "UndoEntry: {what}: pos+len overflow (pos={pos}, len={n})"
                ))
            })?;
            if end > data.len() {
                return Err(StateError::Serialization(format!(
                    "UndoEntry: {what}: truncated (need {n} bytes from pos={pos}, have {})",
                    data.len()
                )));
            }
            let slice = &data[*pos..end];
            *pos = end;
            Ok(slice)
        }

        let mut pos = 0;
        let mut digest_bytes = [0u8; 33];
        digest_bytes.copy_from_slice(take(data, &mut pos, 33, "digest_before")?);
        let digest_before = ADDigest::from_bytes(digest_bytes);

        let root_node_id_before = u64::from_be_bytes(
            take(data, &mut pos, 8, "root_node_id_before")?
                .try_into()
                .unwrap(),
        );
        let tree_height_before = take(data, &mut pos, 1, "tree_height_before")?[0];

        // Deserialize change_log
        let change_count =
            u32::from_be_bytes(take(data, &mut pos, 4, "change_count")?.try_into().unwrap())
                as usize;
        let mut change_log = ChangeLog::new();
        for _ in 0..change_count {
            let tag = take(data, &mut pos, 1, "change tag")?[0];
            match tag {
                0x00 => {
                    let id = u64::from_be_bytes(
                        take(data, &mut pos, 8, "change.modified.id")?
                            .try_into()
                            .unwrap(),
                    );
                    let node_len = u32::from_be_bytes(
                        take(data, &mut pos, 4, "change.modified.node_len")?
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let node_bytes = take(data, &mut pos, node_len, "change.modified.node")?;
                    let node = node_from_bytes(node_bytes)?;
                    // Bypass dedup — these are already the correct before-images
                    change_log.push_raw(NodeChange::Modified(id, node));
                }
                0x01 => {
                    let id = u64::from_be_bytes(
                        take(data, &mut pos, 8, "change.created.id")?
                            .try_into()
                            .unwrap(),
                    );
                    change_log.push_raw(NodeChange::Created(id));
                }
                other => {
                    return Err(StateError::Serialization(format!(
                        "UndoEntry: unknown change tag 0x{other:02x} at pos={pos}"
                    )));
                }
            }
        }

        // Box-level removed
        let removed_count = u32::from_be_bytes(
            take(data, &mut pos, 4, "removed_count")?
                .try_into()
                .unwrap(),
        ) as usize;
        let mut removed = Vec::with_capacity(removed_count);
        for _ in 0..removed_count {
            let mut box_id = [0u8; 32];
            box_id.copy_from_slice(take(data, &mut pos, 32, "removed.box_id")?);
            let box_len = u32::from_be_bytes(
                take(data, &mut pos, 4, "removed.box_len")?
                    .try_into()
                    .unwrap(),
            ) as usize;
            let box_bytes = take(data, &mut pos, box_len, "removed.box_bytes")?.to_vec();
            removed.push((box_id, box_bytes));
        }

        let created_count = u32::from_be_bytes(
            take(data, &mut pos, 4, "created_count")?
                .try_into()
                .unwrap(),
        ) as usize;
        let mut created = Vec::with_capacity(created_count);
        for _ in 0..created_count {
            let mut box_id = [0u8; 32];
            box_id.copy_from_slice(take(data, &mut pos, 32, "created.box_id")?);
            created.push(box_id);
        }

        Ok(Self {
            digest_before,
            root_node_id_before,
            tree_height_before,
            change_log,
            removed,
            created,
        })
    }
}

/// Build the composite key for the undo_log table: height (4 bytes BE) + header_id (32 bytes).
pub(super) fn undo_log_key(height: u32, header_id: &[u8; 32]) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..4].copy_from_slice(&height.to_be_bytes());
    key[4..].copy_from_slice(header_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_undo_entry_bytes() -> Vec<u8> {
        UndoEntry {
            digest_before: ADDigest::from_bytes([0u8; 33]),
            root_node_id_before: 0,
            tree_height_before: 0,
            change_log: ChangeLog::new(),
            removed: Vec::new(),
            created: Vec::new(),
        }
        .serialize()
    }

    // ----- happy path -----

    #[test]
    fn undo_entry_roundtrips_empty_through_serialize_then_deserialize() {
        let bytes = empty_undo_entry_bytes();
        let parsed = UndoEntry::deserialize(&bytes).expect("self-produced bytes parse");
        assert_eq!(parsed.root_node_id_before, 0);
        assert_eq!(parsed.tree_height_before, 0);
        assert_eq!(parsed.removed.len(), 0);
        assert_eq!(parsed.created.len(), 0);
    }

    // ----- error paths -----

    #[test]
    fn undo_entry_deserialize_truncated_input_errors() {
        // Any prefix of the smallest valid encoding (an empty UndoEntry)
        // must reject as Serialization rather than panic in slice access.
        let baseline = empty_undo_entry_bytes();
        for n in 0..baseline.len() {
            let buf = &baseline[..n];
            let err = UndoEntry::deserialize(buf).expect_err("must reject truncation");
            match err {
                StateError::Serialization(msg) => {
                    assert!(
                        msg.contains("UndoEntry"),
                        "unexpected message at n={n}: {msg}"
                    );
                }
                other => panic!("expected Serialization, got {other:?}"),
            }
        }
    }

    #[test]
    fn undo_entry_deserialize_unknown_change_tag_errors() {
        // Build a row with one change-log entry, tag = 0xFF (unknown).
        // Layout: digest[33] || root_id[8] || tree_h[1] || count[4]=1 || tag[1]=0xFF || ...
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 33]); // digest_before
        buf.extend_from_slice(&0u64.to_be_bytes()); // root_node_id_before
        buf.push(0); // tree_height_before
        buf.extend_from_slice(&1u32.to_be_bytes()); // change_count = 1
        buf.push(0xFF); // unknown tag
        let err = UndoEntry::deserialize(&buf).expect_err("unknown change tag must reject");
        match err {
            StateError::Serialization(msg) => {
                assert!(msg.contains("unknown change tag 0xff"), "got: {msg}");
            }
            other => panic!("expected Serialization, got {other:?}"),
        }
    }
}

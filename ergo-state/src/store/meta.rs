//! `StateMeta` — fixed 46-byte snapshot row (key = "root") that
//! anchors the AVL+ tree pointers and the canonical post-block
//! state digest. Crash recovery deserializes one row to resume.

use super::error::StateError;

#[derive(Debug)]
pub(super) struct StateMeta {
    pub(super) height: u32,
    pub(super) tree_height: u8,
    pub(super) root_digest: [u8; 33],
    pub(super) root_node_id: u64,
}

impl StateMeta {
    pub(super) fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(46);
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.push(self.tree_height);
        buf.extend_from_slice(&self.root_digest);
        buf.extend_from_slice(&self.root_node_id.to_be_bytes());
        buf
    }

    pub(super) fn deserialize(data: &[u8]) -> Result<Self, StateError> {
        if data.len() < 46 {
            return Err(StateError::Serialization(format!(
                "StateMeta: truncated input (have {} bytes, need 46)",
                data.len()
            )));
        }
        // All slices below are bounds-checked by the gate above.
        let height = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let tree_height = data[4];
        let mut root_digest = [0u8; 33];
        root_digest.copy_from_slice(&data[5..38]);
        let root_node_id = u64::from_be_bytes(data[38..46].try_into().unwrap());
        Ok(Self {
            height,
            tree_height,
            root_digest,
            root_node_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- happy path -----

    #[test]
    fn state_meta_roundtrips_through_serialize_then_deserialize() {
        let meta = StateMeta {
            height: 600_000,
            tree_height: 24,
            root_digest: [0xAB; 33],
            root_node_id: 0x0123_4567_89AB_CDEF,
        };
        let bytes = meta.serialize();
        assert_eq!(bytes.len(), 46);
        let parsed = StateMeta::deserialize(&bytes).expect("46 bytes is valid");
        assert_eq!(parsed.height, meta.height);
        assert_eq!(parsed.tree_height, meta.tree_height);
        assert_eq!(parsed.root_digest, meta.root_digest);
        assert_eq!(parsed.root_node_id, meta.root_node_id);
    }

    // ----- error paths -----

    #[test]
    fn state_meta_deserialize_truncated_input_errors() {
        // Every length below the fixed 46-byte layout must reject.
        for n in [0usize, 1, 5, 38, 45] {
            let buf = vec![0u8; n];
            let err = StateMeta::deserialize(&buf).expect_err("must reject truncation");
            match err {
                StateError::Serialization(msg) => {
                    assert!(
                        msg.contains("StateMeta") && msg.contains(&format!("have {n} bytes")),
                        "unexpected message at n={n}: {msg}"
                    );
                }
                other => panic!("expected Serialization, got {other:?}"),
            }
        }
    }
}

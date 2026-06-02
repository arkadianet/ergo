//! Chain-level storage types for header-first sync.
//!
//! Provides persistent metadata for headers, block sections, and chain state
//! tracking with separate best-header and best-full-block pointers.
//!
//! Types here are serialization-focused. Database operations live in `store.rs`.

use std::collections::HashSet;

use thiserror::Error;

// ---- Header metadata ----

/// Persistent metadata for a validated header.
///
/// Stored in the `header_meta` table keyed by header_id\[32\].
/// `pow_validity` is the ONLY persisted validity flag. Per spec-freeze
/// invariant #4, persistent invalidity is reserved exclusively for
/// cryptographically definitive failures (invalid PoW). All other
/// failures use session-scoped `ChainState::session_invalids`.
#[derive(Clone, Debug)]
pub struct HeaderMeta {
    /// 32-byte id of the parent header.
    pub parent_id: [u8; 32],
    /// Block height of this header.
    pub height: u32,
    /// Cumulative difficulty as big-endian bytes (variable length).
    pub cumulative_score: Vec<u8>,
    /// 0 = unknown, 1 = valid, 2 = invalid_permanent (PoW only).
    pub pow_validity: u8,
    /// Block timestamp, milliseconds since the Unix epoch.
    pub timestamp: u64,
}

impl HeaderMeta {
    /// Encode this header-metadata row to the persisted byte form.
    pub fn serialize(&self) -> Vec<u8> {
        let score_len = self.cumulative_score.len();
        let mut buf = Vec::with_capacity(32 + 4 + 4 + score_len + 1 + 8);
        buf.extend_from_slice(&self.parent_id);
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&(score_len as u32).to_be_bytes());
        buf.extend_from_slice(&self.cumulative_score);
        buf.push(self.pow_validity);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    /// Decode a persisted header-metadata row, returning a structured
    /// decode error on truncated / malformed input.
    ///
    /// Production callers read the row directly from redb where the
    /// byte length is fixed by the writer; in the absence of disk
    /// corruption this never fails. Callers map the error into
    /// [`crate::store::StateError::DbCorruption`] with the table name
    /// and key context, so an operator sees `which row` was corrupt,
    /// not just a deserialize failure.
    ///
    /// Wire format (unchanged):
    /// `parent_id[32] | height:u32 BE | score_len:u32 BE | cumulative_score[score_len] | pow_validity:u8 | timestamp:u64 BE`
    pub fn deserialize(data: &[u8]) -> Result<Self, HeaderMetaDecodeError> {
        fn require<'a>(
            data: &'a [u8],
            pos: usize,
            len: usize,
            field: &'static str,
        ) -> Result<&'a [u8], HeaderMetaDecodeError> {
            data.get(pos..pos + len)
                .ok_or(HeaderMetaDecodeError::Truncated {
                    field,
                    need: len,
                    pos,
                    total: data.len(),
                })
        }

        let mut pos = 0;
        let mut parent_id = [0u8; 32];
        parent_id.copy_from_slice(require(data, pos, 32, "parent_id")?);
        pos += 32;
        let height = u32::from_be_bytes(require(data, pos, 4, "height")?.try_into().unwrap());
        pos += 4;
        let score_len =
            u32::from_be_bytes(require(data, pos, 4, "score_len")?.try_into().unwrap()) as usize;
        pos += 4;
        let cumulative_score = require(data, pos, score_len, "cumulative_score")?.to_vec();
        pos += score_len;
        let pow_validity = *require(data, pos, 1, "pow_validity")?
            .first()
            .expect("require returns non-empty slice on success");
        pos += 1;
        let timestamp = u64::from_be_bytes(require(data, pos, 8, "timestamp")?.try_into().unwrap());
        Ok(Self {
            parent_id,
            height,
            cumulative_score,
            pow_validity,
            timestamp,
        })
    }
}

/// Decode failure for [`HeaderMeta::deserialize`]. Indicates the
/// persisted row was shorter than required at some specific field.
/// Callers wrap this into `StateError::DbCorruption` with the redb
/// table + key for operator-visible provenance.
#[derive(Debug, Error)]
pub enum HeaderMetaDecodeError {
    #[error("truncated at field `{field}`: need {need} bytes at offset {pos}, total {total}")]
    Truncated {
        field: &'static str,
        need: usize,
        pos: usize,
        total: usize,
    },
}

// ---- Header availability mode (NiPoPoW sparse-history support) ----

/// Whether the locally-stored header chain is fully dense (every
/// canonical height has a row in `HEADER_CHAIN_INDEX`) or sparse
/// (only a subset is locally present, the rest being witnessed by
/// a verified NiPoPoW proof but not height-indexed).
///
/// Persisted inline on [`ChainStateMeta`]. Legacy records that
/// predate this field decode as [`HeaderAvailability::Dense`]
/// (back-compat: any chain-state that exists today is dense, since
/// no apply path can produce sparse state until sub-phase 14.5
/// lands).
///
/// Guards the hidden invariant: `best_header_height` implies every
/// height ≤ that is in `HEADER_CHAIN_INDEX`. The invariant holds for
/// `Dense` and is intentionally false for `PoPowSparse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderAvailability {
    /// Every height in `[1, best_header_height]` has a row in
    /// `HEADER_CHAIN_INDEX`. The full-node default.
    Dense,
    /// Bootstrapped via NiPoPoW. `HEADER_CHAIN_INDEX` covers only
    /// `[dense_from_height, best_header_height]`. Heights below
    /// `dense_from_height` are content-addressed in `HEADERS` /
    /// `HEADER_META` but not height-indexed.
    PoPowSparse {
        /// Lowest height with a `HEADER_CHAIN_INDEX` row. After an
        /// `apply_popow_proof` this equals
        /// `proof.suffix_head.height - k + 1` (= proof suffix bottom).
        dense_from_height: u32,
        /// Height of the proof's suffix tip at apply time. For
        /// observability and bound checks; not consensus state.
        proof_suffix_height: u32,
    },
}

impl HeaderAvailability {
    /// Wire discriminator byte for [`HeaderAvailability::Dense`].
    pub const DISC_DENSE: u8 = 0x00;
    /// Wire discriminator byte for [`HeaderAvailability::PoPowSparse`].
    pub const DISC_POPOW_SPARSE: u8 = 0x01;

    fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Dense => vec![Self::DISC_DENSE],
            Self::PoPowSparse {
                dense_from_height,
                proof_suffix_height,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 4);
                buf.push(Self::DISC_POPOW_SPARSE);
                buf.extend_from_slice(&dense_from_height.to_be_bytes());
                buf.extend_from_slice(&proof_suffix_height.to_be_bytes());
                buf
            }
        }
    }
}

/// Result of a height-to-id lookup. The 3-arm form forces callers to
/// distinguish "canonical-but-not-locally-available" ([`Self::SparseGap`])
/// from "out-of-range" ([`Self::AboveTip`]). Mode 2 manifest
/// verification and the snapshot-install re-fetch path MUST treat
/// `SparseGap` as "wait, retry next tick" rather than fraud.
///
/// See Phase 0 design §4 for the per-call-site decision tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeightLookup {
    /// The height has a canonical header id locally available.
    Dense([u8; 32]),
    /// The height is in the canonical range
    /// (`[1, best_header_height]`) but not locally indexed
    /// (sparse-prefix gap, in `HeaderAvailability::PoPowSparse` mode
    /// only). Callers must NOT treat this as fraud.
    SparseGap,
    /// The height exceeds `best_header_height`. Out of range for the
    /// current view of the chain.
    AboveTip,
}

// ---- Chain state metadata ----

/// Persistent chain state: best-header and best-full-block pointers
/// plus the [`HeaderAvailability`] mode tag.
///
/// Stored in `chain_state_meta` table under key "chain_state".
/// Updated atomically with header acceptance, block application, or
/// NiPoPoW proof apply (sub-phase 14.5). Wire format is suffixed by
/// the header-availability discriminator so legacy records (without
/// the trailing tag) decode as `HeaderAvailability::Dense`.
#[derive(Debug, Clone)]
pub struct ChainStateMeta {
    /// Identifier of the best-known header (highest cumulative score).
    pub best_header_id: [u8; 32],
    /// Height of `best_header_id`.
    pub best_header_height: u32,
    /// Cumulative difficulty score at `best_header_id`, big-endian bytes.
    pub best_header_score: Vec<u8>,
    /// Identifier of the best fully-applied block (header + body validated).
    pub best_full_block_id: [u8; 32],
    /// Height of `best_full_block_id`.
    pub best_full_block_height: u32,
    /// Header availability mode (Phase 0 §3). Defaults to
    /// [`HeaderAvailability::Dense`] for back-compat with legacy
    /// stores that predate this field.
    pub header_availability: HeaderAvailability,
}

impl ChainStateMeta {
    /// Encode this chain-state row to the persisted byte form.
    pub fn serialize(&self) -> Vec<u8> {
        let score_len = self.best_header_score.len();
        let avail_bytes = self.header_availability.serialize();
        let mut buf = Vec::with_capacity(32 + 4 + 4 + score_len + 32 + 4 + avail_bytes.len());
        buf.extend_from_slice(&self.best_header_id);
        buf.extend_from_slice(&self.best_header_height.to_be_bytes());
        buf.extend_from_slice(&(score_len as u32).to_be_bytes());
        buf.extend_from_slice(&self.best_header_score);
        buf.extend_from_slice(&self.best_full_block_id);
        buf.extend_from_slice(&self.best_full_block_height.to_be_bytes());
        buf.extend_from_slice(&avail_bytes);
        buf
    }

    /// Decode a persisted chain-state row. Returns
    /// [`ChainStateMetaDecodeError::Truncated`] when any legacy field
    /// is short; gracefully defaults the header-availability
    /// discriminator to `Dense` when absent (legacy records that
    /// predate the field) or when present with an unknown
    /// discriminator (forward-compat — future arms can be added
    /// without breaking older readers).
    ///
    /// Callers wrap the error into [`crate::store::StateError::DbCorruption`]
    /// with `table: "chain_state_meta"` + key context so an operator
    /// sees which persisted row was corrupt, not just a decode failure.
    pub fn deserialize(data: &[u8]) -> Result<Self, ChainStateMetaDecodeError> {
        fn require<'a>(
            data: &'a [u8],
            pos: usize,
            len: usize,
            field: &'static str,
        ) -> Result<&'a [u8], ChainStateMetaDecodeError> {
            data.get(pos..pos + len)
                .ok_or(ChainStateMetaDecodeError::Truncated {
                    field,
                    need: len,
                    pos,
                    total: data.len(),
                })
        }

        let mut pos = 0;
        let mut best_header_id = [0u8; 32];
        best_header_id.copy_from_slice(require(data, pos, 32, "best_header_id")?);
        pos += 32;
        let best_header_height = u32::from_be_bytes(
            require(data, pos, 4, "best_header_height")?
                .try_into()
                .unwrap(),
        );
        pos += 4;
        let score_len =
            u32::from_be_bytes(require(data, pos, 4, "score_len")?.try_into().unwrap()) as usize;
        pos += 4;
        let best_header_score = require(data, pos, score_len, "best_header_score")?.to_vec();
        pos += score_len;
        let mut best_full_block_id = [0u8; 32];
        best_full_block_id.copy_from_slice(require(data, pos, 32, "best_full_block_id")?);
        pos += 32;
        let best_full_block_height = u32::from_be_bytes(
            require(data, pos, 4, "best_full_block_height")?
                .try_into()
                .unwrap(),
        );
        pos += 4;

        let header_availability = if pos < data.len() {
            let disc = data[pos];
            pos += 1;
            match disc {
                HeaderAvailability::DISC_DENSE => HeaderAvailability::Dense,
                HeaderAvailability::DISC_POPOW_SPARSE => {
                    let dense_from_height = u32::from_be_bytes(
                        require(data, pos, 4, "dense_from_height")?
                            .try_into()
                            .unwrap(),
                    );
                    pos += 4;
                    let proof_suffix_height = u32::from_be_bytes(
                        require(data, pos, 4, "proof_suffix_height")?
                            .try_into()
                            .unwrap(),
                    );
                    HeaderAvailability::PoPowSparse {
                        dense_from_height,
                        proof_suffix_height,
                    }
                }
                // Unknown discriminator: default to Dense. Forward-
                // compat: a future arm can be added without breaking
                // older readers via the same legacy-default path.
                _ => HeaderAvailability::Dense,
            }
        } else {
            HeaderAvailability::Dense
        };

        Ok(Self {
            best_header_id,
            best_header_height,
            best_header_score,
            best_full_block_id,
            best_full_block_height,
            header_availability,
        })
    }
}

/// Decode failure for [`ChainStateMeta::deserialize`]. The persisted
/// row was shorter than required at some specific field. Callers
/// route this into `StateError::DbCorruption` with the redb table +
/// key for operator-visible provenance.
#[derive(Debug, Error)]
pub enum ChainStateMetaDecodeError {
    #[error("truncated at field `{field}`: need {need} bytes at offset {pos}, total {total}")]
    Truncated {
        field: &'static str,
        need: usize,
        pos: usize,
        total: usize,
    },
}

// ---- In-memory chain state ----

/// In-memory chain state tracking.
///
/// The gap between `best_header_height` and `best_full_block_height` drives
/// block download during IBD. `session_invalids` tracks non-PoW validation
/// failures (cleared on restart — these might be our bug).
pub struct ChainState {
    /// Best-known header id (mirrors `ChainStateMeta::best_header_id`).
    pub best_header_id: [u8; 32],
    /// Height of `best_header_id`.
    pub best_header_height: u32,
    /// Cumulative difficulty score at `best_header_id`, big-endian bytes.
    pub best_header_score: Vec<u8>,
    /// Best fully-applied block id (mirrors `ChainStateMeta::best_full_block_id`).
    pub best_full_block_id: [u8; 32],
    /// Height of `best_full_block_id`.
    pub best_full_block_height: u32,
    /// Header availability mode (Phase 0 §3). Mirrors
    /// `ChainStateMeta::header_availability`.
    pub header_availability: HeaderAvailability,
    /// Session-only set of header ids that failed non-PoW validation
    /// during the current process lifetime. Cleared on restart since
    /// these failures might be our bug rather than a permanent reject.
    pub session_invalids: HashSet<[u8; 32]>,
}

impl ChainState {
    /// Empty / pre-genesis state. All ids zeroed; score is `[0]`;
    /// mode defaults to `Dense`.
    pub fn empty() -> Self {
        Self {
            best_header_id: [0u8; 32],
            best_header_height: 0,
            best_header_score: vec![0],
            best_full_block_id: [0u8; 32],
            best_full_block_height: 0,
            header_availability: HeaderAvailability::Dense,
            session_invalids: HashSet::new(),
        }
    }

    /// Hydrate from a persisted [`ChainStateMeta`]. `session_invalids`
    /// always starts empty — non-PoW invalidity is not persisted.
    pub fn from_persisted(meta: &ChainStateMeta) -> Self {
        Self {
            best_header_id: meta.best_header_id,
            best_header_height: meta.best_header_height,
            best_header_score: meta.best_header_score.clone(),
            best_full_block_id: meta.best_full_block_id,
            best_full_block_height: meta.best_full_block_height,
            header_availability: meta.header_availability,
            session_invalids: HashSet::new(),
        }
    }

    /// Project to the persisted form. `session_invalids` is dropped
    /// (intentionally not persisted).
    pub fn to_persisted(&self) -> ChainStateMeta {
        ChainStateMeta {
            best_header_id: self.best_header_id,
            best_header_height: self.best_header_height,
            best_header_score: self.best_header_score.clone(),
            best_full_block_id: self.best_full_block_id,
            best_full_block_height: self.best_full_block_height,
            header_availability: self.header_availability,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn meta_with(avail: HeaderAvailability) -> ChainStateMeta {
        ChainStateMeta {
            best_header_id: [0x01; 32],
            best_header_height: 42,
            best_header_score: vec![0xAA, 0xBB, 0xCC],
            best_full_block_id: [0x02; 32],
            best_full_block_height: 7,
            header_availability: avail,
        }
    }

    // ----- round-trips -----

    #[test]
    fn chain_state_meta_dense_roundtrips() {
        let meta = meta_with(HeaderAvailability::Dense);
        let bytes = meta.serialize();
        let parsed = ChainStateMeta::deserialize(&bytes).expect("roundtrip decode");
        assert_eq!(parsed.best_header_id, meta.best_header_id);
        assert_eq!(parsed.best_header_height, meta.best_header_height);
        assert_eq!(parsed.best_header_score, meta.best_header_score);
        assert_eq!(parsed.best_full_block_id, meta.best_full_block_id);
        assert_eq!(parsed.best_full_block_height, meta.best_full_block_height);
        assert_eq!(parsed.header_availability, HeaderAvailability::Dense);
    }

    #[test]
    fn chain_state_meta_popow_sparse_roundtrips() {
        let avail = HeaderAvailability::PoPowSparse {
            dense_from_height: 1_500_000,
            proof_suffix_height: 1_500_009,
        };
        let meta = meta_with(avail);
        let bytes = meta.serialize();
        let parsed = ChainStateMeta::deserialize(&bytes).expect("roundtrip decode");
        assert_eq!(parsed.header_availability, avail);
    }

    // ----- back-compat -----

    #[test]
    fn legacy_record_without_availability_tag_decodes_as_dense() {
        // Synthesize the pre-14.4.5 byte layout (no trailing
        // discriminator) and confirm deserialize defaults to Dense.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x01; 32]); // best_header_id
        bytes.extend_from_slice(&42u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes()); // score_len
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        bytes.extend_from_slice(&[0x02; 32]); // best_full_block_id
        bytes.extend_from_slice(&7u32.to_be_bytes());
        // INTENTIONALLY no header_availability discriminator.

        let parsed = ChainStateMeta::deserialize(&bytes).expect("roundtrip decode");
        assert_eq!(parsed.header_availability, HeaderAvailability::Dense);
        assert_eq!(parsed.best_header_height, 42);
        assert_eq!(parsed.best_full_block_height, 7);
    }

    #[test]
    fn unknown_availability_discriminator_falls_back_to_dense() {
        // Forward-compat: a future arm we don't recognize yet must
        // decode as Dense rather than panic, so a node running an
        // older binary against a newer-format store still boots.
        let mut bytes = meta_with(HeaderAvailability::Dense).serialize();
        let avail_pos = bytes.len() - 1;
        bytes[avail_pos] = 0xFF; // unknown discriminator
        let parsed = ChainStateMeta::deserialize(&bytes).expect("roundtrip decode");
        assert_eq!(parsed.header_availability, HeaderAvailability::Dense);
    }

    // ----- HeaderMeta decode-error paths -----

    fn sample_header_meta() -> HeaderMeta {
        HeaderMeta {
            parent_id: [0x11; 32],
            height: 1234,
            cumulative_score: vec![0xAA, 0xBB, 0xCC, 0xDD],
            pow_validity: 1,
            timestamp: 1_700_000_000_000,
        }
    }

    #[test]
    fn header_meta_round_trips() {
        let meta = sample_header_meta();
        let bytes = meta.serialize();
        let restored = HeaderMeta::deserialize(&bytes).expect("clean round-trip");
        assert_eq!(restored.parent_id, meta.parent_id);
        assert_eq!(restored.height, meta.height);
        assert_eq!(restored.cumulative_score, meta.cumulative_score);
        assert_eq!(restored.pow_validity, meta.pow_validity);
        assert_eq!(restored.timestamp, meta.timestamp);
    }

    #[test]
    fn header_meta_deserialize_truncated_parent_id_errors() {
        let bytes = vec![0u8; 10]; // far short of 32-byte parent_id
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "parent_id");
    }

    #[test]
    fn header_meta_deserialize_truncated_height_errors() {
        let bytes = vec![0u8; 32 + 2]; // parent_id ok, height short by 2
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "height");
    }

    #[test]
    fn header_meta_deserialize_truncated_score_len_errors() {
        let bytes = vec![0u8; 32 + 4 + 2]; // height ok, score_len short by 2
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "score_len");
    }

    #[test]
    fn header_meta_deserialize_truncated_cumulative_score_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // parent_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // height
        bytes.extend_from_slice(&8u32.to_be_bytes()); // score_len = 8
        bytes.extend_from_slice(&[0u8; 4]); // only 4 score bytes — short
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "cumulative_score");
    }

    #[test]
    fn header_meta_deserialize_truncated_pow_validity_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // parent_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
                                                      // pow_validity byte missing
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "pow_validity");
    }

    #[test]
    fn header_meta_deserialize_truncated_timestamp_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // parent_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
        bytes.push(1); // pow_validity
        bytes.extend_from_slice(&[0u8; 4]); // 4 of 8 timestamp bytes
        let err = HeaderMeta::deserialize(&bytes).expect_err("must error");
        let HeaderMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "timestamp");
    }

    // ----- ChainStateMeta decode-error paths -----

    #[test]
    fn chain_state_meta_deserialize_truncated_best_header_id_errors() {
        let bytes = vec![0u8; 10]; // far short of 32-byte best_header_id
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "best_header_id");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_best_header_height_errors() {
        let bytes = vec![0u8; 32 + 2]; // best_header_id ok, height short by 2
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "best_header_height");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_score_len_errors() {
        let bytes = vec![0u8; 32 + 4 + 2]; // height ok, score_len short by 2
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "score_len");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_best_header_score_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // best_header_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_header_height
        bytes.extend_from_slice(&8u32.to_be_bytes()); // score_len = 8
        bytes.extend_from_slice(&[0u8; 4]); // only 4 score bytes — short
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "best_header_score");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_best_full_block_id_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // best_header_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_header_height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
        bytes.extend_from_slice(&[0u8; 16]); // 16 of 32 best_full_block_id bytes
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "best_full_block_id");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_best_full_block_height_errors() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // best_header_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_header_height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
        bytes.extend_from_slice(&[0u8; 32]); // best_full_block_id
        bytes.extend_from_slice(&[0u8; 2]); // 2 of 4 best_full_block_height bytes
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "best_full_block_height");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_popow_sparse_dense_from_errors() {
        // PoPowSparse discriminator present but `dense_from_height`
        // payload short — this path is stricter than the pre-typed
        // codec, which would have panicked on the trailing `try_into().unwrap()`.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // best_header_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_header_height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
        bytes.extend_from_slice(&[0u8; 32]); // best_full_block_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_full_block_height
        bytes.push(HeaderAvailability::DISC_POPOW_SPARSE); // discriminator
        bytes.extend_from_slice(&[0u8; 2]); // 2 of 4 dense_from_height bytes
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "dense_from_height");
    }

    #[test]
    fn chain_state_meta_deserialize_truncated_popow_sparse_proof_suffix_errors() {
        // PoPowSparse discriminator + dense_from_height present but
        // `proof_suffix_height` payload short.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0u8; 32]); // best_header_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_header_height
        bytes.extend_from_slice(&0u32.to_be_bytes()); // score_len = 0
        bytes.extend_from_slice(&[0u8; 32]); // best_full_block_id
        bytes.extend_from_slice(&0u32.to_be_bytes()); // best_full_block_height
        bytes.push(HeaderAvailability::DISC_POPOW_SPARSE); // discriminator
        bytes.extend_from_slice(&0u32.to_be_bytes()); // dense_from_height = 0
        bytes.extend_from_slice(&[0u8; 2]); // 2 of 4 proof_suffix_height bytes
        let err = ChainStateMeta::deserialize(&bytes).expect_err("must error");
        let ChainStateMetaDecodeError::Truncated { field, .. } = err;
        assert_eq!(field, "proof_suffix_height");
    }
}

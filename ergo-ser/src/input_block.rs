//! Input-block and ordering-block announcement wire codecs (weak-blocks
//! P2P messages). Scala `InputBlockAnnouncement` / `InputBlockFields` /
//! `OrderingBlockAnnouncement` and their message specs.

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;

use crate::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof,
};
use crate::error::WriteError;
use crate::header::{read_header, serialize_header, write_header, Header};
use crate::transaction::{read_transaction, write_transaction, Transaction};
use crate::weak_id::{WeakId, WEAK_ID_LENGTH};

/// Extension-fields data-prefix byte: `03` selects the input-block key
/// namespace inside a header's extension section.
pub const INPUT_BLOCKS_DATA_PREFIX: u8 = 0x03;
/// Extension key for the current input block's transactions digest.
pub const INPUT_BLOCK_TRANSACTIONS_DIGEST_KEY: [u8; 2] = [0x03, 0x00];
/// Extension key for the previous input block's transactions digest.
pub const PREVIOUS_INPUT_BLOCK_TRANSACTIONS_DIGEST_KEY: [u8; 2] = [0x03, 0x01];
/// Extension key for the previous input block's id.
pub const PREV_INPUT_BLOCK_ID_KEY: [u8; 2] = [0x03, 0x02];
/// The initial `InputBlockAnnouncement` wire version (no trailing
/// unparsed-bytes tail).
pub const INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION: u8 = 1;
/// The current `OrderingBlockAnnouncement` wire version.
pub const ORDERING_BLOCK_ANNOUNCEMENT_CURRENT_VERSION: u8 = 1;
/// Cap on array counts (transactions, ids, extension fields) in an
/// `OrderingBlockAnnouncement` — Scala `MaxArraySize`.
pub const ORDERING_ANNOUNCEMENT_MAX_ARRAY: usize = 32_768;
/// Cap on total parsed bytes for an `OrderingBlockAnnouncement` — Scala
/// checks `position - start < 3_200_000` after each section.
pub const ORDERING_ANNOUNCEMENT_MAX_SIZE: usize = 3_200_000;
/// `Short.MaxValue` — the ceiling Scala's `getUShort().toShortExact`
/// enforces on the batch-merkle-proof length prefix.
const SCALA_SHORT_MAX: u16 = 32_767;

/// The consensus-relevant fields of an input block beyond its header:
/// the previous input block link, the transactions digest, the previous
/// input block's transactions digest, and the batch-merkle proof binding
/// them into the header's extension root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlockFields {
    pub prev_input_block_id: Option<[u8; 32]>,
    pub transactions_digest: [u8; 32],
    pub prev_transactions_digest: [u8; 32],
    pub proof: BatchMerkleProof,
}

impl InputBlockFields {
    /// Scala `InputBlockFields.toExtensionFields`: `[(03 02, prev)?, (03 00,
    /// digest), (03 01, prevDigest)]` in that order — the `prev` entry is
    /// present only when `prev_input_block_id` is `Some`.
    pub fn extension_fields(&self) -> Vec<([u8; 2], Vec<u8>)> {
        let mut out = Vec::with_capacity(3);
        if let Some(prev) = self.prev_input_block_id {
            out.push((PREV_INPUT_BLOCK_ID_KEY, prev.to_vec()));
        }
        out.push((
            INPUT_BLOCK_TRANSACTIONS_DIGEST_KEY,
            self.transactions_digest.to_vec(),
        ));
        out.push((
            PREVIOUS_INPUT_BLOCK_TRANSACTIONS_DIGEST_KEY,
            self.prev_transactions_digest.to_vec(),
        ));
        out
    }
}

/// A P2P input-block announcement: a header plus the input-block fields
/// (restated for cheap validation without recomputing the extension
/// merkle root) plus, optionally, the weak transaction ids the block
/// commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlockAnnouncement {
    pub version: u8,
    pub header: Header,
    pub fields: InputBlockFields,
    pub weak_tx_ids: Option<Vec<WeakId>>,
    pub unparsed_bytes: Vec<u8>,
}

impl InputBlockAnnouncement {
    /// The input block's id — its header id.
    pub fn id(&self) -> Result<ModifierId, WriteError> {
        serialize_header(&self.header).map(|(_, id)| id)
    }
}

/// Serialize an [`InputBlockAnnouncement`] to `w`.
pub fn write_input_block_announcement(
    w: &mut VlqWriter,
    a: &InputBlockAnnouncement,
) -> Result<(), WriteError> {
    w.put_u8(a.version);
    write_header(w, &a.header)?;
    match a.fields.prev_input_block_id {
        Some(id) => {
            w.put_u8(1);
            w.put_bytes(&id);
        }
        None => w.put_u8(0),
    }
    w.put_bytes(&a.fields.transactions_digest);
    w.put_bytes(&a.fields.prev_transactions_digest);
    let proof = serialize_batch_merkle_proof(&a.fields.proof);
    let len = u16::try_from(proof.len())
        .ok()
        .filter(|l| *l <= SCALA_SHORT_MAX)
        .ok_or_else(|| {
            WriteError::InvalidData(format!(
                "input block proof length {} > {SCALA_SHORT_MAX}",
                proof.len()
            ))
        })?;
    w.put_u16(len);
    w.put_bytes(&proof);
    match &a.weak_tx_ids {
        Some(ids) => {
            w.put_u8(1);
            w.put_u32(
                u32::try_from(ids.len())
                    .map_err(|_| WriteError::InvalidData("too many weak ids".into()))?,
            );
            for id in ids {
                w.put_bytes(id);
            }
        }
        None => w.put_u8(0),
    }
    if a.version > INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION {
        let n = u8::try_from(a.unparsed_bytes.len())
            .map_err(|_| WriteError::InvalidData("unparsed bytes > 255".into()))?;
        w.put_u8(n);
        w.put_bytes(&a.unparsed_bytes);
    }
    Ok(())
}

fn read_option_id(r: &mut VlqReader) -> Result<Option<[u8; 32]>, ReadError> {
    match r.get_u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.get_array::<32>()?)),
        other => Err(ReadError::InvalidData(format!("option tag {other}"))),
    }
}

/// Deserialize an [`InputBlockAnnouncement`] from `r`.
pub fn read_input_block_announcement(
    r: &mut VlqReader,
) -> Result<InputBlockAnnouncement, ReadError> {
    let version = r.get_u8()?;
    let header = read_header(r)?;
    let prev_input_block_id = read_option_id(r)?;
    let transactions_digest = r.get_array::<32>()?;
    let prev_transactions_digest = r.get_array::<32>()?;
    let proof_len = r.get_u16()?;
    if proof_len > SCALA_SHORT_MAX {
        return Err(ReadError::InvalidData(format!(
            "proof length {proof_len} > Short.MaxValue"
        )));
    }
    let proof_bytes = r.get_bytes(proof_len as usize)?;
    let proof = deserialize_batch_merkle_proof(proof_bytes)?;
    let weak_tx_ids = match r.get_u8()? {
        0 => None,
        1 => {
            let count = r.get_u32_exact()? as usize;
            let mut ids = Vec::with_capacity(count.min(r.remaining() / WEAK_ID_LENGTH + 1));
            for _ in 0..count {
                ids.push(r.get_array::<WEAK_ID_LENGTH>()?);
            }
            Some(ids)
        }
        other => return Err(ReadError::InvalidData(format!("option tag {other}"))),
    };
    let unparsed_bytes = if version > INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION {
        let n = r.get_u8()? as usize;
        r.get_bytes(n)?.to_vec()
    } else {
        Vec::new()
    };
    Ok(InputBlockAnnouncement {
        version,
        header,
        fields: InputBlockFields {
            prev_input_block_id,
            transactions_digest,
            prev_transactions_digest,
            proof,
        },
        weak_tx_ids,
        unparsed_bytes,
    })
}

/// Serialize a fresh [`InputBlockAnnouncement`] to a standalone byte vector.
pub fn serialize_input_block_announcement(
    a: &InputBlockAnnouncement,
) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_input_block_announcement(&mut w, a)?;
    Ok(w.result())
}

/// Parse a standalone [`InputBlockAnnouncement`], rejecting trailing bytes.
pub fn parse_input_block_announcement(bytes: &[u8]) -> Result<InputBlockAnnouncement, ReadError> {
    let mut r = VlqReader::new(bytes);
    let a = read_input_block_announcement(&mut r)?;
    if r.remaining() != 0 {
        return Err(ReadError::InvalidData(format!(
            "{} trailing bytes",
            r.remaining()
        )));
    }
    Ok(a)
}

/// A P2P ordering-block announcement: the ordering block's header, the
/// transactions it carries that the peer may not already have, ids of
/// the ones it may already have (broadcast separately), and the
/// extension fields restated for validation.
///
/// Not `Eq`: [`Transaction`] embeds `ErgoBoxCandidate`, whose value type is
/// `PartialEq`-only.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderingBlockAnnouncement {
    pub version: u8,
    pub header: Header,
    pub non_broadcasted_transactions: Vec<Transaction>,
    pub broadcasted_transaction_ids: Vec<[u8; 32]>,
    pub extension_fields: Vec<([u8; 2], Vec<u8>)>,
    pub unparsed_bytes: Vec<u8>,
}

/// Serialize an [`OrderingBlockAnnouncement`] to `w`.
pub fn write_ordering_block_announcement(
    w: &mut VlqWriter,
    a: &OrderingBlockAnnouncement,
) -> Result<(), WriteError> {
    w.put_u8(a.version);
    write_header(w, &a.header)?;
    w.put_u32(a.non_broadcasted_transactions.len() as u32);
    for tx in &a.non_broadcasted_transactions {
        write_transaction(w, tx)?;
    }
    w.put_u32(a.broadcasted_transaction_ids.len() as u32);
    for id in &a.broadcasted_transaction_ids {
        w.put_bytes(id);
    }
    w.put_u16(
        u16::try_from(a.extension_fields.len())
            .map_err(|_| WriteError::InvalidData("too many extension fields".into()))?,
    );
    for (key, value) in &a.extension_fields {
        w.put_bytes(key);
        w.put_u8(
            u8::try_from(value.len())
                .map_err(|_| WriteError::InvalidData("extension value > 255".into()))?,
        );
        w.put_bytes(value);
    }
    w.put_u8(
        u8::try_from(a.unparsed_bytes.len())
            .map_err(|_| WriteError::InvalidData("unparsed > 255".into()))?,
    );
    w.put_bytes(&a.unparsed_bytes);
    Ok(())
}

fn check_size(r: &VlqReader, start: usize) -> Result<(), ReadError> {
    if r.position() - start >= ORDERING_ANNOUNCEMENT_MAX_SIZE {
        return Err(ReadError::InvalidData(
            "ordering announcement exceeds 3200000 bytes".into(),
        ));
    }
    Ok(())
}

/// Deserialize an [`OrderingBlockAnnouncement`] from `r`.
pub fn read_ordering_block_announcement(
    r: &mut VlqReader,
) -> Result<OrderingBlockAnnouncement, ReadError> {
    let start = r.position();
    let version = r.get_u8()?;
    let header = read_header(r)?;
    let nbt = r.get_u32_exact()? as usize;
    if nbt > ORDERING_ANNOUNCEMENT_MAX_ARRAY {
        return Err(ReadError::InvalidData(format!(
            "non-broadcasted count {nbt} > {ORDERING_ANNOUNCEMENT_MAX_ARRAY}"
        )));
    }
    let mut non_broadcasted_transactions = Vec::with_capacity(nbt.min(1024));
    for _ in 0..nbt {
        non_broadcasted_transactions.push(read_transaction(r)?);
    }
    check_size(r, start)?;
    let nids = r.get_u32_exact()? as usize;
    if nids > ORDERING_ANNOUNCEMENT_MAX_ARRAY {
        return Err(ReadError::InvalidData(format!(
            "tx id count {nids} > {ORDERING_ANNOUNCEMENT_MAX_ARRAY}"
        )));
    }
    let mut broadcasted_transaction_ids = Vec::with_capacity(nids.min(1024));
    for _ in 0..nids {
        broadcasted_transaction_ids.push(r.get_array::<32>()?);
    }
    check_size(r, start)?;
    let nf = r.get_u16()? as usize;
    if nf > ORDERING_ANNOUNCEMENT_MAX_ARRAY {
        return Err(ReadError::InvalidData(format!(
            "field count {nf} > {ORDERING_ANNOUNCEMENT_MAX_ARRAY}"
        )));
    }
    let mut extension_fields = Vec::with_capacity(nf.min(1024));
    for _ in 0..nf {
        let key = r.get_array::<2>()?;
        let len = r.get_u8()? as usize;
        extension_fields.push((key, r.get_bytes(len)?.to_vec()));
    }
    check_size(r, start)?;
    let n = r.get_u8()? as usize;
    let unparsed_bytes = r.get_bytes(n)?.to_vec();
    check_size(r, start)?;
    Ok(OrderingBlockAnnouncement {
        version,
        header,
        non_broadcasted_transactions,
        broadcasted_transaction_ids,
        extension_fields,
        unparsed_bytes,
    })
}

/// Serialize a fresh [`OrderingBlockAnnouncement`] to a standalone byte vector.
pub fn serialize_ordering_block_announcement(
    a: &OrderingBlockAnnouncement,
) -> Result<Vec<u8>, WriteError> {
    let mut w = VlqWriter::new();
    write_ordering_block_announcement(&mut w, a)?;
    Ok(w.result())
}

/// Parse a standalone [`OrderingBlockAnnouncement`].
pub fn parse_ordering_block_announcement(
    bytes: &[u8],
) -> Result<OrderingBlockAnnouncement, ReadError> {
    let mut r = VlqReader::new(bytes);
    let a = read_ordering_block_announcement(&mut r)?;
    if r.remaining() != 0 {
        return Err(ReadError::InvalidData(format!(
            "{} trailing bytes",
            r.remaining()
        )));
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autolykos::AutolykosSolution;
    use crate::batch_merkle_proof::{ProofEntry, Side};
    use ergo_primitives::digest::{ADDigest, Digest32};
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    /// Minimal header sufficient to exercise the announcement codecs; not
    /// oracle-vectored (the integration test covers Scala parity).
    fn sample_header() -> Header {
        Header {
            version: 2,
            parent_id: ModifierId::from_bytes([0x11; 32]),
            ad_proofs_root: Digest32::from_bytes([0x22; 32]),
            transactions_root: Digest32::from_bytes([0x44; 32]),
            state_root: ADDigest::from_bytes([0x33; 33]),
            timestamp: 1_000_000_000,
            extension_root: Digest32::from_bytes([0x55; 32]),
            n_bits: 0x0200_E800,
            height: 47_262,
            votes: [0, 0, 0],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            },
        }
    }

    fn sample_fields() -> InputBlockFields {
        InputBlockFields {
            prev_input_block_id: None,
            transactions_digest: [0x77; 32],
            prev_transactions_digest: [0x00; 32],
            proof: BatchMerkleProof {
                indices: vec![(0, [0xAB; 32])],
                proofs: vec![ProofEntry {
                    digest: Some([0xCD; 32]),
                    side: Side::Left,
                }],
            },
        }
    }

    // ----- round-trips -----

    #[test]
    fn input_block_announcement_round_trips() {
        let ann = InputBlockAnnouncement {
            version: INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION,
            header: sample_header(),
            fields: sample_fields(),
            weak_tx_ids: Some(vec![[0x01; 6], [0x02; 6]]),
            unparsed_bytes: Vec::new(),
        };
        let bytes = serialize_input_block_announcement(&ann).unwrap();
        let parsed = parse_input_block_announcement(&bytes).unwrap();
        assert_eq!(parsed, ann);
    }

    // ----- error paths -----

    #[test]
    fn proof_length_above_short_max_rejected() {
        let mut w = VlqWriter::new();
        w.put_u8(INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION);
        write_header(&mut w, &sample_header()).unwrap();
        w.put_u8(0); // no prev
        w.put_bytes(&[0x77; 32]);
        w.put_bytes(&[0x00; 32]);
        w.put_u16(32_768); // > Short.MaxValue, written directly (VLQ, not raw BE)
        let bytes = w.result();
        assert!(parse_input_block_announcement(&bytes).is_err());
    }

    #[test]
    fn option_tag_2_rejected() {
        let mut w = VlqWriter::new();
        w.put_u8(INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION);
        write_header(&mut w, &sample_header()).unwrap();
        w.put_u8(2); // invalid option tag
        let bytes = w.result();
        assert!(parse_input_block_announcement(&bytes).is_err());
    }

    #[test]
    fn trailing_byte_rejected() {
        let ann = InputBlockAnnouncement {
            version: INPUT_BLOCK_ANNOUNCEMENT_INITIAL_VERSION,
            header: sample_header(),
            fields: sample_fields(),
            weak_tx_ids: None,
            unparsed_bytes: Vec::new(),
        };
        let mut bytes = serialize_input_block_announcement(&ann).unwrap();
        bytes.push(0xFF);
        assert!(parse_input_block_announcement(&bytes).is_err());
    }

    #[test]
    fn ordering_nbt_count_over_cap_rejected() {
        let mut w = VlqWriter::new();
        w.put_u8(ORDERING_BLOCK_ANNOUNCEMENT_CURRENT_VERSION);
        write_header(&mut w, &sample_header()).unwrap();
        w.put_u32(ORDERING_ANNOUNCEMENT_MAX_ARRAY as u32 + 1);
        let bytes = w.result();
        assert!(parse_ordering_block_announcement(&bytes).is_err());
    }
}

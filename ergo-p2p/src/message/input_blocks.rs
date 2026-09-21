//! Sub-block (input block) messages, protocol version 6.5.0 (Scala
//! `MessageSpecInputBlocks` family: `InputBlockMessageSpec`,
//! `InputBlockTransactionsMessageSpec`, `RequestInputBlockTransactionsMessageSpec`,
//! `OrderingBlockAnnouncementMessageSpec`).

use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::input_block::{
    parse_input_block_announcement, parse_ordering_block_announcement,
    serialize_input_block_announcement, serialize_ordering_block_announcement,
    InputBlockAnnouncement, OrderingBlockAnnouncement,
};
use ergo_ser::transaction::{read_transaction, write_transaction, Transaction};
use ergo_ser::weak_id::{WeakId, WEAK_ID_LENGTH};

use super::MessageError;

pub const CODE_INPUT_BLOCK: u8 = 100;
pub const CODE_INPUT_BLOCK_TX_IDS: u8 = 102;
pub const CODE_INPUT_BLOCK_TXS: u8 = 104;
pub const CODE_INPUT_BLOCK_TXS_REQUEST: u8 = 105;
pub const CODE_ORDERING_BLOCK_ANNOUNCEMENT: u8 = 106;
/// Scala `InputBlockMessageSpec.MaxMessageSize`: `require(r.remaining < 16384)`.
pub const INPUT_BLOCK_MESSAGE_MAX_SIZE: usize = 16_384;

/// Payload of `InputBlockTransactionIds` (code 102) — the input block id
/// plus the weak transaction ids it commits to that a peer may not yet
/// have seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlockTxIds {
    pub input_block_id: [u8; 32],
    pub weak_ids: Vec<WeakId>,
}

/// Payload of `InputBlockTransactions` (code 104) — the input block id
/// plus the full transactions requested by a peer.
#[derive(Debug, Clone, PartialEq)]
pub struct InputBlockTxs {
    pub input_block_id: [u8; 32],
    pub transactions: Vec<Transaction>,
}

/// Payload of `RequestInputBlockTransactions` (code 105) — the input
/// block id plus the weak ids of the transactions being requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBlockTxsRequest {
    pub input_block_id: [u8; 32],
    pub weak_ids: Vec<WeakId>,
}

// ---- InputBlock announcement (code 100) ----

pub fn serialize_input_block(a: &InputBlockAnnouncement) -> Result<Vec<u8>, MessageError> {
    serialize_input_block_announcement(a).map_err(|e| MessageError::Read(e.into()))
}

pub fn deserialize_input_block(payload: &[u8]) -> Result<InputBlockAnnouncement, MessageError> {
    if payload.len() >= INPUT_BLOCK_MESSAGE_MAX_SIZE {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    Ok(parse_input_block_announcement(payload)?)
}

// ---- shared weak-id list codec (codes 102 / 105) ----

fn write_weak_ids(w: &mut VlqWriter, id: &[u8; 32], ids: &[WeakId]) {
    w.put_bytes(id);
    w.put_u32(ids.len() as u32);
    for wid in ids {
        w.put_bytes(wid);
    }
}

fn read_weak_ids(
    r: &mut VlqReader,
    kind: &'static str,
) -> Result<([u8; 32], Vec<WeakId>), MessageError> {
    let id = r.get_array::<32>()?;
    let count = r.get_u32_exact()? as usize;
    // Scala: every weak id takes exactly 6 bytes, so a bigger count cannot
    // be fulfilled — reject before allocating.
    if count.saturating_mul(WEAK_ID_LENGTH) > r.remaining() {
        return Err(MessageError::PayloadTooShort {
            kind,
            got: r.remaining(),
            min: count * WEAK_ID_LENGTH,
        });
    }
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(r.get_array::<WEAK_ID_LENGTH>()?);
    }
    Ok((id, ids))
}

// ---- InputBlockTransactionIds (code 102) ----

pub fn serialize_input_block_tx_ids(d: &InputBlockTxIds) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_weak_ids(&mut w, &d.input_block_id, &d.weak_ids);
    w.result()
}

pub fn deserialize_input_block_tx_ids(payload: &[u8]) -> Result<InputBlockTxIds, MessageError> {
    let mut r = VlqReader::new(payload);
    let (input_block_id, weak_ids) = read_weak_ids(&mut r, "InputBlockTxIds")?;
    Ok(InputBlockTxIds {
        input_block_id,
        weak_ids,
    })
}

// ---- RequestInputBlockTransactions (code 105) ----

pub fn serialize_input_block_txs_request(d: &InputBlockTxsRequest) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_weak_ids(&mut w, &d.input_block_id, &d.weak_ids);
    w.result()
}

pub fn deserialize_input_block_txs_request(
    payload: &[u8],
) -> Result<InputBlockTxsRequest, MessageError> {
    let mut r = VlqReader::new(payload);
    let (input_block_id, weak_ids) = read_weak_ids(&mut r, "InputBlockTxsRequest")?;
    Ok(InputBlockTxsRequest {
        input_block_id,
        weak_ids,
    })
}

// ---- InputBlockTransactions (code 104) ----

pub fn serialize_input_block_txs(d: &InputBlockTxs) -> Result<Vec<u8>, MessageError> {
    let mut w = VlqWriter::new();
    w.put_bytes(&d.input_block_id);
    w.put_u32(d.transactions.len() as u32);
    for tx in &d.transactions {
        write_transaction(&mut w, tx).map_err(|e| MessageError::Read(e.into()))?;
    }
    Ok(w.result())
}

pub fn deserialize_input_block_txs(payload: &[u8]) -> Result<InputBlockTxs, MessageError> {
    let mut r = VlqReader::new(payload);
    let input_block_id = r.get_array::<32>()?;
    let count = r.get_u32_exact()? as usize;
    // Scala: every serialized transaction takes at least one byte.
    if count > r.remaining() {
        return Err(MessageError::PayloadTooShort {
            kind: "InputBlockTxs",
            got: r.remaining(),
            min: count,
        });
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        transactions.push(read_transaction(&mut r)?);
    }
    Ok(InputBlockTxs {
        input_block_id,
        transactions,
    })
}

// ---- OrderingBlockAnnouncement (code 106) ----

pub fn serialize_ordering_block_announcement_msg(
    a: &OrderingBlockAnnouncement,
) -> Result<Vec<u8>, MessageError> {
    serialize_ordering_block_announcement(a).map_err(|e| MessageError::Read(e.into()))
}

pub fn deserialize_ordering_block_announcement_msg(
    payload: &[u8],
) -> Result<OrderingBlockAnnouncement, MessageError> {
    Ok(parse_ordering_block_announcement(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- helpers -----

    fn sample_id(fill: u8) -> [u8; 32] {
        [fill; 32]
    }

    // ----- round-trips -----

    #[test]
    fn input_block_tx_ids_round_trips() {
        let d = InputBlockTxIds {
            input_block_id: sample_id(0x11),
            weak_ids: vec![[0x01; 6], [0x02; 6]],
        };
        let bytes = serialize_input_block_tx_ids(&d);
        let parsed = deserialize_input_block_tx_ids(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn input_block_txs_request_round_trips() {
        let d = InputBlockTxsRequest {
            input_block_id: sample_id(0x22),
            weak_ids: vec![[0x03; 6]],
        };
        let bytes = serialize_input_block_txs_request(&d);
        let parsed = deserialize_input_block_txs_request(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    #[test]
    fn input_block_txs_empty_round_trips() {
        let d = InputBlockTxs {
            input_block_id: sample_id(0x33),
            transactions: Vec::new(),
        };
        let bytes = serialize_input_block_txs(&d).unwrap();
        let parsed = deserialize_input_block_txs(&bytes).unwrap();
        assert_eq!(parsed, d);
    }

    // ----- error paths -----

    #[test]
    fn tx_ids_count_exceeds_remaining_rejected() {
        let mut w = VlqWriter::new();
        w.put_bytes(&sample_id(0x44));
        w.put_u32(1000); // claims 1000 weak ids (6000 bytes) but supplies none
        let bytes = w.result();
        assert!(deserialize_input_block_tx_ids(&bytes).is_err());
    }

    #[test]
    fn input_block_payload_at_max_size_rejected() {
        let payload = vec![0u8; INPUT_BLOCK_MESSAGE_MAX_SIZE];
        let err = deserialize_input_block(&payload).unwrap_err();
        assert!(matches!(
            err,
            MessageError::PayloadTooLarge(INPUT_BLOCK_MESSAGE_MAX_SIZE)
        ));
    }
}

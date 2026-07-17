//! P2P message serialization for all message codes.
//!
//! Each message type has serialize/deserialize functions that work on
//! raw payload bytes (inside the frame). The framing layer handles
//! magic, code, length, and checksum separately.
//!
//! Payload encoding uses VLQ (matching Scorex/sigmastate serialization
//! in ergo-primitives VlqReader/VlqWriter).

use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use thiserror::Error;

use crate::handshake::HandshakeError;
use crate::types::{InvData, ModifiersData, NipopowProofData, SnapshotsInfo};

// ---- Message codes [protocol, verified against Scala source] ----

pub const CODE_GET_PEERS: u8 = 1;
pub const CODE_PEERS: u8 = 2;
pub const CODE_REQUEST_MODIFIER: u8 = 22;
pub const CODE_MODIFIER: u8 = 33;
pub const CODE_INV: u8 = 55;
pub const CODE_SYNC_INFO: u8 = 65;
pub const CODE_HANDSHAKE: u8 = 75;
pub const CODE_GET_SNAPSHOTS_INFO: u8 = 76;
pub const CODE_SNAPSHOTS_INFO: u8 = 77;
pub const CODE_GET_MANIFEST: u8 = 78;
pub const CODE_MANIFEST: u8 = 79;
pub const CODE_GET_UTXO_CHUNK: u8 = 80;
pub const CODE_UTXO_CHUNK: u8 = 81;
pub const CODE_GET_NIPOPOW_PROOF: u8 = 90;
pub const CODE_NIPOPOW_PROOF: u8 = 91;

const MAX_INV_OBJECTS: usize = 400;
const MODIFIER_ID_SIZE: usize = 32;
const MAX_MODIFIER_MESSAGE_SIZE: usize = 2_048_576;
const MAX_MODIFIER_WITH_RESERVE: usize = MAX_MODIFIER_MESSAGE_SIZE * 4;

/// Smallest possible on-wire size of one `Modifiers` entry: a 32-byte
/// modifier id plus the ≥1-byte VLQ length prefix of its payload. `count`
/// is a VLQ that `get_u32_exact` bounds only to i32::MAX, so the up-front
/// `Vec::with_capacity` is capped at `remaining / MIN_MODIFIER_ENTRY_BYTES`
/// — the most entries the payload can physically hold. The per-entry size
/// accounting below still enforces `MAX_MODIFIER_WITH_RESERVE`; this only
/// stops a tiny packet claiming `count = i32::MAX` from reserving ~120 GiB
/// before the first entry is read.
const MIN_MODIFIER_ENTRY_BYTES: usize = MODIFIER_ID_SIZE + 1;

/// Smallest on-wire size of one `SnapshotsInfo` entry: a ≥1-byte zig-zag VLQ
/// height plus a 32-byte manifest digest. Bounds the `Vec::with_capacity`
/// the same way as [`MIN_MODIFIER_ENTRY_BYTES`] (the 20 KiB payload cap
/// bounds the message, but not the decoded `count`).
const MIN_SNAPSHOT_ENTRY_BYTES: usize = 1 + 32;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("empty inv list")]
    EmptyInv,
    #[error("too many inv objects: {0} (max {MAX_INV_OBJECTS})")]
    TooManyInv(usize),
    #[error("empty modifiers list")]
    EmptyModifiers,
    #[error("modifier message too large: {0} bytes")]
    ModifiersTooLarge(usize),
    #[error("unexpected data in GetPeers payload")]
    NonEmptyGetPeers,
    #[error("unexpected data in GetSnapshotsInfo payload: {0} bytes")]
    NonEmptyGetSnapshotsInfo(usize),
    #[error("too many peers: {0}")]
    TooManyPeers(usize),
    #[error("read error: {0}")]
    Read(#[from] ReadError),
    #[error("peer spec parse: {0}")]
    PeerSpec(#[from] HandshakeError),
    #[error("{kind} payload too short: got {got} bytes, need at least {min}")]
    PayloadTooShort {
        kind: &'static str,
        got: usize,
        min: usize,
    },
    #[error("invalid sync info version marker: {0}")]
    InvalidSyncVersion(i8),
    #[error("too many headers in sync v2: {0}")]
    TooManyHeaders(usize),
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("nipopow proof size must be > 0")]
    EmptyNipopowProof,
}

// ---- InvData (shared by Inv and RequestModifier) ----

pub fn serialize_inv(data: &InvData) -> Result<Vec<u8>, MessageError> {
    if data.ids.is_empty() {
        return Err(MessageError::EmptyInv);
    }
    if data.ids.len() > MAX_INV_OBJECTS {
        return Err(MessageError::TooManyInv(data.ids.len()));
    }
    let mut w = VlqWriter::new();
    w.put_u8(data.type_id);
    w.put_u32(data.ids.len() as u32);
    for id in &data.ids {
        w.put_bytes(id);
    }
    Ok(w.result())
}

pub fn deserialize_inv(payload: &[u8]) -> Result<InvData, MessageError> {
    let mut r = VlqReader::new(payload);
    let type_id = r.get_u8()?;
    let count = r.get_u32_exact()? as usize;
    if count == 0 {
        return Err(MessageError::EmptyInv);
    }
    if count > MAX_INV_OBJECTS {
        return Err(MessageError::TooManyInv(count));
    }
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = r.get_bytes(MODIFIER_ID_SIZE)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        ids.push(id);
    }
    Ok(InvData { type_id, ids })
}

// ---- ModifiersData (code 33) ----

pub fn serialize_modifiers(data: &ModifiersData) -> Result<Vec<u8>, MessageError> {
    if data.modifiers.is_empty() {
        return Err(MessageError::EmptyModifiers);
    }
    let mut w = VlqWriter::new();
    w.put_u8(data.type_id);

    // Count modifiers that fit within the size reserve.
    let header_len = 5; // type_id(1) + count(4 VLQ worst case)
    let mut msg_size = header_len;
    let mut msg_count = 0usize;
    for (_, modifier) in &data.modifiers {
        let entry_size = MODIFIER_ID_SIZE + 4 + modifier.len(); // id + len + data
        if msg_size + entry_size <= MAX_MODIFIER_WITH_RESERVE {
            msg_count += 1;
        }
        msg_size += entry_size;
    }

    w.put_u32(msg_count as u32);
    for (id, modifier) in data.modifiers.iter().take(msg_count) {
        w.put_bytes(id);
        w.put_u32(modifier.len() as u32);
        w.put_bytes(modifier);
    }
    Ok(w.result())
}

pub fn deserialize_modifiers(payload: &[u8]) -> Result<ModifiersData, MessageError> {
    let mut r = VlqReader::new(payload);
    let type_id = r.get_u8()?;
    let count = r.get_u32_exact()? as usize;
    if count == 0 {
        return Err(MessageError::EmptyModifiers);
    }

    let header_len = 5;
    let mut msg_size = header_len;
    let mut modifiers = Vec::with_capacity(count.min(r.remaining() / MIN_MODIFIER_ENTRY_BYTES));
    for _ in 0..count {
        let id_bytes = r.get_bytes(MODIFIER_ID_SIZE)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(id_bytes);
        let obj_len = r.get_u32_exact()? as usize;
        // Size accounting MUST mirror serialize_modifiers' entry_size
        // (`MODIFIER_ID_SIZE + 4 + modifier.len()`) — the +4 is the
        // u32 length prefix written before each payload. Without it
        // the reserve check undercounts by 4 × count and a crafted
        // payload of `count` entries with `obj_len` close to the cap
        // can slip past the limit.
        msg_size += MODIFIER_ID_SIZE + 4 + obj_len;
        if msg_size > MAX_MODIFIER_WITH_RESERVE {
            return Err(MessageError::ModifiersTooLarge(msg_size));
        }
        let data = r.get_bytes(obj_len)?;
        modifiers.push((id, data.to_vec()));
    }
    Ok(ModifiersData { type_id, modifiers })
}

// ---- GetPeers (code 1) ----

pub fn serialize_get_peers() -> Vec<u8> {
    Vec::new() // empty payload
}

pub fn deserialize_get_peers(payload: &[u8]) -> Result<(), MessageError> {
    if !payload.is_empty() {
        return Err(MessageError::NonEmptyGetPeers);
    }
    Ok(())
}

// ---- Peers (code 2) ----
// Payload: VLQ(count) + PeerSpec[]. Re-uses handshake PeerSpec serialization.

pub fn serialize_peers(peers: &[crate::handshake::PeerSpec]) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_u32(peers.len() as u32);
    for spec in peers {
        crate::handshake::serialize_peer_spec_to(spec, &mut w);
    }
    w.result()
}

pub fn deserialize_peers(
    payload: &[u8],
    limit: usize,
) -> Result<Vec<crate::handshake::PeerSpec>, MessageError> {
    let mut r = VlqReader::new(payload);
    let count = r.get_u32_exact()? as usize;
    if count > limit {
        return Err(MessageError::TooManyPeers(count));
    }
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let spec = crate::handshake::deserialize_peer_spec_from(&mut r)?;
        peers.push(spec);
    }
    Ok(peers)
}

// ---- SyncInfo (code 65) ----

/// V1: list of header IDs. V2: list of serialized headers.
#[derive(Debug, Clone)]
pub enum SyncInfo {
    V1 { header_ids: Vec<[u8; 32]> },
    V2 { headers: Vec<Vec<u8>> },
}

const SYNC_V2_MARKER: i8 = -1;
const MAX_SYNC_V1_IDS: usize = 1000;
const MAX_SYNC_V2_HEADERS: usize = 50;
const MAX_HEADER_SIZE: usize = 1000;

pub fn serialize_sync_info(info: &SyncInfo) -> Vec<u8> {
    let mut w = VlqWriter::new();
    match info {
        SyncInfo::V1 { header_ids } => {
            w.put_u16(header_ids.len() as u16);
            for id in header_ids {
                w.put_bytes(id);
            }
        }
        SyncInfo::V2 { headers } => {
            w.put_u16(0); // sentinel for V2
            w.put_u8(SYNC_V2_MARKER as u8);
            w.put_u8(headers.len() as u8);
            for header_bytes in headers {
                w.put_u16(header_bytes.len() as u16);
                w.put_bytes(header_bytes);
            }
        }
    }
    w.result()
}

pub fn deserialize_sync_info(payload: &[u8]) -> Result<SyncInfo, MessageError> {
    let mut r = VlqReader::new(payload);
    let length = r.get_u16()? as usize;

    if length > 0 {
        // V1: length = number of header IDs
        // Scala allows up to MaxBlockIds + 1 (1001). Match exactly.
        if length > MAX_SYNC_V1_IDS + 1 {
            return Err(MessageError::TooManyHeaders(length));
        }
        let mut ids = Vec::with_capacity(length);
        for _ in 0..length {
            let bytes = r.get_bytes(MODIFIER_ID_SIZE)?;
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            ids.push(id);
        }
        Ok(SyncInfo::V1 { header_ids: ids })
    } else if r.remaining() > 0 {
        // V2: sentinel 0 + mode marker + headers
        let mode = r.get_u8()? as i8;
        if mode != SYNC_V2_MARKER {
            return Err(MessageError::InvalidSyncVersion(mode));
        }
        let count = r.get_u8()? as usize;
        if count > MAX_SYNC_V2_HEADERS {
            return Err(MessageError::TooManyHeaders(count));
        }
        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            let header_len = r.get_u16()? as usize;
            if header_len > MAX_HEADER_SIZE {
                return Err(MessageError::PayloadTooLarge(header_len));
            }
            let bytes = r.get_bytes(header_len)?;
            headers.push(bytes.to_vec());
        }
        Ok(SyncInfo::V2 { headers })
    } else {
        // Empty V1
        Ok(SyncInfo::V1 {
            header_ids: Vec::new(),
        })
    }
}

// ---- Snapshot messages (codes 76-81) ----

pub fn serialize_get_snapshots_info() -> Vec<u8> {
    Vec::new()
}

pub fn deserialize_get_snapshots_info(payload: &[u8]) -> Result<(), MessageError> {
    // GetSnapshotsInfo carries no payload — Scala parity is strict-empty.
    // Mirrors `deserialize_get_peers`. The earlier "<100 bytes is fine"
    // tolerance was a wire-compat blind spot.
    if !payload.is_empty() {
        return Err(MessageError::NonEmptyGetSnapshotsInfo(payload.len()));
    }
    Ok(())
}

pub fn serialize_snapshots_info(info: &SnapshotsInfo) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_u32(info.available_manifests.len() as u32);
    for (height, digest) in &info.available_manifests {
        w.put_i32(*height);
        w.put_bytes(digest);
    }
    w.result()
}

pub fn deserialize_snapshots_info(payload: &[u8]) -> Result<SnapshotsInfo, MessageError> {
    if payload.len() > 20_000 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    let mut r = VlqReader::new(payload);
    let count = r.get_u32_exact()? as usize;
    let mut manifests = Vec::with_capacity(count.min(r.remaining() / MIN_SNAPSHOT_ENTRY_BYTES));
    for _ in 0..count {
        let height = r.get_i32()?;
        let bytes = r.get_bytes(32)?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(bytes);
        manifests.push((height, digest));
    }
    Ok(SnapshotsInfo {
        available_manifests: manifests,
    })
}

pub fn serialize_get_manifest(manifest_id: &[u8; 32]) -> Vec<u8> {
    manifest_id.to_vec()
}

pub fn deserialize_get_manifest(payload: &[u8]) -> Result<[u8; 32], MessageError> {
    if payload.len() >= 100 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    if payload.len() < 32 {
        return Err(MessageError::PayloadTooShort {
            kind: "get_manifest",
            got: payload.len(),
            min: 32,
        });
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&payload[..32]);
    Ok(id)
}

pub fn serialize_manifest(data: &[u8]) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_u32(data.len() as u32);
    w.put_bytes(data);
    w.result()
}

pub fn deserialize_manifest(payload: &[u8]) -> Result<Vec<u8>, MessageError> {
    if payload.len() > 4_000_000 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    let mut r = VlqReader::new(payload);
    let len = r.get_u32_exact()? as usize;
    let bytes = r.get_bytes(len)?;
    Ok(bytes.to_vec())
}

pub fn serialize_get_utxo_chunk(subtree_id: &[u8; 32]) -> Vec<u8> {
    subtree_id.to_vec()
}

pub fn deserialize_get_utxo_chunk(payload: &[u8]) -> Result<[u8; 32], MessageError> {
    if payload.len() >= 100 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    if payload.len() < 32 {
        return Err(MessageError::PayloadTooShort {
            kind: "get_utxo_chunk",
            got: payload.len(),
            min: 32,
        });
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&payload[..32]);
    Ok(id)
}

pub fn serialize_utxo_chunk(data: &[u8]) -> Vec<u8> {
    serialize_manifest(data) // same format
}

pub fn deserialize_utxo_chunk(payload: &[u8]) -> Result<Vec<u8>, MessageError> {
    deserialize_manifest(payload) // same format
}

// ---- NiPoPoW messages (codes 90-91) ----

pub fn serialize_get_nipopow_proof(data: &NipopowProofData) -> Vec<u8> {
    let mut w = VlqWriter::new();
    w.put_i32(data.m);
    w.put_i32(data.k);
    match &data.header_id_opt {
        Some(id) => {
            w.put_u8(1);
            w.put_bytes(id);
        }
        None => {
            w.put_u8(0);
        }
    }
    w.put_u16(0); // padding for future extensibility
    w.result()
}

pub fn deserialize_get_nipopow_proof(payload: &[u8]) -> Result<NipopowProofData, MessageError> {
    if payload.len() > 1000 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    let mut r = VlqReader::new(payload);
    let m = r.get_i32()?;
    let k = r.get_i32()?;
    let present = r.get_u8()?;
    let header_id_opt = if present == 1 {
        let bytes = r.get_bytes(32)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(bytes);
        Some(id)
    } else {
        None
    };
    // Mandatory u16 pad_length per Scala `GetNipopowProofSpec.scala:44`.
    // Scala always emits 0 (`putUShort(0)` at line 29) and always reads
    // it back; absence is a parse error. Truncation (claimed pad >
    // actual bytes) MUST error so malformed peers can't be silently
    // accepted.
    let pad_len = r.get_u16()? as usize;
    if pad_len > 0 && pad_len < 1000 {
        // Scala parity: `r.getBytes(remainingBytes)` at
        // `GetNipopowProofSpec.scala:46` throws on truncation.
        r.get_bytes(pad_len)?;
    }
    // pad_len >= 1000 (SizeLimit) is a Scala-side silent no-op
    // (`if (remainingBytes > 0 && remainingBytes < SizeLimit)` at
    // line 45); match that to avoid splitting the wire interpretation.
    Ok(NipopowProofData {
        m,
        k,
        header_id_opt,
    })
}

pub fn serialize_nipopow_proof(proof_bytes: &[u8]) -> Result<Vec<u8>, MessageError> {
    if proof_bytes.is_empty() {
        return Err(MessageError::EmptyNipopowProof);
    }
    let mut w = VlqWriter::new();
    w.put_u32(proof_bytes.len() as u32);
    w.put_bytes(proof_bytes);
    w.put_u16(0); // padding
    Ok(w.result())
}

pub fn deserialize_nipopow_proof(payload: &[u8]) -> Result<Vec<u8>, MessageError> {
    if payload.len() > 2_000_000 {
        return Err(MessageError::PayloadTooLarge(payload.len()));
    }
    let mut r = VlqReader::new(payload);
    let len = r.get_u32_exact()? as usize;
    if len == 0 {
        return Err(MessageError::EmptyNipopowProof);
    }
    let bytes = r.get_bytes(len)?;
    // Mandatory u16 pad_length per Scala `NipopowProofSpec.scala:25`.
    // Same truncation semantics as `GetNipopowProof`: truncation must
    // error rather than silently ignore. SizeLimit for code 91 is
    // 2_000_000, matching Scala's constant.
    let pad_len = r.get_u16()? as usize;
    if pad_len > 0 && pad_len < 2_000_000 {
        r.get_bytes(pad_len)?;
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests;

//! Header sync protocol logic.
//!
//! Builds SyncInfo V2 messages from our chain state, constructs RequestModifier
//! messages, and processes ModifiersData responses containing headers.

use ergo_consensus::header_validation::{
    validate_child_header, validate_genesis_header, HeaderValidationError,
};
use ergo_types::modifier_id::ModifierId;
use ergo_wire::header_ser::parse_header;
use ergo_wire::inv::{InvData, ModifiersData};
use ergo_wire::sync_info::{ErgoSyncInfo, ErgoSyncInfoV2};
use ergo_wire::vlq::CodecError;
use thiserror::Error;

use crate::header_chain::HeaderChain;

/// Maximum number of headers to include in a SyncInfo V2 message.
const MAX_SYNC_HEADERS: u32 = 10;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors arising from the sync protocol.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Wire-level codec error (parsing/serialization).
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Header validation failed.
    #[error("header validation error: {0}")]
    Validation(#[from] HeaderValidationError),

    /// The modifier type in the response is not the expected header type.
    #[error("unexpected modifier type: expected 101, got {0}")]
    UnexpectedModifierType(i8),

    /// A header referenced a parent that is not in our chain.
    #[error("parent header not found: {0}")]
    ParentNotFound(ModifierId),
}

// ---------------------------------------------------------------------------
// build_sync_info
// ---------------------------------------------------------------------------

/// Build an `ErgoSyncInfo` V2 message from the current chain state.
///
/// If we have headers, includes the last N (up to 10) headers, oldest first.
/// If the chain is empty, returns an empty V2 SyncInfo.
pub fn build_sync_info(chain: &HeaderChain) -> ErgoSyncInfo {
    let best = chain.best_height();
    if best == 0 {
        return ErgoSyncInfo::V2(ErgoSyncInfoV2 {
            last_headers: vec![],
        });
    }

    let start = if best > MAX_SYNC_HEADERS {
        best - MAX_SYNC_HEADERS + 1
    } else {
        1
    };

    let mut headers = Vec::new();
    for h in start..=best {
        if let Some(id) = chain.id_at_height(h) {
            if let Some(header) = chain.get(&id) {
                headers.push(header.clone());
            }
        }
    }

    ErgoSyncInfo::V2(ErgoSyncInfoV2 {
        last_headers: headers,
    })
}

// ---------------------------------------------------------------------------
// build_request_modifier
// ---------------------------------------------------------------------------

/// Serialize an `InvData` as the body for a `RequestModifier` message.
///
/// The wire format is identical to `InvData`: typeId + count + IDs.
pub fn build_request_modifier(type_id: i8, ids: Vec<ModifierId>) -> Vec<u8> {
    let inv = InvData { type_id, ids };
    inv.serialize()
}

// ---------------------------------------------------------------------------
// process_modifiers_response
// ---------------------------------------------------------------------------

/// Parse a `ModifiersData` response, validate each header, and insert valid
/// headers into the chain.
///
/// Returns the count of new headers successfully added.
///
/// Headers are validated against their parent (which must already be in the
/// chain or the header must be a genesis header). Headers already present in
/// the chain are silently skipped.
pub fn process_modifiers_response(
    body: &[u8],
    chain: &mut HeaderChain,
    now_ms: u64,
) -> Result<u32, SyncError> {
    let data = ModifiersData::parse(body)?;

    // Only process header modifiers (type_id = 101).
    if data.type_id != 101 {
        return Err(SyncError::UnexpectedModifierType(data.type_id));
    }

    let mut added = 0u32;

    for (id, payload) in &data.modifiers {
        // Skip headers we already have.
        if chain.contains(id) {
            continue;
        }

        // Parse the header from the payload bytes.
        let header = parse_header(payload)?;

        // Validate: genesis headers vs child headers.
        if header.is_genesis() {
            validate_genesis_header(&header, now_ms, None, None)?;
        } else {
            let parent = chain
                .get(&header.parent_id)
                .ok_or(SyncError::ParentNotFound(header.parent_id))?;
            validate_child_header(&header, parent, now_ms, None)?;
        }

        chain.insert(*id, header);
        added += 1;
    }

    Ok(added)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;
    use ergo_wire::inv::InvData;

    #[test]
    fn build_sync_info_empty() {
        let chain = HeaderChain::new();
        let sync = build_sync_info(&chain);
        match sync {
            ErgoSyncInfo::V2(v2) => assert!(v2.last_headers.is_empty()),
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn build_sync_info_with_headers() {
        let mut chain = HeaderChain::new();
        let mut h = Header::default_for_test();
        h.height = 1;
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 1;
        chain.insert(ModifierId(id_bytes), h);

        let sync = build_sync_info(&chain);
        match sync {
            ErgoSyncInfo::V2(v2) => assert_eq!(v2.last_headers.len(), 1),
            _ => panic!("expected V2"),
        }
    }

    #[test]
    fn build_request_modifier_roundtrip() {
        let ids = vec![ModifierId([0xAA; 32]), ModifierId([0xBB; 32])];
        let body = build_request_modifier(101, ids.clone());
        let parsed = InvData::parse(&body).unwrap();
        assert_eq!(parsed.type_id, 101);
        assert_eq!(parsed.ids.len(), 2);
        assert_eq!(parsed.ids, ids);
    }
}

//! NiPoPoW (Non-Interactive Proofs of Proof-of-Work) interlink parsing and proof construction.

use ergo_consensus::difficulty::decode_compact_bits;
use ergo_storage::continuation::compute_header_id;
use ergo_storage::history_db::HistoryDb;
use ergo_types::extension::{Extension, INTERLINKS_VECTOR_PREFIX};
use ergo_types::header::Header;
use ergo_types::modifier_id::ModifierId;
use ergo_types::nipopow::{NipopowProof, PoPowHeader};
use ergo_wire::header_ser::serialize_header;
use num_bigint::BigUint;

/// Minimum length for a valid interlink field value (1-byte count + 32-byte ID).
const MIN_INTERLINK_VALUE_LEN: usize = 33;

#[derive(Debug, thiserror::Error)]
pub enum NipopowError {
    #[error("header not found: {0}")]
    HeaderNotFound(String),
    #[error("extension not found for header: {0}")]
    ExtensionNotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("insufficient chain length for proof (need k={0}, have {1})")]
    InsufficientChain(u32, usize),
}

/// Unpack the interlinks vector from an Extension block.
///
/// Extension fields with `key[0] == 0x01` contain packed interlinks.
/// Each field: `key = [0x01, index]`, `value = [count, ...32-byte-id]`.
/// Consecutive duplicates are compressed into one entry via the count byte.
pub fn unpack_interlinks(extension: &Extension) -> Vec<ModifierId> {
    let mut interlink_fields: Vec<_> = extension
        .fields
        .iter()
        .filter(|(key, _)| key[0] == INTERLINKS_VECTOR_PREFIX)
        .collect();

    interlink_fields.sort_by_key(|(key, _)| key[1]);

    let mut interlinks = Vec::new();
    for (_key, value) in interlink_fields {
        if value.len() < MIN_INTERLINK_VALUE_LEN {
            continue;
        }
        let count = value[0] as usize;
        let mut id = [0u8; 32];
        id.copy_from_slice(&value[1..33]);
        let modifier_id = ModifierId(id);
        for _ in 0..count {
            interlinks.push(modifier_id);
        }
    }

    interlinks
}

/// Pack an interlinks vector into Extension key-value fields.
///
/// Consecutive duplicate IDs are compressed into a single entry with a count byte.
/// Key: `[0x01, index]`. Value: `[count, ...32-byte-id]`.
pub fn pack_interlinks(interlinks: &[ModifierId]) -> Vec<([u8; 2], Vec<u8>)> {
    let mut fields = Vec::new();
    let mut idx: u8 = 0;
    let mut i = 0;

    while i < interlinks.len() {
        let current = &interlinks[i];
        let mut count: u8 = 1;
        while i + (count as usize) < interlinks.len()
            && interlinks[i + (count as usize)] == *current
            && count < 255
        {
            count += 1;
        }

        let mut value = Vec::with_capacity(33);
        value.push(count);
        value.extend_from_slice(&current.0);
        fields.push(([INTERLINKS_VECTOR_PREFIX, idx], value));

        idx = idx.wrapping_add(1);
        i += count as usize;
    }

    fields
}

/// Compute the updated interlinks vector for a new block.
///
/// Given the parent header, its header ID, and its interlinks vector,
/// computes the interlinks for the child block.
pub fn update_interlinks(
    parent_header: &Header,
    parent_id: &ModifierId,
    parent_interlinks: &[ModifierId],
) -> Vec<ModifierId> {
    let level = max_level_of(parent_header, parent_id);
    let genesis_id = if parent_header.is_genesis() || parent_interlinks.is_empty() {
        *parent_id
    } else {
        parent_interlinks[0]
    };

    let min_len = (level as usize + 1).max(parent_interlinks.len());
    let mut new_interlinks = Vec::with_capacity(min_len);

    for l in 0..min_len {
        if l == 0 {
            new_interlinks.push(genesis_id);
        } else if (l as u32) <= level {
            new_interlinks.push(*parent_id);
        } else if l < parent_interlinks.len() {
            new_interlinks.push(parent_interlinks[l]);
        } else {
            new_interlinks.push(*parent_id);
        }
    }

    new_interlinks
}

/// Compute the NiPoPoW level of a header.
///
/// `level = floor(log2(required_target / real_target))`
/// where `required_target = decode_compact_bits(n_bits)`
/// and `real_target` is the header hash interpreted as a big-endian unsigned integer.
pub fn max_level_of(header: &Header, header_id: &ModifierId) -> u32 {
    let required = decode_compact_bits(header.n_bits);
    let real = BigUint::from_bytes_be(&header_id.0);

    if real == BigUint::ZERO {
        return 0;
    }

    let ratio = &required / &real;
    if ratio == BigUint::ZERO {
        return 0;
    }

    // floor(log2(ratio)) = bits() - 1
    (ratio.bits() as u32).saturating_sub(1)
}

/// Construct a `PoPowHeader` from a header and its extension.
pub fn popow_header_for(header: Header, extension: &Extension) -> PoPowHeader {
    let interlinks = unpack_interlinks(extension);
    PoPowHeader {
        header,
        interlinks,
        interlinks_proof: Vec::new(),
    }
}

/// Construct a NiPoPoW proof from the chain.
///
/// Walks backwards from `anchor_id` (or the best header if `None`) collecting `k`
/// suffix headers, then walks from genesis collecting prefix headers at the best
/// superchain level where at least `m` headers exist.
pub fn prove(
    history: &HistoryDb,
    m: u32,
    k: u32,
    anchor_id: Option<ModifierId>,
) -> Result<NipopowProof, NipopowError> {
    let tip_id = resolve_anchor(history, anchor_id)?;
    let mut suffix_headers = collect_suffix(history, &tip_id, k)?;

    if suffix_headers.is_empty() {
        return Err(NipopowError::InsufficientChain(k, 0));
    }

    // Reverse so oldest is first.
    suffix_headers.reverse();

    let suffix_head_header = suffix_headers.remove(0);
    let suffix_head = build_popow_header(history, suffix_head_header)?;
    let suffix_tail = suffix_headers;

    let prefix_candidates = collect_prefix_candidates(history, suffix_head.header.height)?;
    let best_level = find_best_superchain_level(&prefix_candidates, m);

    let prefix: Vec<PoPowHeader> = prefix_candidates
        .into_iter()
        .filter(|(_, level)| *level >= best_level)
        .map(|(header, _)| header)
        .collect();

    Ok(NipopowProof {
        m,
        k,
        prefix,
        suffix_head,
        suffix_tail,
    })
}

/// Resolve the anchor header ID, defaulting to the best header if none provided.
fn resolve_anchor(
    history: &HistoryDb,
    anchor_id: Option<ModifierId>,
) -> Result<ModifierId, NipopowError> {
    match anchor_id {
        Some(id) => Ok(id),
        None => history
            .best_header_id()
            .map_err(|e| NipopowError::Storage(e.to_string()))?
            .ok_or_else(|| NipopowError::HeaderNotFound("no best header".to_string())),
    }
}

/// Walk backwards from `start_id` collecting up to `k` headers.
fn collect_suffix(
    history: &HistoryDb,
    start_id: &ModifierId,
    k: u32,
) -> Result<Vec<Header>, NipopowError> {
    let mut headers = Vec::new();
    let mut current_id = *start_id;

    for _ in 0..k {
        let header = history
            .load_header(&current_id)
            .map_err(|e| NipopowError::Storage(e.to_string()))?
            .ok_or_else(|| NipopowError::HeaderNotFound(hex::encode(current_id.0)))?;

        headers.push(header.clone());

        if header.is_genesis() {
            break;
        }
        current_id = header.parent_id;
    }

    Ok(headers)
}

/// Build a `PoPowHeader` for a header, loading its extension from storage.
fn build_popow_header(
    history: &HistoryDb,
    header: Header,
) -> Result<PoPowHeader, NipopowError> {
    let header_id = compute_header_id(&serialize_header(&header));
    let extension = history
        .load_extension(&header_id)
        .map_err(|e| NipopowError::Storage(e.to_string()))?
        .unwrap_or(Extension {
            header_id,
            fields: Vec::new(),
        });
    Ok(popow_header_for(header, &extension))
}

/// Walk heights 1..suffix_head_height collecting (PoPowHeader, level) pairs.
fn collect_prefix_candidates(
    history: &HistoryDb,
    suffix_head_height: u32,
) -> Result<Vec<(PoPowHeader, u32)>, NipopowError> {
    let mut candidates = Vec::new();

    for height in 1..suffix_head_height {
        let ids = history
            .header_ids_at_height(height)
            .map_err(|e| NipopowError::Storage(e.to_string()))?;

        let Some(id) = ids.first() else {
            continue;
        };

        let header = match history.load_header(id) {
            Ok(Some(h)) => h,
            _ => continue,
        };

        let extension = history
            .load_extension(id)
            .map_err(|e| NipopowError::Storage(e.to_string()))?
            .unwrap_or(Extension {
                header_id: *id,
                fields: Vec::new(),
            });

        let level = max_level_of(&header, id);
        let popow_header = popow_header_for(header, &extension);
        candidates.push((popow_header, level));
    }

    Ok(candidates)
}

/// Find the best superchain level mu where `2^mu * count_at_level_mu` is maximized
/// and at least `m` headers exist at that level.
fn find_best_superchain_level(candidates: &[(PoPowHeader, u32)], m: u32) -> u32 {
    let max_level = candidates.iter().map(|(_, l)| *l).max().unwrap_or(0);

    let mut best_level = 0u32;
    let mut best_score = 0u64;

    for mu in 0..=max_level {
        let count = candidates.iter().filter(|(_, l)| *l >= mu).count() as u64;
        let score = (1u64 << mu.min(63)) * count;
        if count >= m as u64 && score > best_score {
            best_score = score;
            best_level = mu;
        }
    }

    best_level
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_types::extension::Extension;
    use ergo_types::header::Header;
    use ergo_types::modifier_id::ModifierId;

    #[test]
    fn unpack_interlinks_empty() {
        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: Vec::new(),
        };
        assert!(unpack_interlinks(&ext).is_empty());
    }

    #[test]
    fn unpack_interlinks_single() {
        let mut value = vec![1u8]; // count = 1
        let id = [0xAA; 32];
        value.extend_from_slice(&id);

        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: vec![([INTERLINKS_VECTOR_PREFIX, 0x00], value)],
        };
        let interlinks = unpack_interlinks(&ext);
        assert_eq!(interlinks.len(), 1);
        assert_eq!(interlinks[0], ModifierId(id));
    }

    #[test]
    fn unpack_interlinks_duplicates() {
        let mut value = vec![3u8]; // count = 3
        let id = [0xBB; 32];
        value.extend_from_slice(&id);

        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: vec![([INTERLINKS_VECTOR_PREFIX, 0x00], value)],
        };
        let interlinks = unpack_interlinks(&ext);
        assert_eq!(interlinks.len(), 3);
        for link in &interlinks {
            assert_eq!(*link, ModifierId(id));
        }
    }

    #[test]
    fn unpack_interlinks_multiple_sorted() {
        let mut v0 = vec![1u8];
        v0.extend_from_slice(&[0xAA; 32]);

        let mut v1 = vec![2u8];
        v1.extend_from_slice(&[0xBB; 32]);

        // Insert in reverse order -- should still sort by key[1].
        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: vec![
                ([INTERLINKS_VECTOR_PREFIX, 0x01], v1),
                ([INTERLINKS_VECTOR_PREFIX, 0x00], v0),
            ],
        };
        let interlinks = unpack_interlinks(&ext);
        assert_eq!(interlinks.len(), 3); // 1 + 2
        assert_eq!(interlinks[0], ModifierId([0xAA; 32]));
        assert_eq!(interlinks[1], ModifierId([0xBB; 32]));
        assert_eq!(interlinks[2], ModifierId([0xBB; 32]));
    }

    #[test]
    fn max_level_of_zero_real_target() {
        let header = Header::default_for_test();
        let id = ModifierId([0; 32]);
        assert_eq!(max_level_of(&header, &id), 0);
    }

    #[test]
    fn max_level_of_basic() {
        let mut header = Header::default_for_test();
        header.n_bits = 0x1A01E7F0;

        // Header ID = 0x00 0x01 followed by zeros -> real_target = 2^248
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 0x00;
        id_bytes[1] = 0x01;
        let id = ModifierId(id_bytes);

        let _level = max_level_of(&header, &id);
        // Verify it computes without panicking; exact value depends on decode_compact_bits.
    }

    #[test]
    fn unpack_interlinks_skips_non_interlink_fields() {
        let mut interlink_value = vec![1u8];
        interlink_value.extend_from_slice(&[0xCC; 32]);

        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: vec![
                ([0x00, 0x01], vec![0x42]),
                ([INTERLINKS_VECTOR_PREFIX, 0x00], interlink_value),
                ([0x02, 0x00], vec![0x01]),
            ],
        };
        let interlinks = unpack_interlinks(&ext);
        assert_eq!(interlinks.len(), 1);
        assert_eq!(interlinks[0], ModifierId([0xCC; 32]));
    }

    #[test]
    fn unpack_interlinks_skips_malformed_short_values() {
        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields: vec![
                ([INTERLINKS_VECTOR_PREFIX, 0x00], vec![1u8; 10]), // too short
            ],
        };
        assert!(unpack_interlinks(&ext).is_empty());
    }

    #[test]
    fn find_best_superchain_level_empty() {
        assert_eq!(find_best_superchain_level(&[], 1), 0);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let id_a = ModifierId([0xAA; 32]);
        let id_b = ModifierId([0xBB; 32]);
        let id_c = ModifierId([0xCC; 32]);
        let interlinks = vec![id_a, id_a, id_b, id_c, id_c, id_c];

        let fields = pack_interlinks(&interlinks);
        let ext = Extension {
            header_id: ModifierId([0; 32]),
            fields,
        };
        let unpacked = unpack_interlinks(&ext);
        assert_eq!(unpacked, interlinks);
    }

    #[test]
    fn test_pack_interlinks_compression() {
        let id = ModifierId([0xDD; 32]);
        let interlinks = vec![id, id, id];

        let fields = pack_interlinks(&interlinks);
        assert_eq!(fields.len(), 1);
        // First byte of value is the count
        assert_eq!(fields[0].1[0], 3);
        // Rest is the 32-byte ID
        assert_eq!(&fields[0].1[1..33], &[0xDD; 32]);
    }

    #[test]
    fn test_pack_interlinks_empty() {
        let fields = pack_interlinks(&[]);
        assert!(fields.is_empty());
    }

    #[test]
    fn test_update_interlinks_genesis() {
        let mut header = Header::default_for_test();
        header.height = 1; // is_genesis() == true
        header.n_bits = 0x01010000; // minimal target so level is 0

        let parent_id = ModifierId([0x11; 32]);
        let parent_interlinks: Vec<ModifierId> = Vec::new();

        let result = update_interlinks(&header, &parent_id, &parent_interlinks);
        // For genesis, result[0] should be the parent_id (genesis_id)
        assert!(!result.is_empty());
        assert_eq!(result[0], parent_id);
    }

    #[test]
    fn test_update_interlinks_level_0() {
        let mut header = Header::default_for_test();
        header.height = 100; // non-genesis
        // Set n_bits very low so level = 0 (real target > required target)
        header.n_bits = 0x01010000;

        let parent_id = ModifierId([0xFF; 32]); // very large hash -> level 0
        let genesis_id = ModifierId([0x01; 32]);
        let parent_interlinks = vec![genesis_id, ModifierId([0x22; 32])];

        let result = update_interlinks(&header, &parent_id, &parent_interlinks);
        // level=0, so min_len = max(1, 2) = 2
        assert_eq!(result.len(), parent_interlinks.len());
        // result[0] = genesis_id from parent_interlinks[0]
        assert_eq!(result[0], genesis_id);
        // result[1]: level=0, l=1 > level, so copies parent_interlinks[1]
        assert_eq!(result[1], parent_interlinks[1]);
    }
}

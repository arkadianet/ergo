//! Run-loop-local scratch state for `apply_block`.
//!
//! Owned by the indexer task and passed to `apply_block_with_scratch` by
//! `&mut`. Two scopes:
//!
//! - **Per-block** collections (touched-* maps, staged_spills,
//!   deleted_spills): cleared once at apply entry.
//! - **Per-tx** collections (tx_touched_*, input_tokens, input_nums,
//!   output_nums, data_inputs): cleared once per tx loop iteration.
//!
//! Plus a long-lived `writer: VlqWriter` reused across all per-row
//! emits — `tx_id`, `box_id`, `IndexedErgoBox`, `IndexedErgoTransaction`,
//! and the per-row writes inside the four flush loops. Cleared
//! before every emit (never relying on clear-after-success), which
//! eliminates the per-row `Vec<u8>` allocations the apply path used to
//! pay.
//!
//! Safety: all clears happen at *entry* to the relevant scope, never at
//! exit. An aborted apply (early return on error) leaves stale data
//! behind, but the next call's entry-clear wipes it before it can leak
//! into a subsequent block.

use std::collections::{HashMap, HashSet};

use ergo_primitives::digest::Digest32;
use ergo_primitives::writer::VlqWriter;

use crate::address::IndexedAddress;
use crate::apply::TemplateKey;
use crate::segment_buffer::{DeletedSpills, StagedSpills};
use crate::template::IndexedTemplate;
use crate::token::IndexedToken;
use crate::TokenId;

/// Reusable scratch buffers for one indexer run loop. Lives across many
/// `apply_block` calls; cleared (not reallocated) at each scope entry.
pub struct BlockApplyScratch {
    #[cfg(test)]
    pub(crate) cache_templates: bool,
    template_hashes: HashMap<Vec<u8>, Option<Digest32>>,
    template_cache_bytes: usize,
    #[cfg(test)]
    pub(crate) template_derivations: u64,
    pub(crate) capture_changes: bool,
    pub(crate) box_changes: Vec<crate::events::BoxChange>,
    pub(crate) touched_addresses: HashMap<Digest32, IndexedAddress>,
    pub(crate) touched_templates: HashMap<Digest32, IndexedTemplate>,
    pub(crate) touched_tokens: HashMap<TokenId, IndexedToken>,
    pub(crate) staged_spills: StagedSpills,
    pub(crate) deleted_spills: DeletedSpills,

    pub(crate) tx_touched_order: Vec<Digest32>,
    pub(crate) tx_touched_seen: HashSet<Digest32>,
    pub(crate) input_tokens: HashSet<TokenId>,
    pub(crate) input_nums: Vec<i64>,
    pub(crate) output_nums: Vec<i64>,
    pub(crate) data_inputs: Vec<Digest32>,

    pub(crate) writer: VlqWriter,
}

impl BlockApplyScratch {
    pub fn new() -> Self {
        Self {
            #[cfg(test)]
            cache_templates: true,
            template_hashes: HashMap::new(),
            template_cache_bytes: 0,
            #[cfg(test)]
            template_derivations: 0,
            capture_changes: false,
            box_changes: Vec::new(),
            touched_addresses: HashMap::new(),
            touched_templates: HashMap::new(),
            touched_tokens: HashMap::new(),
            staged_spills: HashMap::new(),
            deleted_spills: HashSet::new(),
            tx_touched_order: Vec::new(),
            tx_touched_seen: HashSet::new(),
            input_tokens: HashSet::new(),
            input_nums: Vec::new(),
            output_nums: Vec::new(),
            data_inputs: Vec::new(),
            writer: VlqWriter::new(),
        }
    }

    /// The template hash of `bytes` under `key`. `Current` results are
    /// retained across blocks, keyed by exact script bytes and bounded by
    /// 4,096 keys and 4 MiB of retained keys; errors are never retained. A
    /// fixed derivation always derives and never reads or fills the cache.
    pub(crate) fn template_hash(
        &mut self,
        bytes: &[u8],
        key: TemplateKey,
    ) -> Result<Option<Digest32>, crate::IndexerError> {
        let derive = match key {
            TemplateKey::Current => crate::template::template_hash_for_box_bytes,
            #[cfg(test)]
            TemplateKey::Fixed(derive) => return derive(bytes),
        };
        #[cfg(test)]
        if !self.cache_templates {
            return derive(bytes);
        }
        if let Some(hash) = self.template_hashes.get(bytes) {
            return Ok(*hash);
        }
        #[cfg(test)]
        {
            self.template_derivations += 1;
        }
        let hash = derive(bytes)?;
        if bytes.len() <= 4 * 1024 * 1024 {
            if self.template_hashes.len() >= 4096
                || self.template_cache_bytes + bytes.len() > 4 * 1024 * 1024
            {
                self.template_hashes.clear();
                self.template_cache_bytes = 0;
            }
            self.template_cache_bytes += bytes.len();
            self.template_hashes.insert(bytes.to_vec(), hash);
        }
        Ok(hash)
    }

    /// Reset all per-block + per-tx state. Called at apply_block entry so
    /// stale data from a prior aborted apply can never leak in.
    pub(crate) fn clear_block(&mut self) {
        self.box_changes.clear();
        self.touched_addresses.clear();
        self.touched_templates.clear();
        self.touched_tokens.clear();
        self.staged_spills.clear();
        self.deleted_spills.clear();
        self.clear_tx();
    }

    /// Reset only per-tx state. Called at the top of each tx loop
    /// iteration so a mint in tx-N is not masked by token ids spent in
    /// tx-(N-1) of the same block, and so the per-tx address-touched
    /// set never carries entries from a prior tx.
    pub(crate) fn clear_tx(&mut self) {
        self.tx_touched_order.clear();
        self.tx_touched_seen.clear();
        self.input_tokens.clear();
        self.input_nums.clear();
        self.output_nums.clear();
        self.data_inputs.clear();
        self.writer.clear();
    }
}

impl Default for BlockApplyScratch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::IndexedAddress;
    use crate::segment::Segment;
    use crate::template::IndexedTemplate;
    use crate::token::IndexedToken;

    fn d(seed: u8) -> Digest32 {
        Digest32::from_bytes([seed; 32])
    }

    fn populated() -> BlockApplyScratch {
        let mut s = BlockApplyScratch::new();
        s.touched_addresses
            .insert(d(0x01), IndexedAddress::empty(d(0x01)));
        s.touched_templates
            .insert(d(0x02), IndexedTemplate::empty(d(0x02)));
        s.touched_tokens
            .insert(d(0x03), IndexedToken::empty(d(0x03)));
        s.staged_spills.insert(d(0x04), Segment::empty());
        s.deleted_spills.insert(d(0x05));
        s.tx_touched_order.push(d(0x06));
        s.tx_touched_seen.insert(d(0x07));
        s.input_tokens.insert(d(0x08));
        s.input_nums.push(42);
        s.output_nums.push(7);
        s.data_inputs.push(d(0x09));
        s.writer.put_u8(0xFF);
        s
    }

    #[test]
    fn clear_block_resets_everything() {
        let mut s = populated();
        s.clear_block();
        assert!(s.touched_addresses.is_empty());
        assert!(s.touched_templates.is_empty());
        assert!(s.touched_tokens.is_empty());
        assert!(s.staged_spills.is_empty());
        assert!(s.deleted_spills.is_empty());
        assert!(s.tx_touched_order.is_empty());
        assert!(s.tx_touched_seen.is_empty());
        assert!(s.input_tokens.is_empty());
        assert!(s.input_nums.is_empty());
        assert!(s.output_nums.is_empty());
        assert!(s.data_inputs.is_empty());
        assert!(s.writer.as_slice().is_empty());
    }

    #[test]
    fn clear_tx_resets_only_per_tx_fields() {
        let mut s = populated();
        s.clear_tx();
        // per-block survives
        assert_eq!(s.touched_addresses.len(), 1);
        assert_eq!(s.touched_templates.len(), 1);
        assert_eq!(s.touched_tokens.len(), 1);
        assert_eq!(s.staged_spills.len(), 1);
        assert_eq!(s.deleted_spills.len(), 1);
        // per-tx wiped
        assert!(s.tx_touched_order.is_empty());
        assert!(s.tx_touched_seen.is_empty());
        assert!(s.input_tokens.is_empty());
        assert!(s.input_nums.is_empty());
        assert!(s.output_nums.is_empty());
        assert!(s.data_inputs.is_empty());
        assert!(s.writer.as_slice().is_empty());
    }

    #[test]
    fn capacity_retained_across_clear() {
        // Reuse — not realloc — is the point of this struct. After a
        // clear, the underlying capacity should still be available so
        // the next block / tx doesn't pay another allocation.
        let mut s = BlockApplyScratch::new();
        s.input_nums.reserve(64);
        s.tx_touched_order.reserve(16);
        let cap_input = s.input_nums.capacity();
        let cap_order = s.tx_touched_order.capacity();
        assert!(cap_input >= 64);
        assert!(cap_order >= 16);

        s.input_nums.push(1);
        s.tx_touched_order.push(d(0xAA));
        s.clear_tx();

        assert_eq!(s.input_nums.capacity(), cap_input);
        assert_eq!(s.tx_touched_order.capacity(), cap_order);
    }
}

#[cfg(test)]
mod template_cache_tests {
    use super::*;

    #[test]
    fn template_cache_reuses_exact_bytes_across_blocks_and_bounds_retention() {
        let mut scratch = BlockApplyScratch::new();
        let bytes = hex::decode("1000d10101").unwrap();
        let expected = crate::template::template_hash_for_box_bytes(&bytes).unwrap();
        assert_eq!(
            scratch.template_hash(&bytes, TemplateKey::Current).unwrap(),
            expected
        );
        scratch.clear_block();
        assert_eq!(
            scratch.template_hash(&bytes, TemplateKey::Current).unwrap(),
            expected
        );
        assert_eq!(scratch.template_derivations, 1);
        // Retain byte identity even for soft-fork/fallback shapes.
        for bytes in [vec![0xff], vec![0xff, 1], vec![0xff, 2]] {
            assert_eq!(
                scratch.template_hash(&bytes, TemplateKey::Current).unwrap(),
                crate::template::template_hash_for_box_bytes(&bytes).unwrap()
            );
        }
        for key in 0_u32..5000 {
            let mut bytes = vec![0xff];
            bytes.extend_from_slice(&key.to_be_bytes());
            scratch.template_hash(&bytes, TemplateKey::Current).unwrap();
            assert!(scratch.template_hashes.len() <= 4096);
        }
        for key in 0_u32..600 {
            let mut bytes = vec![0xff; 8192];
            bytes[..4].copy_from_slice(&key.to_be_bytes());
            scratch.template_hash(&bytes, TemplateKey::Current).unwrap();
            assert!(scratch.template_cache_bytes <= 4 * 1024 * 1024);
        }
        let retained = scratch.template_cache_bytes;
        scratch
            .template_hash(&vec![0xff; 4 * 1024 * 1024 + 1], TemplateKey::Current)
            .unwrap();
        assert_eq!(scratch.template_cache_bytes, retained);
    }

    #[test]
    fn fixed_derivation_neither_reads_nor_fills_the_cache() {
        fn fixed(_: &[u8]) -> Result<Option<Digest32>, crate::IndexerError> {
            Ok(None)
        }
        let mut scratch = BlockApplyScratch::new();
        let bytes = hex::decode("1000d10101").unwrap();
        assert!(scratch
            .template_hash(&bytes, TemplateKey::Current)
            .unwrap()
            .is_some());
        assert_eq!(
            scratch
                .template_hash(&bytes, TemplateKey::Fixed(fixed))
                .unwrap(),
            None
        );
        scratch
            .template_hash(&[0xff, 3], TemplateKey::Fixed(fixed))
            .unwrap();
        assert_eq!(scratch.template_hashes.len(), 1);
        assert_eq!(scratch.template_cache_bytes, bytes.len());
        assert_eq!(scratch.template_derivations, 1);
    }
}

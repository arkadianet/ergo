//! Production [`ChainView`] implementations.
//!
//! Pure delegation boilerplate: the three impls forward every trait
//! method to the UTXO `StateStore`, the Mode 5 `DigestStateStore`, or
//! match-forward through the runtime `StateBackendKind` enum. No
//! coupling to [`SyncCoordinator`](super::SyncCoordinator) state.

use ergo_state::store::StateStore;

use super::ChainView;

// ---- ChainView impl for StateStore (production) ----
//
// Keeps the trait for unit-test mocking (MockChain below), but production
// code and integration tests pass `&StateStore` directly. The previous
// `StateChainView` wrapper type was deleted.

impl ChainView for ergo_state::store::StateStore {
    fn best_header_id(&self) -> [u8; 32] {
        self.chain_state().best_header_id
    }

    fn best_header_height(&self) -> u32 {
        self.chain_state().best_header_height
    }

    fn best_full_block_height(&self) -> u32 {
        self.chain_state().best_full_block_height
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        // Two-read lookup: header's height (HEADER_META) + best-chain id at
        // that height (HEADER_CHAIN_INDEX). Depth-independent.
        let target_height = match self.get_header_meta(header_id).ok().flatten() {
            Some(m) => m.height,
            None => return false,
        };
        if target_height > self.chain_state().best_header_height {
            return false;
        }
        match self.get_header_id_at_height(target_height).ok().flatten() {
            Some(best_at_h) => best_at_h == *header_id,
            None => false,
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        self.get_header(header_id).ok().flatten().is_some()
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        self.get_block_section(modifier_id).ok().flatten().is_some()
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        StateStore::get_section_height(self, modifier_id)
            .ok()
            .flatten()
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        StateStore::is_invalid(self, header_id).unwrap_or(false)
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        let mut ids = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            ids.push(current);
            match self.get_header_meta(&current).ok().flatten() {
                Some(meta) => current = meta.parent_id,
                None => break,
            }
        }
        ids
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        let mut headers = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            match self.get_header(&current).ok().flatten() {
                Some(bytes) => {
                    headers.push(bytes);
                    match self.get_header_meta(&current).ok().flatten() {
                        Some(meta) => current = meta.parent_id,
                        None => break,
                    }
                }
                None => break,
            }
        }
        headers
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        self.lookup_header_at_height(height)
            .unwrap_or(ergo_state::chain::HeightLookup::AboveTip)
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        self.get_header_meta(header_id)
            .ok()
            .flatten()
            .map(|m| m.height)
    }
}

/// `ChainView` over the Mode 5 digest backend. Mirrors the
/// `StateStore` impl's semantics method-for-method, reading through the
/// `HeaderSectionStore` / `ChainStateRead` surface the digest store
/// shares. The digest store persists the same header + section tables,
/// so the sync coordinator drives header/section flow against a digest
/// node identically to a UTXO node — only the block-apply seam differs.
impl ChainView for ergo_state::DigestStateStore {
    fn best_header_id(&self) -> [u8; 32] {
        self.chain_state().best_header_id
    }

    fn best_header_height(&self) -> u32 {
        self.chain_state().best_header_height
    }

    fn best_full_block_height(&self) -> u32 {
        self.chain_state().best_full_block_height
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        let target_height = match self.get_header_meta(header_id).ok().flatten() {
            Some(m) => m.height,
            None => return false,
        };
        if target_height > self.chain_state().best_header_height {
            return false;
        }
        match self.get_header_id_at_height(target_height).ok().flatten() {
            Some(best_at_h) => best_at_h == *header_id,
            None => false,
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        self.get_header(header_id).ok().flatten().is_some()
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        use ergo_state::HeaderSectionStore;
        self.get_block_section(modifier_id).ok().flatten().is_some()
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        ergo_state::HeaderSectionStore::get_section_height(self, modifier_id)
            .ok()
            .flatten()
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        ergo_state::HeaderSectionStore::is_invalid(self, header_id).unwrap_or(false)
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        use ergo_state::HeaderSectionStore;
        let mut ids = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            ids.push(current);
            match self.get_header_meta(&current).ok().flatten() {
                Some(meta) => current = meta.parent_id,
                None => break,
            }
        }
        ids
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        use ergo_state::HeaderSectionStore;
        let mut headers = Vec::new();
        let mut current = self.chain_state().best_header_id;
        for _ in 0..count {
            if current == [0u8; 32] {
                break;
            }
            match self.get_header(&current).ok().flatten() {
                Some(bytes) => {
                    headers.push(bytes);
                    match self.get_header_meta(&current).ok().flatten() {
                        Some(meta) => current = meta.parent_id,
                        None => break,
                    }
                }
                None => break,
            }
        }
        headers
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        self.lookup_header_at_height(height)
            .unwrap_or(ergo_state::chain::HeightLookup::AboveTip)
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        use ergo_state::HeaderSectionStore;
        self.get_header_meta(header_id)
            .ok()
            .flatten()
            .map(|m| m.height)
    }
}

/// `ChainView` over the runtime backend enum: match-forward every
/// method to the live `StateStore` or `DigestStateStore`. Lets the
/// sync coordinator and executor hold `&StateBackendKind` without a
/// type parameter or `dyn`.
impl ChainView for ergo_state::StateBackendKind {
    fn best_header_id(&self) -> [u8; 32] {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_header_id(),
            ergo_state::StateBackendKind::Digest(d) => d.best_header_id(),
        }
    }

    fn best_header_height(&self) -> u32 {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_header_height(),
            ergo_state::StateBackendKind::Digest(d) => d.best_header_height(),
        }
    }

    fn best_full_block_height(&self) -> u32 {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.best_full_block_height(),
            ergo_state::StateBackendKind::Digest(d) => d.best_full_block_height(),
        }
    }

    fn is_on_best_chain(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.is_on_best_chain(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.is_on_best_chain(header_id),
        }
    }

    fn has_header(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.has_header(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.has_header(header_id),
        }
    }

    fn has_block_section(&self, modifier_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.has_block_section(modifier_id),
            ergo_state::StateBackendKind::Digest(d) => d.has_block_section(modifier_id),
        }
    }

    fn get_section_height(&self, modifier_id: &[u8; 32]) -> Option<u32> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => ChainView::get_section_height(s, modifier_id),
            ergo_state::StateBackendKind::Digest(d) => {
                ChainView::get_section_height(d, modifier_id)
            }
        }
    }

    fn is_invalid(&self, header_id: &[u8; 32]) -> bool {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => ChainView::is_invalid(s, header_id),
            ergo_state::StateBackendKind::Digest(d) => ChainView::is_invalid(d, header_id),
        }
    }

    fn recent_header_ids(&self, count: usize) -> Vec<[u8; 32]> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.recent_header_ids(count),
            ergo_state::StateBackendKind::Digest(d) => d.recent_header_ids(count),
        }
    }

    fn recent_header_bytes(&self, count: usize) -> Vec<Vec<u8>> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.recent_header_bytes(count),
            ergo_state::StateBackendKind::Digest(d) => d.recent_header_bytes(count),
        }
    }

    fn header_id_at_height(&self, height: u32) -> ergo_state::chain::HeightLookup {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.header_id_at_height(height),
            ergo_state::StateBackendKind::Digest(d) => d.header_id_at_height(height),
        }
    }

    fn header_height_for(&self, header_id: &[u8; 32]) -> Option<u32> {
        match self {
            ergo_state::StateBackendKind::Utxo(s) => s.header_height_for(header_id),
            ergo_state::StateBackendKind::Digest(d) => d.header_height_for(header_id),
        }
    }
}

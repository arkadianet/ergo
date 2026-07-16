//! Recent-blocks tail: tip-cached canonical full-chain walk newest-first,
//! plus the transient first-deliverer merge layered on at serve time.

use std::sync::Arc;

use ergo_api::types::ApiRecentBlock;
use ergo_primitives::reader::VlqReader;
use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};
use ergo_ser::block_transactions::read_block_transactions;
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::reader::ChainStoreReader;
use ergo_state::{HeaderSectionStore, StateBackendKind};

use crate::snapshot::RecentBlocksCache;

/// Number of recent full blocks the dashboard tail holds, and the upper
/// bound on the chain walk that builds it.
const RECENT_BLOCKS_CAP: usize = 32;

/// Return the recent-blocks tail for `tip_id`, reusing the cached `Arc`
/// when the full-block tip is unchanged.
///
/// Walking the full-block ancestor chain (header parse + section reads)
/// is too heavy to redo on every `sync_tick`; the tail only changes when
/// the full-block tip advances, so we recompute only when `tip_id` differs
/// from the cached entry and otherwise hand back the cached allocation.
/// Takes the cache and store as separate borrows (disjoint `NodeState`
/// fields) so the call site can hold a `&mut` to the cache without aliasing
/// the rest of `state`.
///
/// Caching keyed on `tip_id` alone (no per-tick section re-validation) is
/// sound because a *committed* block is immutable: its header and sections
/// never change once written, so a tail that was contiguous when cached stays
/// correct until the tip advances. Re-reading all 32 sections every tick to
/// detect post-commit corruption would reintroduce exactly the hot-path cost
/// this cache exists to avoid; such corruption is an apply-path fault, not a
/// dashboard concern.
///
/// `tip_id`/`tip_height` are the *committed* full-block tip (the caller reads
/// it from `ChainStoreReader::committed_tip`), whose sections are durably
/// stored, so the walk normally reaches it.
///
/// The result is cached only when the tail is a *contiguous* run anchored at
/// the tip — heights `tip, tip-1, tip-2, …` with no gaps. `build_recent_blocks`
/// walks past a faulted ancestor section (leaving a gap) rather than
/// truncating, and such a fault is usually transient; caching a gappy or
/// tip-short tail would pin it until the next tip change. Requiring contiguity
/// means a one-tick read fault recomputes next tick instead (cheap and brief),
/// filling the tail back in once the section reads cleanly.
pub(super) fn recent_blocks_for_tip(
    cache: &mut Option<RecentBlocksCache>,
    store: &StateBackendKind,
    tip_id: [u8; 32],
    tip_height: u32,
    network: NetworkPrefix,
) -> Arc<Vec<ApiRecentBlock>> {
    if let Some(c) = cache {
        if c.tip_id == tip_id {
            return c.blocks.clone();
        }
    }
    let blocks = Arc::new(build_recent_blocks(store, tip_id, tip_height, network));
    // Contiguous-from-tip: `blocks[i]` must be height `tip_height - i`. This
    // implies the tip itself was emitted (i = 0) and that no ancestor inside
    // the window was skipped on a transient fault. An empty tail (tip block
    // unreadable this tick) is therefore not cached — it retries next tick.
    let contiguous = !blocks.is_empty()
        && blocks
            .iter()
            .enumerate()
            .all(|(i, b)| Some(b.height) == tip_height.checked_sub(i as u32));
    if contiguous {
        *cache = Some(RecentBlocksCache {
            tip_id,
            blocks: blocks.clone(),
        });
    }
    blocks
}

/// Layer the transient `delivered_by` first-deliverer fact onto a
/// committed (tip-cached) recent-blocks tail.
///
/// The tip-keyed `recent_blocks` cache holds committed-state only — its
/// `Arc` is reused across ticks until the full-block tip advances. The
/// first deliverer of a block, by contrast, is a live P2P observation
/// that can be recorded AFTER the tip was cached, so it is merged in here
/// at serve-build time rather than baked into the cache (which would pin a
/// stale or absent deliverer until the next tip change).
///
/// For each block whose `header_id` (hex) resolves in the ring, sets
/// `delivered_by` to the first deliverer's socket address; blocks not in
/// the ring keep `None`. Returns the input `Arc` UNCHANGED when no block
/// in the window has a recorded deliverer — the steady-state synced case,
/// kept allocation-free — and only clones into a fresh `Vec` when at least
/// one deliverer is found.
pub(super) fn merge_delivered_by(
    committed: Arc<Vec<ApiRecentBlock>>,
    ring: &super::super::first_deliverer::FirstDelivererRing,
) -> Arc<Vec<ApiRecentBlock>> {
    // First pass: does any block in the window have a recorded deliverer?
    // Avoids allocating a new Vec on the common (fully-synced, ring-cold-
    // for-this-window) path where every lookup misses.
    let any = committed.iter().any(|b| {
        decode_header_id(&b.header_id)
            .map(|id| ring.get(&id).is_some())
            .unwrap_or(false)
    });
    if !any {
        return committed;
    }
    let merged: Vec<ApiRecentBlock> = committed
        .iter()
        .map(|b| {
            let delivered_by = decode_header_id(&b.header_id)
                .and_then(|id| ring.get(&id).map(|d| d.peer.to_string()));
            ApiRecentBlock {
                delivered_by,
                ..b.clone()
            }
        })
        .collect();
    Arc::new(merged)
}

/// Decode a 64-char lowercase-hex header id back to its 32 bytes for a
/// ring lookup. Returns `None` on any malformed input (wrong length / non-
/// hex) — those simply miss the ring and surface `delivered_by = None`.
fn decode_header_id(hex_id: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_id).ok()?;
    bytes.try_into().ok()
}

/// Walk the canonical full-block chain backwards from the best full block,
/// newest-first, building up to [`RECENT_BLOCKS_CAP`] entries.
///
/// The walk follows each header's `parent_id` rather than the best-*header*
/// height index (`get_header_id_at_height`): a heavier header-only fork can
/// run the header index ahead of — and away from — the applied full-block
/// chain, and this endpoint must only ever surface applied full blocks.
/// Every ancestor of an applied full block is itself an applied full block,
/// so the parent walk stays on the canonical full chain by construction.
///
/// The walk is bounded to at most `RECENT_BLOCKS_CAP` headers regardless of
/// how many emit, so a run of corrupt sections near the tip can leave a
/// gap but can never turn this into a walk to genesis.
///
/// Headers are read through `store` (which sees the in-flight `batch_headers`
/// tip), but block sections are read through a non-draining
/// [`ChainStoreReader`]: the draining `StateStore::get_block_section` reaps
/// the async persist pipeline's results and would surface — and thereby
/// consume — a `PersistFailed` on this read-only snapshot path, masking a
/// storage fault the apply path must own. The reader reads committed sections
/// only, which is exactly what the draining path saw anyway (sections aren't
/// readable until their persist job commits); it just never steals the fault.
///
/// UTXO-only tail: [`try_recent_block`] treats an absent `adProofs` section as
/// the benign 0-byte case, which holds for UTXO mode but not for digest
/// backends, where a missing `adProofs` section is a fault
/// (`DigestAdProofsSectionMissing`). `publish_snapshot` itself now runs for
/// both backends (its state-root read goes through the backend-agnostic
/// [`StateBackendKind::state_root_digest`]), so the backend gate lives HERE:
/// a digest backend gets an empty recent-blocks tail rather than adopting the
/// wrong size rule.
fn build_recent_blocks(
    store: &StateBackendKind,
    tip_id: [u8; 32],
    tip_height: u32,
    network: NetworkPrefix,
) -> Vec<ApiRecentBlock> {
    let mut out = Vec::new();
    if tip_height == 0 || store.as_utxo().is_none() {
        return out; // no full block applied yet, or a non-UTXO backend
    }
    let sections = ChainStoreReader::new_from_db(store.db_arc());
    let mut id = tip_id;
    let mut height = tip_height;
    for _ in 0..RECENT_BLOCKS_CAP {
        // The header is the walk anchor: we need its `parent_id` to step
        // back, and an applied full block always retains its header. A
        // miss or parse fault here means we cannot continue the walk
        // (older entries become unreachable), so stop.
        let header_bytes = match store.get_header(&id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                tracing::warn!(height, "recent_blocks: header bytes absent; stopping walk");
                break;
            }
            Err(e) => {
                tracing::warn!(error = %e, height, "recent_blocks: header read failed; stopping walk");
                break;
            }
        };
        let header = match read_header(&mut VlqReader::new(&header_bytes)) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, height, "recent_blocks: header parse failed; stopping walk");
                break;
            }
        };
        let parent = *header.parent_id.as_bytes();
        if let Some(block) =
            try_recent_block(&sections, &id, height, &header, header_bytes.len(), network)
        {
            out.push(block);
        }
        // Step to the parent even when this block was skipped, so a single
        // faulty section near the tip doesn't truncate the whole list.
        // Genesis is height 1 with a zero parent id — stop there.
        if height <= 1 || parent == [0u8; 32] {
            break;
        }
        id = parent;
        height -= 1;
    }
    out
}

/// Build one recent-blocks entry from a parsed header plus its on-disk
/// sections, or `None` when the block must be omitted.
///
/// Sections are read through the non-draining [`ChainStoreReader`] (see
/// `build_recent_blocks`), so a section read `Err` here is a redb read fault,
/// never an async-persist `PersistFailed`.
///
/// `size_bytes` sums the on-disk section byte lengths. `transactions` and
/// `extension` are required — an applied full block always has both (see
/// `AssemblyTracker::is_complete`) — so a missing or unreadable required
/// section omits the block rather than under-reporting its size. `adProofs`
/// is optional in UTXO mode (apply does not retain it): a genuine absence
/// (`Ok(None)`) contributes 0, but a read *error* still omits the block
/// rather than reporting a silently wrong size. Omitting keeps a corrupt or
/// partial block out of the list instead of undercounting it.
fn try_recent_block(
    sections: &ChainStoreReader,
    id: &[u8; 32],
    height: u32,
    header: &Header,
    header_len: usize,
    network: NetworkPrefix,
) -> Option<ApiRecentBlock> {
    let expected = ExpectedSections::from_header(
        id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    // transactions — required; we need the bytes for both the size and
    // the tx count.
    let tx_bytes = match sections.get_block_section(&expected.transactions_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            tracing::warn!(
                height,
                "recent_blocks: transactions section absent; omitting block"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: transactions read failed; omitting block");
            return None;
        }
    };
    let bt = match read_block_transactions(&mut VlqReader::new(&tx_bytes)) {
        Ok(bt) => bt,
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: blockTransactions parse failed; omitting block");
            return None;
        }
    };
    // Defense-in-depth: the section was looked up by the id derived from the
    // header's `transactions_root`, so its embedded `header_id` must point
    // back at the block we walked. A mismatch means the stored section bytes
    // are inconsistent with the header (corruption / cross-block write); omit
    // rather than report a tx count from the wrong block.
    if bt.header_id.as_bytes() != id {
        tracing::warn!(
            height,
            "recent_blocks: blockTransactions header_id mismatch; omitting block"
        );
        return None;
    }
    // extension — required.
    let ext_len = match sections.get_block_section(&expected.extension_id) {
        Ok(Some(b)) => b.len(),
        Ok(None) => {
            tracing::warn!(
                height,
                "recent_blocks: extension section absent; omitting block"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: extension read failed; omitting block");
            return None;
        }
    };
    // adProofs — optional in UTXO mode; a genuine absence contributes 0,
    // but a read error still omits the block.
    let adp_len = match sections.get_block_section(&expected.ad_proofs_id) {
        Ok(Some(b)) => b.len(),
        Ok(None) => 0,
        Err(e) => {
            tracing::warn!(error = %e, height, "recent_blocks: adProofs read failed; omitting block");
            return None;
        }
    };
    let (miner_pk, miner_address) = miner_fields(header.solution.pk().as_bytes(), network);
    Some(ApiRecentBlock {
        height,
        header_id: hex::encode(id),
        ts_unix_ms: header.timestamp,
        txs: bt.transactions.len() as u32,
        size_bytes: (header_len + tx_bytes.len() + ext_len + adp_len) as u64,
        // `delivered_by` is merged in at snapshot-assembly time from the
        // first-deliverer ring (a transient P2P fact), NOT baked into the
        // tip-keyed recent-blocks cache (committed-state only). See
        // `merge_delivered_by` at the `publish_snapshot` call site.
        delivered_by: None,
        miner_pk,
        miner_address,
    })
}

/// Miner attribution facts from a header's Autolykos solution pk bytes:
/// (hex pk, derived P2PK address). The address encodes with this node's
/// network prefix; an encode failure (wrong length) degrades to `None`
/// rather than omitting the block.
fn miner_fields(pk_bytes: &[u8], network: NetworkPrefix) -> (Option<String>, Option<String>) {
    (
        Some(hex::encode(pk_bytes)),
        encode_p2pk_from_pubkey(network, pk_bytes).ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
    use ergo_primitives::group_element::GroupElement;
    use ergo_primitives::writer::VlqWriter;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::block_transactions::{write_block_transactions, BlockTransactions};
    use ergo_ser::header::serialize_header;
    use ergo_ser::modifier_id::{TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION};
    use ergo_state::store::StateStore;
    use std::time::Instant;

    // ----- helpers -----

    /// A minimal v2 header chained to `parent`, with its three section
    /// roots derived from `tag` (distinct blocks → distinct roots, though
    /// the header id already disambiguates section ids). Returns the
    /// header plus its canonical id and wire bytes.
    fn header(height: u32, parent: [u8; 32], tag: u8) -> (Header, [u8; 32], Vec<u8>) {
        let h = Header {
            version: 2,
            parent_id: ModifierId::from_bytes(parent),
            ad_proofs_root: Digest32::from_bytes([tag.wrapping_add(1); 32]),
            transactions_root: Digest32::from_bytes([tag.wrapping_add(2); 32]),
            state_root: ADDigest::from_bytes([0x04; 33]),
            timestamp: 1_700_000_000_000 + height as u64,
            extension_root: Digest32::from_bytes([tag.wrapping_add(3); 32]),
            n_bits: 0x1a01_7660,
            height,
            votes: [0; 3],
            unparsed_bytes: vec![],
            solution: AutolykosSolution::V2 {
                pk: GroupElement::from_bytes([0x02; 33]),
                nonce: [0xAA; 8],
            },
        };
        let (bytes, id) = serialize_header(&h).unwrap();
        (h, *id.as_bytes(), bytes)
    }

    /// Canonical bytes of an empty `BlockTransactions` — valid input for
    /// `read_block_transactions` (tx count 0), enough to exercise the
    /// section read + parse + size path.
    fn tx_section(header_id: [u8; 32]) -> Vec<u8> {
        let bt = BlockTransactions {
            header_id: ModifierId::from_bytes(header_id),
            transactions: vec![],
        };
        let mut w = VlqWriter::new();
        write_block_transactions(&mut w, &bt).unwrap();
        w.result()
    }

    /// Store a header and any subset of its three sections. `ext`/`adp`
    /// are the raw section bytes to store (the walk only measures their
    /// length); `None` leaves that section absent.
    fn store_block(
        store: &StateStore,
        h: &Header,
        id: [u8; 32],
        header_bytes: &[u8],
        tx: bool,
        ext: Option<&[u8]>,
        adp: Option<&[u8]>,
    ) {
        store.store_header(&id, header_bytes).unwrap();
        let expected = ExpectedSections::from_header(
            &id,
            h.transactions_root.as_bytes(),
            h.extension_root.as_bytes(),
            h.ad_proofs_root.as_bytes(),
        );
        if tx {
            let b = tx_section(id);
            store
                .store_block_section_typed(&expected.transactions_id, &b, TYPE_BLOCK_TRANSACTIONS)
                .unwrap();
        }
        if let Some(e) = ext {
            store
                .store_block_section_typed(&expected.extension_id, e, TYPE_EXTENSION)
                .unwrap();
        }
        if let Some(a) = adp {
            store
                .store_block_section_typed(&expected.ad_proofs_id, a, TYPE_AD_PROOFS)
                .unwrap();
        }
    }

    fn open_store() -> (tempfile::TempDir, StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::open(&tmp.path().join("state.redb")).unwrap();
        (tmp, store)
    }

    // ----- happy path -----

    /// Newest-first over the canonical full chain, with `size_bytes` summing
    /// the on-disk sections and adProofs being optional: the block without
    /// an adProofs section is still emitted, its size just excludes it.
    #[test]
    fn recent_blocks_walks_full_chain_newest_first_with_section_sizes() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        let adp = vec![0xAAu8; 5];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), Some(&adp));
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None); // no adProofs
        store_block(&store, &h3, id3, &b3, true, Some(&ext), Some(&adp));
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3, NetworkPrefix::Mainnet);

        assert_eq!(out.len(), 3);
        assert_eq!(out[0].height, 3);
        assert_eq!(out[1].height, 2);
        assert_eq!(out[2].height, 1);
        assert_eq!(out[0].header_id, hex::encode(id3));
        assert_eq!(out[0].ts_unix_ms, 1_700_000_000_003);
        assert_eq!(out[0].txs, 0);
        // h3 has adProofs → size includes all four sections.
        assert_eq!(
            out[0].size_bytes,
            b3.len() as u64 + tx_section(id3).len() as u64 + ext.len() as u64 + adp.len() as u64,
        );
        // h2 has no adProofs → size excludes it; block still present.
        assert_eq!(
            out[1].size_bytes,
            b2.len() as u64 + tx_section(id2).len() as u64 + ext.len() as u64,
        );
    }

    /// The walk follows `parent_id`, so a header on a different branch
    /// (not an ancestor of the full tip) never appears — the fork-safety
    /// invariant that the best-*header* height index could not provide.
    #[test]
    fn recent_blocks_follows_parent_links_not_unrelated_headers() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        // Competing height-2 header on a different branch (parent is not
        // id1). Present in the store but not an ancestor of id3.
        let (hf, idf, bf) = header(2, [0x77u8; 32], 99);
        store_block(&store, &hf, idf, &bf, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3, NetworkPrefix::Mainnet);

        let ids: Vec<String> = out.iter().map(|b| b.header_id.clone()).collect();
        assert_eq!(
            ids,
            vec![hex::encode(id3), hex::encode(id2), hex::encode(id1)],
        );
        assert!(
            !ids.contains(&hex::encode(idf)),
            "fork header must not appear in the recent-blocks tail",
        );
    }

    /// The walk is bounded to `RECENT_BLOCKS_CAP` headers even when more
    /// blocks exist — it never runs to genesis.
    #[test]
    fn recent_blocks_caps_walk_at_recent_blocks_cap() {
        let (_tmp, store) = open_store();
        let ext = vec![0xEEu8; 3];
        let total = RECENT_BLOCKS_CAP as u32 + 8;
        let mut parent = [0u8; 32];
        let mut tip_id = [0u8; 32];
        for h in 1..=total {
            let (hdr, id, bytes) = header(h, parent, (h % 200) as u8);
            store_block(&store, &hdr, id, &bytes, true, Some(&ext), None);
            parent = id;
            tip_id = id;
        }
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, tip_id, total, NetworkPrefix::Mainnet);

        assert_eq!(out.len(), RECENT_BLOCKS_CAP);
        assert_eq!(out[0].height, total);
        assert_eq!(
            out[RECENT_BLOCKS_CAP - 1].height,
            total - RECENT_BLOCKS_CAP as u32 + 1,
        );
    }

    /// No full block applied yet (`tip_height == 0`) → empty, no reads.
    #[test]
    fn recent_blocks_empty_when_no_full_block() {
        let (_tmp, store) = open_store();
        let backend = StateBackendKind::Utxo(store);
        assert!(build_recent_blocks(&backend, [0u8; 32], 0, NetworkPrefix::Mainnet).is_empty());
    }

    /// Digest backends treat an absent adProofs section as a fault, not the
    /// benign 0-byte case the recent-blocks size rule assumes; the list is
    /// UTXO-only and yields an empty tail on a digest backend regardless of
    /// the requested tip.
    #[test]
    fn recent_blocks_empty_on_digest_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ergo_state::DigestStateStore::open(
            &tmp.path().join("digest.redb"),
            ergo_validation::scala_launch(),
            ergo_chain_spec::VotingParams {
                voting_length: 2,
                ..ergo_chain_spec::VotingParams::mainnet()
            },
            [0u8; 33], // EMPTY_AVL_DIGEST — a fresh digest store seeds from it
        )
        .unwrap();
        let backend = StateBackendKind::Digest(store);
        assert!(build_recent_blocks(&backend, [7u8; 32], 5, NetworkPrefix::Mainnet).is_empty());
    }

    /// The tail tracks the *committed* full-block tip, not the highest header
    /// present in the store. With h3 fully persisted but the committed tip
    /// still at h2 (the async-persist / in-memory-ahead window), the snapshot
    /// path reads committed_tip = h2 and never advertises h3.
    #[test]
    fn recent_blocks_reflects_committed_tip_not_uncommitted_headers() {
        let (_tmp, mut store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        // h3 is fully present in the store, but is not the committed tip.
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        store.set_best_full_block_for_test(id2, 2).unwrap();
        let backend = StateBackendKind::Utxo(store);

        // The snapshot path anchors on committed_tip (= h2), not the highest
        // present header (h3).
        let reader = ChainStoreReader::new_from_db(backend.db_arc());
        assert_eq!(reader.committed_tip().unwrap(), Some((2, id2)));

        let out = build_recent_blocks(&backend, id2, 2, NetworkPrefix::Mainnet);
        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(
            heights,
            vec![2, 1],
            "tail reflects committed tip h2, never the uncommitted h3",
        );
    }

    /// The cache hands back the same `Arc` while the tip is unchanged and
    /// rebuilds (new allocation + contents) once the tip moves.
    #[test]
    fn recent_blocks_cache_reuses_arc_until_tip_changes() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let ext = vec![0xEEu8; 4];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let mut cache = None;
        let first = recent_blocks_for_tip(&mut cache, &backend, id2, 2, NetworkPrefix::Mainnet);
        let second = recent_blocks_for_tip(&mut cache, &backend, id2, 2, NetworkPrefix::Mainnet);
        assert!(
            Arc::ptr_eq(&first, &second),
            "unchanged tip must reuse the cached Arc"
        );

        let third = recent_blocks_for_tip(&mut cache, &backend, id1, 1, NetworkPrefix::Mainnet);
        assert!(
            !Arc::ptr_eq(&first, &third),
            "tip change must rebuild the tail"
        );
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].height, 1);
    }

    /// A transient fault on an *ancestor* section leaves a gap in the tail;
    /// the contiguity guard refuses to cache it, so the next tick (same tip)
    /// recomputes and self-heals once the section reads cleanly — no tip
    /// advance required.
    #[test]
    fn recent_blocks_cache_self_heals_after_transient_ancestor_gap() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        // h2: header + tx present, extension missing (the transient gap).
        store_block(&store, &h2, id2, &b2, true, None, None);
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let mut cache = None;
        // First tick: h2 omitted → gappy tail [3, 1]. Not contiguous from the
        // tip, so it must not be cached.
        let gappy = recent_blocks_for_tip(&mut cache, &backend, id3, 3, NetworkPrefix::Mainnet);
        assert_eq!(
            gappy.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![3, 1]
        );
        assert!(cache.is_none(), "a gappy tail must not be cached");

        // The missing ancestor section appears (the fault was transient).
        let expected = ExpectedSections::from_header(
            &id2,
            h2.transactions_root.as_bytes(),
            h2.extension_root.as_bytes(),
            h2.ad_proofs_root.as_bytes(),
        );
        backend
            .as_utxo()
            .unwrap()
            .store_block_section_typed(&expected.extension_id, &ext, TYPE_EXTENSION)
            .unwrap();

        // Second tick, same tip id: recomputes (was never cached) and now
        // yields the full contiguous tail, which is cached.
        let healed = recent_blocks_for_tip(&mut cache, &backend, id3, 3, NetworkPrefix::Mainnet);
        assert_eq!(
            healed.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![3, 2, 1]
        );
        assert!(cache.is_some(), "a contiguous tail is cached");
    }

    // ----- error paths -----

    /// A block missing a *required* section (extension) is omitted rather
    /// than size-undercounted, and the walk still reaches older blocks via
    /// the parent links.
    #[test]
    fn recent_blocks_omits_block_with_missing_required_section_and_continues() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let (h3, id3, b3) = header(3, id2, 30);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        store_block(&store, &h2, id2, &b2, true, None, None); // missing extension
        store_block(&store, &h3, id3, &b3, true, Some(&ext), None);
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id3, 3, NetworkPrefix::Mainnet);

        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(heights, vec![3, 1], "h2 omitted, walk continued to h1");
    }

    /// A block whose stored transactions section embeds a different
    /// `header_id` than the walked block (corruption / cross-block write) is
    /// omitted — the tx count must never be reported from the wrong block.
    #[test]
    fn recent_blocks_omits_block_with_mismatched_tx_header_id() {
        let (_tmp, store) = open_store();
        let (h1, id1, b1) = header(1, [0u8; 32], 10);
        let (h2, id2, b2) = header(2, id1, 20);
        let ext = vec![0xEEu8; 7];
        store_block(&store, &h1, id1, &b1, true, Some(&ext), None);
        // h2: well-formed header + extension, but a transactions section
        // whose embedded `header_id` points at h1, not h2.
        store.store_header(&id2, &b2).unwrap();
        let expected = ExpectedSections::from_header(
            &id2,
            h2.transactions_root.as_bytes(),
            h2.extension_root.as_bytes(),
            h2.ad_proofs_root.as_bytes(),
        );
        store
            .store_block_section_typed(
                &expected.transactions_id,
                &tx_section(id1),
                TYPE_BLOCK_TRANSACTIONS,
            )
            .unwrap();
        store
            .store_block_section_typed(&expected.extension_id, &ext, TYPE_EXTENSION)
            .unwrap();
        let backend = StateBackendKind::Utxo(store);

        let out = build_recent_blocks(&backend, id2, 2, NetworkPrefix::Mainnet);

        let heights: Vec<u32> = out.iter().map(|b| b.height).collect();
        assert_eq!(
            heights,
            vec![1],
            "h2 omitted on tx header_id mismatch, walk continued to h1"
        );
    }

    // ----- miner attribution -----

    #[test]
    fn miner_fields_derives_pk_hex_and_mainnet_p2pk_address() {
        // Live-verified vector: 2Miners' mining pk → its P2PK address
        // (cross-checked against /utils/rawToAddress on mainnet 2026-07-05).
        let pk = hex::decode("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
            .unwrap();
        let (pk_hex, addr) = miner_fields(&pk, NetworkPrefix::Mainnet);
        assert_eq!(
            pk_hex.as_deref(),
            Some("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
        );
        assert_eq!(
            addr.as_deref(),
            Some("9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx")
        );
    }

    #[test]
    fn miner_fields_bad_pk_length_yields_pk_but_no_address() {
        let (pk_hex, addr) = miner_fields(&[0u8; 5], NetworkPrefix::Mainnet);
        assert_eq!(pk_hex.as_deref(), Some("0000000000"));
        assert!(addr.is_none(), "address encoding must fail closed to None");
    }

    // ----- delivered_by merge -----

    fn recent_block_stub(header_id: [u8; 32], height: u32) -> ApiRecentBlock {
        ApiRecentBlock {
            height,
            header_id: hex::encode(header_id),
            ts_unix_ms: 0,
            txs: 0,
            size_bytes: 0,
            delivered_by: None,
            miner_pk: None,
            miner_address: None,
        }
    }

    /// `delivered_by` is populated from the first-deliverer ring for a
    /// block whose header id is recorded, and stays `None` for one that
    /// isn't. Proves the serve-build-time merge layers the transient P2P
    /// fact onto the committed (deliverer-free) recent-blocks tail.
    #[test]
    fn merge_delivered_by_populates_from_ring_and_none_when_absent() {
        use crate::node::first_deliverer::FirstDelivererRing;
        let mut ring = FirstDelivererRing::new();
        let known = [0xAAu8; 32];
        let unknown = [0xBBu8; 32];
        let peer: std::net::SocketAddr = "203.0.113.7:9030".parse().unwrap();
        ring.record(known, peer, Instant::now());

        let committed = Arc::new(vec![
            recent_block_stub(known, 100),
            recent_block_stub(unknown, 99),
        ]);
        let merged = merge_delivered_by(committed, &ring);

        assert_eq!(
            merged[0].delivered_by.as_deref(),
            Some("203.0.113.7:9030"),
            "recorded header id must surface its first deliverer",
        );
        assert_eq!(
            merged[1].delivered_by, None,
            "header id absent from the ring must stay None",
        );
    }

    /// When no block in the window has a recorded deliverer, the input
    /// `Arc` is returned UNCHANGED (no reallocation) — the steady-state
    /// synced path stays allocation-free.
    #[test]
    fn merge_delivered_by_returns_same_arc_when_no_match() {
        use crate::node::first_deliverer::FirstDelivererRing;
        let ring = FirstDelivererRing::new(); // empty
        let committed = Arc::new(vec![recent_block_stub([0x11u8; 32], 1)]);
        let merged = merge_delivered_by(committed.clone(), &ring);
        assert!(
            Arc::ptr_eq(&committed, &merged),
            "no deliverer in window must reuse the input Arc, not reallocate",
        );
    }
}

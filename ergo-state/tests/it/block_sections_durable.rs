//! `store_block_sections_durable`: the sections of a block this node mined or
//! was handed whole are on disk when the call returns, and are written all
//! together or not at all.
//!
//! A crash image is a copy of the database file taken while the store is
//! still open: what a process killed at that moment leaves on disk. redb keeps
//! a commit made with `Durability::None` in memory until a durable commit
//! follows, so such a commit is missing from the image.

use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::header::{write_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::chain::HeaderMeta;
use ergo_state::store::{StateError, StateStore};
use std::path::Path;

// ----- helpers -----

const CACHE_BYTES: usize = 4 * 1024 * 1024;

/// Section ids of a stored header, in `(id, modifier type)` pairs.
type Sections = [([u8; 32], u8); 3];

/// Store a synthetic header at `height` through the validated-header path,
/// which writes its `SECTION_HEIGHT_INDEX` rows, and return its section ids.
fn store_header(store: &mut StateStore, height: u32) -> Sections {
    let header_id = [0x55; 32];
    let roots = [
        (TYPE_BLOCK_TRANSACTIONS, [0x92; 32]),
        (TYPE_EXTENSION, [0x93; 32]),
        (TYPE_AD_PROOFS, [0x91; 32]),
    ];
    let header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes([0; 32]),
        ad_proofs_root: Digest32::from_bytes(roots[2].1),
        transactions_root: Digest32::from_bytes(roots[0].1),
        state_root: ADDigest::from_bytes([0x04; 33]),
        timestamp: 1_700_000_000_000,
        extension_root: Digest32::from_bytes(roots[1].1),
        n_bits: 0x1a01_7660,
        height,
        votes: [0; 3],
        unparsed_bytes: vec![],
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from_bytes([0x02; 33]),
            nonce: [0xAA; 8],
        },
    };
    let mut w = VlqWriter::new();
    write_header(&mut w, &header).unwrap();
    let meta = HeaderMeta {
        parent_id: [0; 32],
        height,
        cumulative_score: vec![0; 8],
        pow_validity: 1,
        timestamp: header.timestamp,
    };
    store
        .store_validated_header(&header_id, &w.result(), &meta, None)
        .unwrap();
    roots.map(|(kind, root)| (compute_section_id(kind, &header_id, &root), kind))
}

/// Copy the open store's database file and open the copy.
fn crash_image(store: &StateStore, dir: &Path) -> StateStore {
    let image = dir.join("crash-image.redb");
    std::fs::copy(store.database_path(), &image).unwrap();
    StateStore::open_with_cache(&image, CACHE_BYTES).unwrap()
}

fn stored(store: &StateStore, id: &[u8; 32]) -> bool {
    store.get_block_section(id).unwrap().is_some()
}

// ----- happy path -----

#[test]
fn block_sections_durable_crash_image_holds_every_section() {
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        StateStore::open_with_cache(&dir.path().join("state.redb"), CACHE_BYTES).unwrap();
    let sections = store_header(&mut store, 5);
    let payloads = sections.map(|(_, kind)| [kind]);
    let writes: Vec<(&[u8; 32], &[u8], u8)> = sections
        .iter()
        .zip(&payloads)
        .map(|((id, kind), payload)| (id, payload.as_slice(), *kind))
        .collect();
    store.store_block_sections_durable(&writes).unwrap();
    let image = crash_image(&store, dir.path());
    for (id, kind) in &sections {
        assert_eq!(
            image.get_block_section(id).unwrap().as_deref(),
            Some([*kind].as_slice()),
            "type {kind}"
        );
    }
}

#[test]
fn block_section_typed_crash_image_lacks_section() {
    // The single-section write commits with `Durability::None`, which a
    // crash image does not hold: the loss the durable write exists to close.
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        StateStore::open_with_cache(&dir.path().join("state.redb"), CACHE_BYTES).unwrap();
    let [(id, kind), ..] = store_header(&mut store, 5);
    store.store_block_section_typed(&id, &[kind], kind).unwrap();
    assert!(stored(&store, &id));
    assert!(!stored(&crash_image(&store, dir.path()), &id));
}

// ----- error paths -----

#[test]
fn block_sections_durable_unindexed_section_writes_none() {
    // With the window above height one, the prune guard refuses a section
    // whose header is not stored. The other sections in the same call are
    // not written either.
    let dir = tempfile::tempdir().unwrap();
    let mut store =
        StateStore::open_with_cache(&dir.path().join("state.redb"), CACHE_BYTES).unwrap();
    store.write_minimal_full_block_height(2).unwrap();
    let [(bt, bt_kind), (ext, ext_kind), _] = store_header(&mut store, 5);
    let unindexed = [0x77; 32];
    let err = store
        .store_block_sections_durable(&[
            (&bt, [1].as_slice(), bt_kind),
            (&ext, [2].as_slice(), ext_kind),
            (&unindexed, [3].as_slice(), TYPE_AD_PROOFS),
        ])
        .expect_err("an unindexed section is refused");
    assert!(
        matches!(
            err,
            StateError::PrunedSection {
                section_height: 0,
                sentinel: 2,
                ..
            }
        ),
        "{err:?}"
    );
    for id in [bt, ext, unindexed] {
        assert!(!stored(&store, &id), "{}", hex::encode(id));
    }
}

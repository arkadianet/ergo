//! Non-gated test of the persisted PoPoW-header accessor (§6.1).
//!
//! `StateStore::popow_header_by_id` derives a `PoPowHeader` on
//! demand from stored header bytes + stored extension bytes — this
//! is the Rust equivalent of Scala's
//! `PopowProcessor.popowHeader(headerId)` at
//! `ergo-core/.../modifiers/history/popow/.../PopowProcessor.scala:75-86`.
//!
//! Coverage:
//! - Insert real mainnet h=2 header bytes + h=2 extension bytes
//!   into an in-process redb store.
//! - Call `popow_header_by_id` and `popow_header_at_height` (via
//!   `store_header_chain_index_record`).
//! - Assert the returned PoPowHeader is structurally well-formed
//!   and that its built-in interlinks proof validates against the
//!   verifier — full e2e through the store-backed path.
//! - Header missing / extension missing branches return `None`
//!   without panicking.

use ergo_primitives::reader::VlqReader;
use ergo_ser::extension::{Extension, ExtensionField};
use ergo_ser::header::read_header;
use ergo_state::store::StateStore;
use ergo_validation::popow::proof::check_popow_header_interlinks_proof;
use serde::Deserialize;
use tempfile::TempDir;

#[derive(Deserialize)]
struct BlockJson {
    height: u32,
    #[serde(rename = "headerId")]
    header_id: String,
    extension: ExtJson,
}

#[derive(Deserialize)]
struct ExtJson {
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct HeaderVec {
    height: u32,
    bytes: String,
}

fn fixture_path(rel: &str) -> String {
    format!(
        "{}/../test-vectors/mainnet/{}",
        env!("CARGO_MANIFEST_DIR"),
        rel
    )
}

fn load_block(height: u32) -> BlockJson {
    let raw = std::fs::read_to_string(fixture_path("blocks_1_5.json")).unwrap();
    let blocks: Vec<BlockJson> = serde_json::from_str(&raw).unwrap();
    blocks.into_iter().find(|b| b.height == height).unwrap()
}

fn load_header_bytes(height: u32) -> Vec<u8> {
    let raw = std::fs::read_to_string(fixture_path("headers_1_2000.json")).unwrap();
    let vecs: Vec<HeaderVec> = serde_json::from_str(&raw).unwrap();
    let entry = vecs.iter().find(|v| v.height == height).unwrap();
    hex::decode(&entry.bytes).unwrap()
}

fn build_extension(block: &BlockJson) -> Extension {
    use ergo_primitives::digest::ModifierId;
    Extension {
        header_id: ModifierId::from_bytes(
            hex::decode(&block.header_id).unwrap().try_into().unwrap(),
        ),
        fields: block
            .extension
            .fields
            .iter()
            .map(|(k, v)| ExtensionField {
                key: hex::decode(k).unwrap().try_into().unwrap(),
                value: hex::decode(v).unwrap(),
            })
            .collect(),
    }
}

fn compute_extension_id(header_id: &[u8; 32], extension_root: &[u8; 32]) -> [u8; 32] {
    use ergo_ser::modifier_id::{compute_section_id, TYPE_EXTENSION};
    compute_section_id(TYPE_EXTENSION, header_id, extension_root)
}

fn open_store() -> (TempDir, StateStore) {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("state.redb");
    let store = StateStore::open(&db_path).unwrap();
    (tmp, store)
}

#[test]
fn popow_header_by_id_returns_well_formed_header_for_real_mainnet_h2() {
    let (_tmp, store) = open_store();

    // 1. Load real mainnet h=2 header + extension bytes.
    let block = load_block(2);
    let header_id: [u8; 32] = hex::decode(&block.header_id).unwrap().try_into().unwrap();
    let header_bytes = load_header_bytes(2);
    let header = {
        let mut r = VlqReader::new(&header_bytes);
        read_header(&mut r).unwrap()
    };
    let ext = build_extension(&block);
    let ext_bytes = {
        use ergo_primitives::writer::VlqWriter;
        let mut w = VlqWriter::new();
        ergo_ser::extension::write_extension(&mut w, &ext).unwrap();
        w.result()
    };
    let extension_id = compute_extension_id(&header_id, header.extension_root.as_bytes());

    // 2. Insert header + extension into the store.
    store.store_header(&header_id, &header_bytes).unwrap();
    store
        .store_block_section(&extension_id, &ext_bytes)
        .unwrap();

    // 3. Derive the PoPowHeader through the persisted accessor.
    let popow = store
        .popow_header_by_id(&header_id)
        .unwrap()
        .expect("popow_header_by_id returns Some after inserting header + extension");

    // 4. The derived PoPowHeader must carry the same header back
    //    and have non-empty interlinks (h=2's extension has 1
    //    interlink field pointing to genesis).
    assert_eq!(popow.header, header);
    assert_eq!(
        popow.interlinks.len(),
        1,
        "h=2 interlinks vector is [genesis_id]"
    );
    assert!(
        !popow.interlinks_proof.is_empty(),
        "interlinks proof bytes present"
    );

    // 5. The built-in interlinks proof must validate against the
    //    verifier's reconstructed root — the full e2e Scala-parity
    //    contract from `PoPowHeader.checkInterlinksProof`.
    assert!(
        check_popow_header_interlinks_proof(&popow),
        "persisted accessor must yield a verifier-valid PoPowHeader",
    );
}

#[test]
fn popow_header_by_id_missing_header_returns_none() {
    // No store inserts → lookup must return Ok(None).
    let (_tmp, store) = open_store();
    let bogus_id = [0u8; 32];
    let result = store.popow_header_by_id(&bogus_id).unwrap();
    assert!(result.is_none());
}

#[test]
fn popow_header_by_id_missing_extension_returns_none() {
    // Insert only the header — extension is absent. Accessor must
    // return Ok(None) without panicking.
    let (_tmp, store) = open_store();
    let block = load_block(2);
    let header_id: [u8; 32] = hex::decode(&block.header_id).unwrap().try_into().unwrap();
    let header_bytes = load_header_bytes(2);
    store.store_header(&header_id, &header_bytes).unwrap();

    let result = store.popow_header_by_id(&header_id).unwrap();
    assert!(
        result.is_none(),
        "missing extension must surface as None, not Err or panic",
    );
}

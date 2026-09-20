use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::{extension_root, merkle_tree_root};
use ergo_primitives::reader::VlqReader;
use ergo_ser::header::{read_header, Header};
use ergo_ser::transaction::read_transaction;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct BlockVector {
    height: u32,
    transactions: Vec<TxVector>,
    #[serde(default)]
    extension: Option<ExtensionVector>,
}

#[derive(Deserialize)]
struct ExtensionVector {
    digest: String,
    fields: Vec<(String, String)>,
}

#[derive(Deserialize)]
struct TxVector {
    id: String,
    bytes: String,
}

#[derive(Deserialize)]
struct HeaderVector {
    height: u32,
    bytes: String,
}

fn load_blocks(path: &str) -> Vec<BlockVector> {
    let data = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&data).unwrap()
}

fn load_headers_map(path: &str) -> HashMap<u32, Header> {
    let data = std::fs::read_to_string(path).unwrap();
    let vectors: Vec<HeaderVector> = serde_json::from_str(&data).unwrap();
    vectors
        .into_iter()
        .map(|v| {
            let bytes = hex::decode(&v.bytes).unwrap();
            let mut r = VlqReader::new(&bytes);
            (v.height, read_header(&mut r).unwrap())
        })
        .collect()
}

fn witness_id(tx_bytes: &[u8]) -> Vec<u8> {
    let mut reader = VlqReader::new(tx_bytes);
    let tx = read_transaction(&mut reader).unwrap();
    let mut all_proofs = Vec::new();
    for input in &tx.inputs {
        all_proofs.extend_from_slice(&input.spending_proof.proof);
    }
    let hash = blake2b256(&all_proofs);
    hash[1..].to_vec() // 31 bytes
}

fn tx_id_from_bytes(tx_bytes: &[u8]) -> [u8; 32] {
    let mut reader = VlqReader::new(tx_bytes);
    let tx = read_transaction(&mut reader).unwrap();
    let bts = ergo_ser::transaction::bytes_to_sign(&tx).unwrap();
    blake2b256(&bts)
}

fn verify_transactions_root(block: &BlockVector, header: &Header) {
    assert_eq!(block.height, header.height);

    let tx_ids: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|tv| {
            let tx_bytes = hex::decode(&tv.bytes).unwrap();
            let computed = tx_id_from_bytes(&tx_bytes);
            let expected = hex::decode(&tv.id).unwrap();
            assert_eq!(computed.as_slice(), expected.as_slice());
            computed
        })
        .collect();

    let tx_id_slices: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();

    let root = if header.version == 1 {
        merkle_tree_root(&tx_id_slices)
    } else {
        let witness_ids: Vec<Vec<u8>> = block
            .transactions
            .iter()
            .map(|tv| witness_id(&hex::decode(&tv.bytes).unwrap()))
            .collect();
        let witness_slices: Vec<&[u8]> = witness_ids.iter().map(|w| w.as_slice()).collect();
        let mut all_leaves = tx_id_slices;
        all_leaves.extend(witness_slices);
        merkle_tree_root(&all_leaves)
    };

    assert_eq!(
        root,
        *header.transactions_root.as_bytes(),
        "transactionsRoot mismatch at height {}: computed={}, expected={}",
        block.height,
        hex::encode(root),
        hex::encode(header.transactions_root.as_bytes())
    );
}

#[test]
fn transactions_root_blocks_1_5() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_1_5.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");

    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_transactions_root(block, header);
        eprintln!(
            "OK: height {} ({} txs)",
            block.height,
            block.transactions.len()
        );
    }
    eprintln!("{} blocks verified", blocks.len());
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn transactions_root_blocks_700000_700010() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");

    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_transactions_root(block, header);
        eprintln!(
            "OK: height {} ({} txs, v{})",
            block.height,
            block.transactions.len(),
            header.version
        );
    }
    eprintln!("{} v2 blocks verified", blocks.len());
}

fn verify_extension_root(block: &BlockVector, _header: &Header) {
    let ext = block
        .extension
        .as_ref()
        .unwrap_or_else(|| panic!("no extension for block at height {}", block.height));
    let fields: Vec<(Vec<u8>, Vec<u8>)> = ext
        .fields
        .iter()
        .map(|(k, v)| (hex::decode(k).unwrap(), hex::decode(v).unwrap()))
        .collect();
    let field_refs: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let computed = extension_root(&field_refs);
    let expected = hex::decode(&ext.digest).unwrap();
    assert_eq!(
        computed,
        expected.as_slice(),
        "extension root mismatch at height {}: computed={}, expected={}",
        block.height,
        hex::encode(computed),
        ext.digest,
    );
}

#[test]
fn extension_root_blocks_1_5() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_1_5.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_1_2000.json");

    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_extension_root(block, header);
        let nfields = block
            .extension
            .as_ref()
            .map(|e| e.fields.len())
            .unwrap_or(0);
        eprintln!("OK: height {} ({} ext fields)", block.height, nfields);
    }
    eprintln!("{} blocks extension root verified", blocks.len());
}

#[test]
#[ignore = "needs gitignored headers_700000_700500.json — extract via test-vectors/scripts then run with --ignored"]
fn extension_root_blocks_700000_700010() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_700000_700010.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_700000_700500.json");

    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_extension_root(block, header);
        let nfields = block
            .extension
            .as_ref()
            .map(|e| e.fields.len())
            .unwrap_or(0);
        eprintln!(
            "OK: height {} ({} ext fields, v{})",
            block.height, nfields, header.version
        );
    }
    eprintln!("{} v2 blocks extension root verified", blocks.len());
}

#[test]
#[ignore = "needs gitignored headers_417785_417800.json — extract via test-vectors/scripts then run with --ignored"]
fn extension_root_blocks_417785_417800() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_417785_417800.json");
    let headers = load_headers_map("../test-vectors/mainnet/headers_417785_417800.json");
    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_extension_root(block, header);
    }
    eprintln!("{} v1→v2 blocks extension root verified", blocks.len());
}

#[test]
#[ignore = "needs gitignored headers_843000_844672.json + headers_844673_846000.json — extract via test-vectors/scripts then run with --ignored"]
fn extension_root_blocks_844665_844680() {
    let blocks = load_blocks("../test-vectors/mainnet/blocks_844665_844680.json");
    let mut headers = load_headers_map("../test-vectors/mainnet/headers_843000_844672.json");
    headers.extend(load_headers_map(
        "../test-vectors/mainnet/headers_844673_846000.json",
    ));
    for block in &blocks {
        let header = headers
            .get(&block.height)
            .unwrap_or_else(|| panic!("no header for height {}", block.height));
        verify_extension_root(block, header);
    }
    eprintln!("{} EIP-37 blocks extension root verified", blocks.len());
}

/// The block-level `transactionsRoot` is built over the CANONICAL transaction
/// ids, so a transaction whose input extension arrives on the wire as the
/// `TrueLeaf` opcode (`01017f`) contributes the same leaf as the one carrying
/// the canonical constant (`01010101`): Scala's `ErgoLikeTransaction.id`
/// hashes `bytesToSign`, which re-serializes the parsed extension. The oracle
/// (`scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala`,
/// `BlockTransactions(hdr, version 3, Seq(tx)).digest`) reports one root for
/// both encodings; the witness leaf is the same on both sides (no proofs).
///
/// Vector: `test-vectors/scala/canonical_extension_and_group_element.json`.
#[test]
fn transactions_root_over_wire_true_leaf_extension_matches_canonical_scala_root() {
    use ergo_ser::transaction::transaction_id;
    const IN: &str = "01010101010101010101010101010101010101010101010101010101010101010100";
    const OUT: &str = "000001c0843d10010101d17300000000";
    const EXPECTED_ROOT: &str = "bdb0ebec0e29bdabb8187b34fc57c29051a39d3f6cb3b6014e5c98157d25b3fe";

    for ext in ["01017f", "01010101"] {
        let tx_bytes = hex::decode(format!("{IN}{ext}{OUT}")).unwrap();
        let mut reader = VlqReader::new(&tx_bytes);
        let tx = read_transaction(&mut reader).unwrap();
        let tx_id = transaction_id(&tx).unwrap();
        let witness = witness_id(&tx_bytes);
        // Block version 3: tx-id leaves followed by witness-id leaves.
        let leaves: Vec<&[u8]> = vec![tx_id.as_bytes(), witness.as_slice()];
        assert_eq!(
            hex::encode(merkle_tree_root(&leaves)),
            EXPECTED_ROOT,
            "extension wire form {ext}: transactionsRoot must match the JVM",
        );
    }
}

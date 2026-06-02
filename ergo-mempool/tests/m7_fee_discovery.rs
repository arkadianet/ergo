//! Diagnostic: find the miner-fee proposition by scanning mainnet tx
//! output trees across our 1761k corpus. The fee output appears ~1x
//! per tx, so the tree with occurrence count ≈ tx count is the fee
//! proposition. Run once with `--ignored --nocapture` and hardcode
//! the result in `ergo-validation::fee_proposition_bytes`.

use std::collections::HashMap;

use ergo_primitives::reader::VlqReader;
use ergo_ser::transaction::read_transaction;

#[derive(serde::Deserialize)]
struct TxVector {
    bytes: String,
}

#[test]
#[ignore = "diagnostic only; run with --ignored"]
fn find_fee_proposition_by_frequency() {
    let data = std::fs::read_to_string("../test-vectors/mainnet/transactions_1761000_1762000.json")
        .expect("fixture not found");
    let txs: Vec<TxVector> = serde_json::from_str(&data).unwrap();
    let tx_count = txs.len();

    let mut freq: HashMap<Vec<u8>, u32> = HashMap::new();
    for v in txs.iter().take(500) {
        let bytes = hex::decode(&v.bytes).unwrap();
        let mut r = VlqReader::new(&bytes);
        let tx = read_transaction(&mut r).unwrap();
        for out in &tx.output_candidates {
            *freq.entry(out.ergo_tree_bytes().to_vec()).or_default() += 1;
        }
    }

    let mut ranked: Vec<(Vec<u8>, u32)> = freq.into_iter().collect();
    ranked.sort_by_key(|b| std::cmp::Reverse(b.1));

    eprintln!("\n[fee-discovery] sampled 500 of {tx_count} txs");
    eprintln!("[fee-discovery] top 10 output ergo_tree_bytes:");
    for (bytes, count) in ranked.iter().take(10) {
        eprintln!("  {count:4}  len={:3}  {}", bytes.len(), hex::encode(bytes));
    }
}

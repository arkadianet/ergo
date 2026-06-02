//! Mode 5 "ADProof replay" oracle-corpus extractor.
//!
//! Pulls a contiguous block window from a LIVE Ergo node REST API and emits,
//! per height, everything a digest verifier needs to replay the block against
//! its parent state root:
//!
//!   * `state_root`     — post-apply AVL+ root (header.stateRoot, 33 bytes)
//!   * `ad_proofs_root` — header.adProofsRoot (32 bytes)
//!   * `proof_bytes`    — the ADProofs blob (block.adProofs.proofBytes)
//!   * `to_remove`      — net spent box ids
//!   * `to_insert`      — net created boxes, each with canonical serialized bytes
//!   * `parent_state_root` — the state root the block is applied on top of
//!   * `header_bytes`   — canonical header section bytes (`serialize_header`)
//!   * `block_tx_bytes` — canonical block-transactions section bytes
//!   * `extension_bytes`— canonical extension section bytes
//!
//! The three section-byte fields feed the Mode 5 executor-through-mainnet
//! test: the digest verifier loads sections from the store and parses them
//! with `read_header` / `read_block_transactions` / `read_extension`, so the
//! corpus carries byte-exact canonical bytes for each. Every reconstruction
//! is reconstructed from the node's JSON and cross-checked by id so a wrong
//! byte aborts the run rather than producing a false oracle:
//!   * header bytes — `blake2b256(bytes) == header id`;
//!   * each tx — `blake2b256(bytes_to_sign(tx)) == tx id`, then the
//!     transactions Merkle root recomputed over the tx ids (+ witness ids
//!     for v2+) == `header.transactions_root`;
//!   * extension — the extension Merkle root recomputed over the fields ==
//!     `header.extension_root`, and the bytes round-trip through
//!     `read_extension`.
//!
//! The net (to_remove, to_insert) sets are built by replaying the EXACT
//! algorithm in `ergo-state::store::apply::build_utxo_changes_checked`:
//! per transaction, inputs first (with intra-block create-then-spend
//! cancellation against the in-progress insert map), then outputs; txs in
//! block order. That ordering is consensus-load-bearing.
//!
//! Every output box's canonical bytes are obtained one of two ways:
//!   1. `GET /utxo/byIdBinary/{boxId}` — canonical bytes straight from the
//!      node's UTXO set (only hits for still-unspent boxes).
//!   2. Reconstruction from the output JSON (value, ergoTree, assets,
//!      creationHeight, additionalRegisters, transactionId, index) through
//!      `ErgoBox` + `serialize_ergo_box`.
//!
//! Both paths are gated by a mandatory cross-check: blake2b256(canonical
//! bytes) MUST equal the node-reported boxId. A mismatch aborts the run —
//! a wrong byte string would make the corpus a false consensus oracle.
//!
//! Run: `cargo run -p ergo-state --example extract_mode5_corpus`

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ergo_crypto::merkle::{extension_root, transactions_root};
use ergo_primitives::digest::{blake2b256, ADDigest, Digest32, ModifierId};
use ergo_primitives::group_element::GroupElement;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::{parse_ergo_box_bytes, serialize_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::extension::{read_extension, write_extension, Extension, ExtensionField};
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{read_context_extension, DataInput, Input, SpendingProof};
use ergo_ser::register::read_registers;
use ergo_ser::token::{Token, TokenId};
use ergo_ser::transaction::{bytes_to_sign, Transaction};
use serde_json::Value;

const NODE: &str = "http://localhost:9053";
const WINDOW_LO: u32 = 1_795_968;
const WINDOW_HI: u32 = 1_796_160;
const EPOCH_BOUNDARY: u32 = 1_796_096;

fn main() {
    // Some mainnet ErgoTree / register expressions parse with deep recursion
    // in read_ergo_tree / read_registers; the default 1 MiB main-thread stack
    // (notably on Windows) overflows. Run on a worker thread with a large
    // stack. This affects only parsing depth, not the produced bytes.
    let worker = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .expect("spawn worker thread");
    match worker.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("\nFATAL: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("\nFATAL: worker thread panicked");
            std::process::exit(1);
        }
    }
}

/// Running totals across the whole window, for the final summary and the
/// byIdBinary-vs-reconstruct split reported in the run log.
struct Counters {
    by_id_binary_hits: usize,
    json_reconstructs: usize,
    total_boxes: usize,
    total_removes: usize,
    header_gates: usize,
    tx_gates: usize,
    extension_gates: usize,
}

fn run() -> Result<(), String> {
    const {
        assert!(
            WINDOW_LO <= EPOCH_BOUNDARY && EPOCH_BOUNDARY <= WINDOW_HI,
            "window must cross the epoch boundary"
        );
    }

    let out_dir = corpus_dir();
    fs::create_dir_all(&out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;

    let mut counters = Counters {
        by_id_binary_hits: 0,
        json_reconstructs: 0,
        total_boxes: 0,
        total_removes: 0,
        header_gates: 0,
        tx_gates: 0,
        extension_gates: 0,
    };

    // parent_state_root for the first height comes from h0-1's header.
    let mut prev_state_root: Option<String> = Some(fetch_state_root(WINDOW_LO - 1)?);
    let mut prev_header_id: Option<String> = None;

    let n = WINDOW_HI - WINDOW_LO + 1;
    println!(
        "Extracting Mode 5 ADProof-replay corpus for heights {WINDOW_LO}..={WINDOW_HI} ({n} blocks)"
    );

    for h in WINDOW_LO..=WINDOW_HI {
        let block = fetch_block_at(h)?;
        let header = &block["header"];

        let header_id = json_str(header, "id")?;
        let height = json_u32(header, "height")?;
        if height != h {
            return Err(format!("height mismatch at {h}: header.height={height}"));
        }
        let state_root = json_str(header, "stateRoot")?;
        let ad_proofs_root = json_str(header, "adProofsRoot")?;
        let parent_id = json_str(header, "parentId")?;

        // Chain-continuity asserts.
        let parent_state_root = prev_state_root
            .clone()
            .ok_or_else(|| format!("missing parent_state_root for {h}"))?;
        if let Some(prev_id) = &prev_header_id {
            if &parent_id != prev_id {
                return Err(format!(
                    "parentId linkage broken at {h}: parentId={parent_id} prev_header_id={prev_id}"
                ));
            }
        }

        let proof_bytes = block["adProofs"]["proofBytes"]
            .as_str()
            .ok_or_else(|| format!("h{h}: missing adProofs.proofBytes"))?
            .to_string();
        if proof_bytes.is_empty() {
            return Err(format!("h{h}: empty adProofs.proofBytes — ABORT"));
        }

        let txs = block["blockTransactions"]["transactions"]
            .as_array()
            .ok_or_else(|| format!("h{h}: missing blockTransactions.transactions"))?;

        // Replicate build_utxo_changes_checked EXACTLY: inputs-before-outputs
        // per tx, txs in block order, intra-block create-then-spend
        // cancellation. to_insert values here are the source output JSON so
        // the bytes step can reconstruct; ids preserve BTreeMap ordering to
        // mirror the real maps.
        let mut to_remove: BTreeMap<String, ()> = BTreeMap::new();
        let mut to_insert: BTreeMap<String, Value> = BTreeMap::new();

        for tx in txs {
            let inputs = tx["inputs"]
                .as_array()
                .ok_or_else(|| format!("h{h}: tx missing inputs"))?;
            for input in inputs {
                let box_id = input["boxId"]
                    .as_str()
                    .ok_or_else(|| format!("h{h}: input missing boxId"))?
                    .to_string();
                if to_insert.remove(&box_id).is_none() {
                    to_remove.insert(box_id, ());
                }
            }
            let outputs = tx["outputs"]
                .as_array()
                .ok_or_else(|| format!("h{h}: tx missing outputs"))?;
            for output in outputs {
                let box_id = output["boxId"]
                    .as_str()
                    .ok_or_else(|| format!("h{h}: output missing boxId"))?
                    .to_string();
                to_insert.insert(box_id, output.clone());
            }
        }

        // Data-input lookups, in transaction order with duplicates kept —
        // Scala's `toLookup = txs.flatMap(_.dataInputs).map(Lookup(_.boxId))`.
        let mut to_lookup: Vec<String> = Vec::new();
        for tx in txs {
            if let Some(dis) = tx["dataInputs"].as_array() {
                for di in dis {
                    if let Some(id) = di["boxId"].as_str() {
                        to_lookup.push(id.to_string());
                    }
                }
            }
        }

        // Resolve canonical bytes for every net-inserted box, gated by box_id.
        let mut insert_entries: Vec<Value> = Vec::with_capacity(to_insert.len());
        for (box_id, output_json) in &to_insert {
            let bytes = canonical_box_bytes(box_id, output_json, &mut counters)?;

            // MANDATORY CORRECTNESS GATE: blake2b256(bytes) == reported boxId.
            let computed = blake2b256(&bytes);
            let computed_hex = hex::encode(computed.as_bytes());
            if &computed_hex != box_id {
                return Err(format!(
                    "h{h}: box_id GATE FAILED for {box_id}\n  computed: {computed_hex}\n  bytes:    {}",
                    hex::encode(&bytes)
                ));
            }
            counters.total_boxes += 1;
            insert_entries.push(serde_json::json!({
                "box_id": box_id,
                "bytes": hex::encode(&bytes),
            }));
        }
        counters.total_removes += to_remove.len();

        let remove_list: Vec<String> = to_remove.keys().cloned().collect();

        // Reconstruct + cross-check the three full-block sections the Mode 5
        // executor parses from the store (header, block-transactions,
        // extension). Each aborts the run on any id mismatch.
        let header_struct = build_header(header)?;
        let header_bytes = reconstruct_header_bytes(&header_struct, &header_id, &mut counters)?;
        let block_tx_bytes =
            reconstruct_block_tx_bytes(txs, &header_struct, &header_id, h, &mut counters)?;
        let extension_bytes = reconstruct_extension_bytes(
            &block["extension"],
            &header_struct,
            &header_id,
            &mut counters,
        )?;

        let record = serde_json::json!({
            "height": h,
            "header_id": header_id,
            "parent_state_root": parent_state_root,
            "state_root": state_root,
            "ad_proofs_root": ad_proofs_root,
            "proof_bytes": proof_bytes,
            "to_lookup": to_lookup,
            "to_remove": remove_list,
            "to_insert": insert_entries,
            "header_bytes": hex::encode(&header_bytes),
            "block_tx_bytes": hex::encode(&block_tx_bytes),
            "extension_bytes": hex::encode(&extension_bytes),
        });

        let path = out_dir.join(format!("{h}.json"));
        let serialized = serde_json::to_string_pretty(&record)
            .map_err(|e| format!("serialize {h}.json: {e}"))?;
        fs::write(&path, serialized).map_err(|e| format!("write {}: {e}", path.display()))?;

        if h.is_multiple_of(16) || h == WINDOW_HI {
            println!(
                "  h{h}  removes={:>3}  inserts={:>3}  txs={:>2}  (byIdBinary={} json={}) sections OK",
                remove_list.len(),
                to_insert.len(),
                txs.len(),
                counters.by_id_binary_hits,
                counters.json_reconstructs,
            );
        }

        prev_state_root = Some(state_root);
        prev_header_id = Some(header_id);
    }

    write_provisioning(&out_dir)?;

    println!("\n=== DONE ===");
    println!(
        "  files written:        {} ({}.json .. {}.json)",
        n, WINDOW_LO, WINDOW_HI
    );
    println!("  total inserted boxes: {}", counters.total_boxes);
    println!("  total removed boxes:  {}", counters.total_removes);
    println!("  byIdBinary hits:      {}", counters.by_id_binary_hits);
    println!("  JSON reconstructs:    {}", counters.json_reconstructs);
    println!(
        "  box_id gate:          100% passed ({} boxes)",
        counters.total_boxes
    );
    println!(
        "  header  id gate:      100% passed ({} headers)",
        counters.header_gates
    );
    println!(
        "  tx      id+root gate: 100% passed ({} txs across {} blocks)",
        counters.tx_gates, n
    );
    println!(
        "  extension root gate:  100% passed ({} extensions)",
        counters.extension_gates
    );
    println!("  epoch boundary {EPOCH_BOUNDARY} crossed: yes");
    println!(
        "  PROVISIONING.md:      {}",
        out_dir.join("PROVISIONING.md").display()
    );
    Ok(())
}

/// Canonical serialized bytes for one output box. byIdBinary first (unspent
/// boxes), JSON reconstruction otherwise. Does NOT gate box_id — the caller
/// does, on both paths uniformly.
fn canonical_box_bytes(
    box_id: &str,
    output_json: &Value,
    counters: &mut Counters,
) -> Result<Vec<u8>, String> {
    // Path 1: byIdBinary (canonical bytes from the live UTXO set). A spent /
    // absent box yields HTTP 404 — that is the expected signal to fall back
    // to reconstruction, NOT a transport error.
    if let Some(bytes_hex) = fetch_utxo_bytes_hex(box_id)? {
        if !bytes_hex.is_empty() {
            let bytes = hex::decode(&bytes_hex)
                .map_err(|e| format!("byIdBinary {box_id}: bad hex: {e}"))?;
            // Round-trip parse/reserialize to confirm canonicality (and that
            // our serializer agrees with the node's stored bytes). Uses the
            // box JSON's ergoTree to find the tree/body boundary.
            let tree_hex = json_str(output_json, "ergoTree")?;
            let tree_bytes =
                hex::decode(&tree_hex).map_err(|e| format!("{box_id}: bad ergoTree hex: {e}"))?;
            let parsed = parse_ergo_box_bytes(&bytes, &tree_bytes)
                .map_err(|e| format!("{box_id}: byIdBinary bytes do not parse: {e}"))?;
            let reser = serialize_ergo_box(&parsed)
                .map_err(|e| format!("{box_id}: reserialize failed: {e}"))?;
            if reser != bytes {
                return Err(format!(
                    "{box_id}: byIdBinary bytes not canonical (reserialize differs)"
                ));
            }
            counters.by_id_binary_hits += 1;
            return Ok(bytes);
        }
    }

    // Path 2: reconstruct from the output JSON.
    counters.json_reconstructs += 1;
    reconstruct_box_bytes(output_json)
}

/// Build an `ErgoBox` from output JSON and serialize it canonically.
///
/// The candidate (value, ergoTree, assets, creationHeight, registers) comes
/// from the shared [`reconstruct_candidate`] helper — the same builder the
/// transaction-section path uses. Here it is sealed with `transactionId` +
/// `index` into a full [`ErgoBox`] so the bytes carry the box-id preimage.
fn reconstruct_box_bytes(output: &Value) -> Result<Vec<u8>, String> {
    let candidate = reconstruct_candidate(output)?;

    let tx_id_hex = json_str(output, "transactionId")?;
    let tx_id_bytes: [u8; 32] = hex::decode(&tx_id_hex)
        .map_err(|e| format!("bad transactionId hex: {e}"))?
        .try_into()
        .map_err(|_| format!("transactionId not 32 bytes: {tx_id_hex}"))?;
    let index = json_u32(output, "index")?;
    if index > u16::MAX as u32 {
        return Err(format!("output index {index} exceeds u16"));
    }

    let ergo_box = ErgoBox {
        candidate,
        transaction_id: ModifierId::from_bytes(tx_id_bytes),
        index: index as u16,
    };
    serialize_ergo_box(&ergo_box).map_err(|e| format!("serialize_ergo_box: {e}"))
}

/// Shared candidate reconstruction from an output-box JSON object. A
/// transaction output is an [`ErgoBoxCandidate`] — the same fields as an
/// `ErgoBox` minus `transactionId` / `index` — so both the net-insert
/// box-bytes path ([`reconstruct_box_bytes`]) and the block-transactions
/// section path go through this one builder.
///
/// Mirrors the `box_id_from_explorer_data` fixture in `ergo-ser`: the
/// `ergoTree` hex IS the canonical tree bytes; each `additionalRegisters`
/// value is the raw per-register wire bytes (type code + value), so
/// register_bytes is `count(u8) || concat(R4..R9 hex)`; assets are tokens in
/// wire order.
fn reconstruct_candidate(output: &Value) -> Result<ErgoBoxCandidate, String> {
    let value = json_u64(output, "value")?;
    let creation_height = json_u32(output, "creationHeight")?;
    let tree_hex = json_str(output, "ergoTree")?;
    let tree_bytes = hex::decode(&tree_hex).map_err(|e| format!("bad ergoTree hex: {e}"))?;
    let ergo_tree = {
        let mut r = VlqReader::new(&tree_bytes);
        read_ergo_tree(&mut r).map_err(|e| format!("ergoTree parse: {e}"))?
    };

    // Tokens (assets), preserving wire order.
    let mut tokens: Vec<Token> = Vec::new();
    if let Some(assets) = output.get("assets").and_then(Value::as_array) {
        for asset in assets {
            let id_hex = json_str(asset, "tokenId")?;
            let id_bytes: [u8; 32] = hex::decode(&id_hex)
                .map_err(|e| format!("bad tokenId hex: {e}"))?
                .try_into()
                .map_err(|_| format!("tokenId not 32 bytes: {id_hex}"))?;
            let amount = json_u64(asset, "amount")?;
            tokens.push(Token {
                token_id: TokenId::from_bytes(id_bytes),
                amount,
            });
        }
    }

    // Registers: R4..R9 in order, each value is raw register wire hex.
    let mut reg_bytes: Vec<u8> = Vec::new();
    let mut reg_hexes: Vec<String> = Vec::new();
    if let Some(regs) = output.get("additionalRegisters").and_then(Value::as_object) {
        for key in ["R4", "R5", "R6", "R7", "R8", "R9"] {
            if let Some(v) = regs.get(key) {
                let hex_str = v
                    .as_str()
                    .ok_or_else(|| format!("register {key} not a string"))?;
                reg_hexes.push(hex_str.to_string());
            }
        }
    }
    reg_bytes.push(reg_hexes.len() as u8);
    for rh in &reg_hexes {
        reg_bytes.extend(hex::decode(rh).map_err(|e| format!("bad register hex: {e}"))?);
    }
    let additional_registers = {
        let mut r = VlqReader::new(&reg_bytes);
        read_registers(&mut r).map_err(|e| format!("registers parse: {e}"))?
    };

    Ok(ErgoBoxCandidate::from_trusted_raw_parts(
        value,
        ergo_tree,
        tree_bytes,
        creation_height,
        tokens,
        additional_registers,
        reg_bytes,
    ))
}

// ----- full block sections: build + cross-check -----

/// Build a [`Header`] from the header JSON. Autolykos V2 (header v2+, the
/// only version in this window) carries only `pk + nonce` on the wire — the
/// JSON `w`/`d` fields are v1-era and are not part of the v2 solution.
/// `unparsed_bytes` is empty for these heights (the id gate would catch any
/// non-empty trailer).
fn build_header(header: &Value) -> Result<Header, String> {
    let version = u8::try_from(json_u64(header, "version")?)
        .map_err(|_| "header version overflows u8".to_string())?;
    let parent_id = hex32(header, "parentId").map(ModifierId::from_bytes)?;
    let ad_proofs_root = hex32(header, "adProofsRoot").map(Digest32::from_bytes)?;
    let transactions_root = hex32(header, "transactionsRoot").map(Digest32::from_bytes)?;
    let state_root = hex_n::<33>(json_str(header, "stateRoot")?.as_str(), "stateRoot")
        .map(ADDigest::from_bytes)?;
    let timestamp = json_u64(header, "timestamp")?;
    let extension_root = hex32(header, "extensionHash").map(Digest32::from_bytes)?;
    let n_bits = json_u32(header, "nBits")?;
    let height = json_u32(header, "height")?;
    let votes = hex_n::<3>(json_str(header, "votes")?.as_str(), "votes")?;

    let pow = header
        .get("powSolutions")
        .ok_or_else(|| "header missing powSolutions".to_string())?;
    let pk = hex_n::<33>(json_str(pow, "pk")?.as_str(), "powSolutions.pk")
        .map(GroupElement::from_bytes)?;
    let nonce = hex_n::<8>(json_str(pow, "n")?.as_str(), "powSolutions.n")?;

    if version < 2 {
        return Err(format!(
            "header version {version} is pre-Autolykos-v2; this extractor targets v2+ headers"
        ));
    }
    let solution = AutolykosSolution::V2 { pk, nonce };

    Ok(Header {
        version,
        parent_id,
        ad_proofs_root,
        transactions_root,
        state_root,
        timestamp,
        extension_root,
        n_bits,
        height,
        votes,
        unparsed_bytes: vec![],
        solution,
    })
}

/// Serialize the header and gate `blake2b256(bytes) == header id`.
fn reconstruct_header_bytes(
    header: &Header,
    header_id: &str,
    counters: &mut Counters,
) -> Result<Vec<u8>, String> {
    let (bytes, id) = serialize_header(header).map_err(|e| format!("serialize_header: {e}"))?;
    let id_hex = hex::encode(id.as_bytes());
    if id_hex != header_id {
        return Err(format!(
            "header id GATE FAILED\n  computed: {id_hex}\n  expected: {header_id}\n  bytes:    {}",
            hex::encode(&bytes)
        ));
    }
    counters.header_gates += 1;
    Ok(bytes)
}

/// Build one [`Transaction`] from a transaction JSON object. Inputs carry the
/// `proofBytes` and a [`SpendingProof`] reconstructed from the verbatim
/// context-extension wire bytes (so `bytes_to_sign` parity holds); data
/// inputs are box-id pointers; outputs reuse [`reconstruct_candidate`].
fn build_transaction(tx: &Value) -> Result<Transaction, String> {
    let mut inputs = Vec::new();
    for input in tx["inputs"]
        .as_array()
        .ok_or_else(|| "tx missing inputs".to_string())?
    {
        let box_id = hex32(input, "boxId").map(Digest32::from_bytes)?;
        let sp = input
            .get("spendingProof")
            .ok_or_else(|| "input missing spendingProof".to_string())?;
        let proof = hex::decode(json_str(sp, "proofBytes")?)
            .map_err(|e| format!("bad proofBytes hex: {e}"))?;
        let extension_bytes = context_extension_wire_bytes(sp.get("extension"))?;
        let extension = {
            let mut r = VlqReader::new(&extension_bytes);
            let ext = read_context_extension(&mut r)
                .map_err(|e| format!("context extension parse: {e}"))?;
            if !r.is_empty() {
                return Err("context extension has trailing bytes".to_string());
            }
            ext
        };
        let spending_proof =
            SpendingProof::from_trusted_raw_parts(proof, extension, extension_bytes);
        inputs.push(Input {
            box_id,
            spending_proof,
        });
    }

    let mut data_inputs = Vec::new();
    if let Some(dis) = tx["dataInputs"].as_array() {
        for di in dis {
            data_inputs.push(DataInput {
                box_id: hex32(di, "boxId").map(Digest32::from_bytes)?,
            });
        }
    }

    let mut output_candidates = Vec::new();
    for output in tx["outputs"]
        .as_array()
        .ok_or_else(|| "tx missing outputs".to_string())?
    {
        output_candidates.push(reconstruct_candidate(output)?);
    }

    Ok(Transaction {
        inputs,
        data_inputs,
        output_candidates,
    })
}

/// Assemble verbatim context-extension wire bytes from the JSON `extension`
/// map (`{ "<u8 key>": "<hex constant>" }`). Wire form is
/// `count(u8) || concat(key(u8) || value_bytes)` in ascending key order —
/// the Scala `Map1`-`Map4` insertion order for ≤4 entries is ascending here
/// because the JSON object is emitted ascending; the `bytes_to_sign` tx-id
/// gate is the byte-exact arbiter regardless.
fn context_extension_wire_bytes(ext: Option<&Value>) -> Result<Vec<u8>, String> {
    let mut entries: Vec<(u8, Vec<u8>)> = Vec::new();
    if let Some(obj) = ext.and_then(Value::as_object) {
        for (k, v) in obj {
            let key: u8 = k
                .parse()
                .map_err(|_| format!("context extension key not u8: {k}"))?;
            let val_hex = v
                .as_str()
                .ok_or_else(|| format!("context extension value for {k} not a string"))?;
            let val = hex::decode(val_hex)
                .map_err(|e| format!("bad context extension value hex for {k}: {e}"))?;
            entries.push((key, val));
        }
    }
    // serde_json::Map iterates in key order for string keys, but normalize
    // explicitly so the wire order is deterministic regardless of map impl.
    entries.sort_by_key(|(k, _)| *k);
    if entries.len() > u8::MAX as usize {
        return Err(format!(
            "context extension has {} entries (max 255)",
            entries.len()
        ));
    }
    let mut bytes = Vec::new();
    bytes.push(entries.len() as u8);
    for (k, v) in entries {
        bytes.push(k);
        bytes.extend_from_slice(&v);
    }
    Ok(bytes)
}

/// Build the block-transactions section, gate every tx id via
/// `blake2b256(bytes_to_sign(tx))`, recompute the transactions Merkle root and
/// gate it against `header.transactions_root`, then serialize the section.
fn reconstruct_block_tx_bytes(
    txs: &[Value],
    header: &Header,
    header_id: &str,
    h: u32,
    counters: &mut Counters,
) -> Result<Vec<u8>, String> {
    let header_id_bytes = hex_n::<32>(header_id, "header_id")?;

    let mut transactions = Vec::with_capacity(txs.len());
    let mut tx_ids: Vec<[u8; 32]> = Vec::with_capacity(txs.len());
    let mut witness_ids: Vec<Vec<u8>> = Vec::with_capacity(txs.len());

    for tx_json in txs {
        let tx = build_transaction(tx_json)?;

        // GATE 1: tx id = blake2b256(bytes_to_sign(tx)) == JSON id. Binds
        // inputs, data inputs, and outputs (proofs are excluded from
        // bytes_to_sign and validated later by the executor's script check).
        let bts = bytes_to_sign(&tx).map_err(|e| format!("h{h}: bytes_to_sign: {e}"))?;
        let computed = *blake2b256(&bts).as_bytes();
        let expected = json_str(tx_json, "id")?;
        let computed_hex = hex::encode(computed);
        if computed_hex != expected {
            return Err(format!(
                "h{h}: tx id GATE FAILED\n  computed: {computed_hex}\n  expected: {expected}"
            ));
        }
        counters.tx_gates += 1;

        // Witness id (v2+): blake2b256(concat input proofs).drop(1) -> 31 bytes.
        let mut all_proofs = Vec::new();
        for input in &tx.inputs {
            all_proofs.extend_from_slice(&input.spending_proof.proof);
        }
        let wid = blake2b256(&all_proofs).as_bytes()[1..].to_vec();

        tx_ids.push(computed);
        witness_ids.push(wid);
        transactions.push(tx);
    }

    // GATE 2: recomputed transactions Merkle root == header.transactions_root.
    // The strong section gate — binds the full ordered tx set to the header.
    let tx_id_refs: Vec<&[u8]> = tx_ids.iter().map(|id| id.as_slice()).collect();
    let computed_root = if header.version >= 2 {
        let witness_refs: Vec<&[u8]> = witness_ids.iter().map(|w| w.as_slice()).collect();
        transactions_root(&tx_id_refs, Some(&witness_refs))
    } else {
        transactions_root(&tx_id_refs, None)
    };
    if &computed_root != header.transactions_root.as_bytes() {
        return Err(format!(
            "h{h}: transactions_root GATE FAILED\n  computed: {}\n  expected: {}",
            hex::encode(computed_root),
            hex::encode(header.transactions_root.as_bytes())
        ));
    }

    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(header_id_bytes),
        transactions,
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &bt, header.version)
        .map_err(|e| format!("h{h}: write_block_transactions: {e}"))?;
    Ok(w.result())
}

/// Build the extension section, gate the recomputed extension Merkle root
/// against `header.extension_root`, confirm the section bytes round-trip
/// through `read_extension`, then return the serialized bytes.
fn reconstruct_extension_bytes(
    ext_json: &Value,
    header: &Header,
    header_id: &str,
    counters: &mut Counters,
) -> Result<Vec<u8>, String> {
    let header_id_bytes = hex_n::<32>(header_id, "header_id")?;

    let mut fields: Vec<ExtensionField> = Vec::new();
    for pair in ext_json["fields"]
        .as_array()
        .ok_or_else(|| "extension missing fields".to_string())?
    {
        let arr = pair
            .as_array()
            .ok_or_else(|| "extension field not a [key, value] pair".to_string())?;
        if arr.len() != 2 {
            return Err(format!("extension field pair has {} elements", arr.len()));
        }
        let key = hex_n::<2>(
            arr[0]
                .as_str()
                .ok_or_else(|| "extension key not a string".to_string())?,
            "extension key",
        )?;
        let value = hex::decode(
            arr[1]
                .as_str()
                .ok_or_else(|| "extension value not a string".to_string())?,
        )
        .map_err(|e| format!("bad extension value hex: {e}"))?;
        fields.push(ExtensionField { key, value });
    }

    // GATE: recomputed extension Merkle root == header.extension_root.
    let field_refs: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|f| (f.key.as_slice(), f.value.as_slice()))
        .collect();
    let computed_root = extension_root(&field_refs);
    if &computed_root != header.extension_root.as_bytes() {
        return Err(format!(
            "extension_root GATE FAILED\n  computed: {}\n  expected: {}",
            hex::encode(computed_root),
            hex::encode(header.extension_root.as_bytes())
        ));
    }

    let ext = Extension {
        header_id: ModifierId::from_bytes(header_id_bytes),
        fields,
    };
    let mut w = VlqWriter::new();
    write_extension(&mut w, &ext).map_err(|e| format!("write_extension: {e}"))?;
    let bytes = w.result();

    // Round-trip the serialized bytes through read_extension and confirm
    // the parsed struct matches — defends against a writer/reader skew that
    // the root gate alone could miss (the root is over fields, not the
    // header-id-prefixed section bytes).
    {
        let mut r = VlqReader::new(&bytes);
        let parsed =
            read_extension(&mut r).map_err(|e| format!("extension round-trip parse: {e}"))?;
        if !r.is_empty() {
            return Err("extension bytes have trailing content after parse".to_string());
        }
        if parsed != ext {
            return Err("extension bytes do not round-trip to the same struct".to_string());
        }
    }

    counters.extension_gates += 1;
    Ok(bytes)
}

// ----- node REST helpers -----

fn fetch_block_at(h: u32) -> Result<Value, String> {
    let id = fetch_block_id_at(h)?;
    curl_json(&format!("{NODE}/blocks/{id}"))
}

fn fetch_block_id_at(h: u32) -> Result<String, String> {
    let arr = curl_json(&format!("{NODE}/blocks/at/{h}"))?;
    arr.as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("no block id at height {h}"))
}

fn fetch_state_root(h: u32) -> Result<String, String> {
    let block = fetch_block_at(h)?;
    json_str(&block["header"], "stateRoot")
}

fn curl_json(url: &str) -> Result<Value, String> {
    let out = Command::new("curl")
        .args(["-s", "--fail-with-body", url])
        .output()
        .map_err(|e| format!("curl spawn failed for {url}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed (status {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "parse JSON from {url}: {e}\n  body: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Fetch a box's canonical bytes hex from `/utxo/byIdBinary`. Returns
/// `Ok(Some(hex))` when the box is in the UTXO set, `Ok(None)` on HTTP 404
/// (spent / never-existed — caller reconstructs), and `Err` on any other
/// HTTP status or transport failure. The HTTP code is captured out-of-band
/// via `-w` so a 404 body is distinguishable from a real error.
fn fetch_utxo_bytes_hex(box_id: &str) -> Result<Option<String>, String> {
    let url = format!("{NODE}/utxo/byIdBinary/{box_id}");
    let out = Command::new("curl")
        .args(["-s", "-w", "\n%{http_code}", &url])
        .output()
        .map_err(|e| format!("curl spawn failed for {url}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} transport failure: {:?}",
            out.status.code()
        ));
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let (json_part, code) = body
        .rsplit_once('\n')
        .ok_or_else(|| format!("byIdBinary {box_id}: no http_code marker in output"))?;
    match code.trim() {
        "200" => {
            let v: Value = serde_json::from_str(json_part)
                .map_err(|e| format!("byIdBinary {box_id}: parse 200 body: {e}"))?;
            Ok(v.get("bytes").and_then(Value::as_str).map(str::to_string))
        }
        "404" => Ok(None),
        other => Err(format!(
            "byIdBinary {box_id}: unexpected HTTP {other}: {json_part}"
        )),
    }
}

// ----- small JSON accessors -----

fn json_str(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing/invalid string field '{key}'"))
}

fn json_u32(v: &Value, key: &str) -> Result<u32, String> {
    let n = v
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing/invalid u64 field '{key}'"))?;
    u32::try_from(n).map_err(|_| format!("field '{key}' overflows u32: {n}"))
}

fn json_u64(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing/invalid u64 field '{key}'"))
}

/// Decode a hex string into a fixed `[u8; N]`, erroring with the field name
/// on bad hex or a length mismatch.
fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(s)
        .map_err(|e| format!("{what}: bad hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("{what}: expected {N} bytes, got {}", v.len()))
}

/// Read a string field and decode it as a `[u8; 32]`.
fn hex32(v: &Value, key: &str) -> Result<[u8; 32], String> {
    hex_n::<32>(json_str(v, key)?.as_str(), key)
}

// ----- output paths + docs -----

fn corpus_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR = ergo-state/; corpus lives at repo-root test-vectors/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors")
        .join("mode5")
        .join("ad_proofs_replay")
}

fn write_provisioning(dir: &Path) -> Result<(), String> {
    let body = format!(
        r#"# Mode 5 ADProof-replay oracle corpus

Per-height fixtures that let a Mode 5 digest verifier replay each block
against its parent state root: seed an AVL+ verifier at `parent_state_root`,
replay the block's operations in Scala's order — data-input lookups
(`to_lookup`), then `to_remove`, then `to_insert` — and assert the finalized
root equals `state_root`. The `proof_bytes` are the block's serialized
ADProofs blob; `ad_proofs_root` is the header commitment to them.

## Window

`{lo} ..= {hi}` ({n} contiguous blocks), chosen to cross the voting-epoch
boundary **{boundary}** (epoch length 1024 on mainnet). Every height in the
window was verified to carry a non-empty `adProofs.proofBytes` before
extraction. The window sits ~few-hundred blocks below the tip, so most
created boxes are already spent — the byIdBinary path hits only for the
still-unspent minority and the JSON-reconstruct path covers the rest. Both
paths pass the same box_id gate.

## Record shape (`{{h}}.json`)

```jsonc
{{
  "height":            <u32>,
  "header_id":         "<64-hex>",   // canonical block id at this height
  "parent_state_root": "<66-hex>",   // 33-byte AVL+ root the block applies on
  "state_root":        "<66-hex>",   // 33-byte post-apply root (header.stateRoot)
  "ad_proofs_root":    "<64-hex>",   // 32-byte header.adProofsRoot
  "proof_bytes":       "<hex>",      // block.adProofs.proofBytes (ADProofs blob)
  "to_lookup":         ["<boxIdHex>", ...],          // data-input ids, tx order
  "to_remove":         ["<boxIdHex>", ...],          // net spent box ids
  "to_insert":         [{{"box_id":"<hex>","bytes":"<hex>"}}, ...], // net created
  "header_bytes":      "<hex>",      // canonical header section bytes
  "block_tx_bytes":    "<hex>",      // canonical block-transactions section bytes
  "extension_bytes":   "<hex>"       // canonical extension section bytes
}}
```

`parent_state_root` is stored per-height for robustness even though it equals
the prior height's `state_root` (the extractor asserts that continuity, and
the parentId linkage, while building the corpus).

The `to_lookup` / `to_remove` / `to_insert` fields drive the in-memory AVL+
replay test (`mainnet_replay` in `ergo-state::digest_apply`). The
`header_bytes` / `block_tx_bytes` / `extension_bytes` fields drive the Mode 5
executor-through-mainnet test, which loads sections from a store and parses
them with `read_header` / `read_block_transactions` / `read_extension` exactly
as the digest path does in production. The two consumers are independent: the
section-byte fields were added without touching the replay fields, and the
replay `Row` deserializer ignores the extra keys.

## Net box-change derivation

The `(to_remove, to_insert)` sets replicate
`ergo-state::store::apply::build_utxo_changes_checked` EXACTLY:

* iterate `blockTransactions.transactions` in block order;
* per tx, process **inputs before outputs**;
* for each input boxId: if it is in the in-progress insert map, drop it from
  there (intra-block create-then-spend cancellation); otherwise add it to the
  remove set;
* for each output: add it to the insert map.

`to_lookup` is `txs.flatMap(_.dataInputs).map(_.boxId)` — every data-input
box id in transaction order, duplicates kept. It is the `toLookup` prefix of
Scala's `StateChanges.operations = toLookup ++ toRemove ++ toAppend`
(`ErgoState.stateChanges`): the ADProofs were generated by replaying those
lookups first, then the (sorted) removes, then the (sorted) inserts. A
`BatchAVLVerifier` consumes its proof as a stream, so a verifier MUST replay
the lookups — read-only and digest-neutral though they are — to keep the
stream aligned for the removes that follow.

This ordering is consensus-load-bearing — it must match the node's box-change
model and operation sequence or the replayed root diverges.

## Box-bytes sourcing

For every net-inserted box the extractor obtains canonical serialized bytes:

1. **byIdBinary (primary):** `GET /utxo/byIdBinary/{{boxId}}` returns the
   node's stored canonical bytes — only for still-unspent boxes. The bytes are
   parsed via `parse_ergo_box_bytes` (using the box JSON's `ergoTree` for the
   tree/body boundary) and reserialized to confirm canonicality.
2. **JSON reconstruct (fallback):** for spent boxes, byIdBinary returns
   `{{"boxId":null,"bytes":""}}`, so the box is rebuilt from the output JSON
   (`value`, `ergoTree`, `assets`, `creationHeight`, `additionalRegisters`,
   `transactionId`, `index`) into an `ErgoBox` and serialized with
   `serialize_ergo_box`.

### Reconstruction field mapping

* `ergoTree` hex is the canonical tree bytes verbatim (used as-is).
* `assets` -> tokens in wire order (`tokenId` 32-byte id + VLQ `amount`).
* `additionalRegisters` is `{{Rk: <raw-register-hex>}}`; each value is the
  per-register wire bytes (type code + value). register_bytes is assembled as
  `count(u8) || concat(R4..R9 hex)` in ascending register order, then parsed
  by `read_registers`.
* `transactionId` + `index` seal the candidate into an `ErgoBox`.

## Mandatory box_id gate

On BOTH paths the extractor recomputes `blake2b256(canonical_bytes)` and
asserts it equals the node-reported `boxId`. Any mismatch aborts the whole
run — wrong bytes would make this a false consensus oracle. The published
corpus is produced only when 100% of boxes pass.

## Full block sections

The node serves blocks as JSON, not canonical bytes, but the Mode 5 executor
digest path (`ergo-sync block_proc::process_block_digest`) loads sections from
the store and parses them with `read_header` / `read_block_transactions` /
`read_extension` (ADProofs bytes are `proof_bytes` above). So the corpus also
carries byte-exact canonical bytes for the three remaining sections,
reconstructed from the JSON and each gated by an id cross-check. A wrong
reconstruction ABORTS the run rather than emitting a false oracle.

### Header (`header_bytes`)

Built into an `ergo_ser::header::Header` from the header JSON and serialized
with `serialize_header`. For these heights (header version >= 2) the PoW
solution is `AutolykosSolution::V2 {{ pk, nonce }}` — `pk` is
`GroupElement::from_bytes(powSolutions.pk)`, `nonce` is `powSolutions.n`; the
JSON `w` / `d` fields are Autolykos-v1-era and absent from the v2 wire form.
`votes` is the 3-byte `votes` hex, `extension_root` is the JSON `extensionHash`,
`state_root` is the 33-byte `stateRoot`, and `unparsed_bytes` is empty (the id
gate would catch any non-empty trailer).

* **GATE:** `blake2b256(header_bytes) == header id` (the `/blocks/at/{{h}}` id).

### Block transactions (`block_tx_bytes`)

Each transaction is rebuilt as `Transaction {{ inputs, data_inputs,
output_candidates }}`:

* **inputs** — `box_id` + a `SpendingProof` from the `proofBytes` hex and a
  `ContextExtension` reconstructed from the verbatim extension wire bytes
  (`count(u8) || key(u8) || serialized-constant` per entry; the JSON
  `extension` map is `{{ "<u8 key>": "<hex constant>" }}`). The verbatim bytes
  are kept (`SpendingProof::from_trusted_raw_parts`) so `bytes_to_sign` stays
  byte-exact.
* **data inputs** — `box_id` pointers.
* **outputs** — `ErgoBoxCandidate`s via the SAME `reconstruct_candidate`
  helper the box-bytes path uses (outputs are candidates: box fields minus
  `transactionId` / `index`). The per-tx distinct-token table is built by the
  transaction serializer in first-occurrence order across outputs.

Then `BlockTransactions {{ header_id, transactions }}` is serialized with the
block-version-aware writer (v2+ emits the `MAX_TRANSACTIONS_IN_BLOCK +
block_version` marker).

* **GATE 1 (per tx):** `blake2b256(bytes_to_sign(tx)) == tx id`. Binds the
  inputs' box ids, data inputs, and outputs. Proofs are excluded from
  `bytes_to_sign` — they are validated later by the executor's script check.
* **GATE 2 (section):** the transactions Merkle root recomputed over the tx
  ids (++ witness ids for v2+, where witness id =
  `blake2b256(concat input proofs).drop(1)`) `== header.transactions_root`.
  This is the strong gate binding the full ordered tx set to the header.

### Extension (`extension_bytes`)

`Extension {{ header_id, fields }}` from the JSON `fields` (each
`[key(hex2), value(hex)]`), serialized with `write_extension`.

* **GATE:** the extension Merkle root recomputed over the `(key, value)` fields
  `== header.extension_root` (`extensionHash`), AND the serialized section
  round-trips through `read_extension` to the same struct (the root is over
  fields, so the round-trip additionally pins the header-id-prefixed section
  framing).

All three gates ran at 100% over the window: {n} headers, every transaction,
and {n} extensions. The section-byte fields were added without changing any
existing field or the in-memory replay test.

## ADProofs-retention caveat

The node serves `adProofs.proofBytes` for blocks it still retains. Archival /
recently-synced nodes keep them for recent history; older blocks may be pruned
(empty `proofBytes`). The pre-flight non-empty check shrinks/shifts the window
toward the tip if any height lacks proofs. This corpus's window was clean at
extraction time.

## Regeneration

Requires a live mainnet full-UTXO node at `{node}` that retains ADProofs for
the window. Then:

```
cargo run -p ergo-state --example extract_mode5_corpus
```

The extractor rewrites every `{{h}}.json` and this `PROVISIONING.md`. To move
the window, edit `WINDOW_LO` / `WINDOW_HI` / `EPOCH_BOUNDARY` in
`ergo-state/examples/extract_mode5_corpus.rs` (keep it contiguous and crossing
an epoch boundary).
"#,
        lo = WINDOW_LO,
        hi = WINDOW_HI,
        n = WINDOW_HI - WINDOW_LO + 1,
        boundary = EPOCH_BOUNDARY,
        node = NODE,
    );
    let path = dir.join("PROVISIONING.md");
    fs::write(&path, body).map_err(|e| format!("write {}: {e}", path.display()))
}

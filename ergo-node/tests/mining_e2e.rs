//! Node-level end-to-end mining: boot a real `run_inner` node already at a
//! synced UTXO tip with trivial difficulty, then drive the full external-miner
//! path over raw HTTP — serve a candidate, CPU-solve it, submit the solution,
//! and watch the booted node's tip advance.
//!
//! This covers the seam no other test reaches. `ergo-mining`'s
//! `engine_published_parity` proves the synthetic chain drives
//! `generate_candidate` to `Published` at the `StateStore` level, and
//! `ergo-state`'s `committed_snapshot_parity` proves the off-loop snapshot
//! matches the on-loop store. Both stop below `run_inner`. The two genuinely
//! unexercised parts here are:
//!
//! 1. The synthetic chain surviving the node's **boot hydration** — boot
//!    rebuilds in-memory block context from HEADERS + HEADER_META and runs a
//!    HEADER_META backfill that walks the best-header chain back to height 1
//!    with no gaps, so the chain must be a full, contiguous height-1..=N chain
//!    whose stored header timestamps match the HEADER_META the test-apply path
//!    synthesizes — neither of which `engine_published_parity`'s window-only,
//!    far-future-timestamp seed satisfies (see `seed_synced_chain` /
//!    `meta_timestamp` for the two boot-hydration adaptations that were needed).
//! 2. The submit path's **authoritative re-verification** inside the action
//!    loop: `verify_solution` → `apply_mined_block` → `process_header_cfg`,
//!    which re-runs PoW (`verify_pow_solution`, strict `hit >= target`
//!    rejection), re-derives `n_bits` off the parent epoch headers, and checks
//!    `height == parent + 1` before the executor's `AssembleBlock` applies and
//!    advances the tip.
//!
//! The chain mirrors `engine_published_parity::synced_store` for the candidate-
//! build inputs — a trivially-spendable emission box seeded into genesis, the
//! parent block's BlockTransactions + Extension sections, the last-10 window and
//! `synced(tip)` gate — but seeds the full height-1..=14 chain (boot needs it)
//! at a `block_version = 2` voted-params row (so the candidate's header version,
//! its Autolykos v2 PoW, and the v2 solution layout all agree — a v1 header
//! breaks the submit-path header decode). Height 15 (parent 14) keeps difficulty
//! on the non-recalc path (parent reuses its own `n_bits`) and clear of any
//! epoch / hard-fork boundary, so the submit-path `next_n_bits` re-derivation
//! off the synthetic parent returns the same trivial value the candidate
//! carries.
//!
//! Difficulty MUST be trivial (`n_bits = 0x01010000`, target = secp256k1
//! order): the submit path re-verifies PoW for real, so a single-threaded CPU
//! solve is only viable at difficulty 1, where the first nonce essentially
//! always satisfies `hit < target`.
//!
//! **Successive candidates against canonical-extension parents.** After the
//! mined block applies and the tip advances to N+1, the action loop signals the
//! engine to build the N+2 candidate. That build re-reads N+1's stored Extension
//! via `ergo_mining::candidate::unpack_interlinks_from_extension`, which decodes
//! the canonical `ergo_ser::extension::write_extension` layout (`[32-byte
//! header_id][u16 n_fields]` then per field `[2-byte key][u8 val_len][val]`) —
//! the same layout `apply_mined_block` and peer-block ingest (`ergo_sync::
//! block_proc`) persist. The parser recovers the full interlinks vector, so the
//! engine hands a non-empty vector to `update_interlinks` and builds the next
//! candidate for N+2. `engine_builds_second_candidate_after_block_applies`
//! pins this end-to-end: it solves + submits a block, then serves a candidate
//! for the new tip — exercising a build whose parent is a real applied block's
//! canonical extension.

mod common;

use std::time::Duration;

use num_bigint::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use ergo_crypto::autolykos::common::calc_n;
use ergo_crypto::autolykos::v2::hit_for_v2;
use ergo_primitives::digest::{ADDigest, Digest32, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::block_transactions::{write_block_transactions_with_version, BlockTransactions};
use ergo_ser::ergo_box::{write_ergo_box, ErgoBox, ErgoBoxCandidate};
use ergo_ser::ergo_tree::read_ergo_tree;
use ergo_ser::header::{serialize_header, Header};
use ergo_ser::input::{ContextExtension, Input, SpendingProof};
use ergo_ser::modifier_id::{compute_section_id, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION};
use ergo_ser::register::AdditionalRegisters;
use ergo_ser::transaction::Transaction;
use ergo_state::store::StateStore;
use ergo_validation::popow::algos::pack_interlinks;

use common::{make_test_config, spawn_node};
use ergo_node::RunHandle;

// ----- chain-construction constants (mirroring engine_published_parity) -----

/// Compressed secp256k1 point used as the miner pubkey throughout. `0x02`-
/// prefixed all-`0x02` bytes is the same placeholder the reward/parity tests
/// use; it round-trips through `GroupElement::from` and header serialization.
const MINER_PK: [u8; 33] = [0x02u8; 33];

/// Parent (tip) height. The candidate is built for `PARENT_HEIGHT + 1 = 15`:
/// ≥ 10 so the last-10 window holds, not a 1024-multiple (non-epoch), parent
/// height 14 not a 1024-multiple (difficulty non-recalc → parent `n_bits`
/// reused), far below the v2 / EIP-37 boundaries.
const PARENT_HEIGHT: u32 = 14;

/// Candidate height the node mines.
const CANDIDATE_HEIGHT: u32 = PARENT_HEIGHT + 1;

/// Header version the synthetic chain (and thus the candidate) carries.
const HEADER_VERSION: u8 = 2;

/// Trivial compact-bits: difficulty 1, target = secp256k1 order. Round-trips
/// through decode→encode unchanged, so the non-recalc difficulty path
/// reproduces it verbatim as the candidate's `n_bits`, and the submit-path
/// `next_n_bits` re-derivation off the parent returns the same value. The first
/// nonce essentially always satisfies `hit < target` here.
const N_BITS: u32 = 0x01010000;

/// Emission-box value: comfortably above the per-block miner reward at a
/// fixed-rate-window height (67.5 ERG) and the structural min-value floor.
const EMISSION_BOX_VALUE: u64 = 73_000_000_000_000;

// ----- chain construction -----

/// A trivially-true ErgoTree (`SBoolean true`, inline): header `0x00`, body
/// `0x01 0x01`. Reduces to `TrivialProp(true)`, so the emission tx's single
/// input verifies with an empty spending proof.
fn trivial_true_tree() -> (Vec<u8>, ergo_ser::ergo_tree::ErgoTree) {
    let bytes = vec![0x00u8, 0x01, 0x01];
    let mut r = VlqReader::new(&bytes);
    let tree = read_ergo_tree(&mut r).expect("trivial-true tree decodes");
    (bytes, tree)
}

/// The emission tx the parent block "applied": one input (an arbitrary prior
/// box id) and `output[0]` = the emission box the candidate will consume. A
/// second output keeps the coinbase shape close to real, but only `output[0]`
/// matters for emission-box discovery.
fn parent_emission_tx() -> Transaction {
    let (tree_bytes, tree) = trivial_true_tree();
    let input = Input {
        box_id: Digest32::from_bytes([0xAAu8; 32]),
        spending_proof: SpendingProof::new(Vec::new(), ContextExtension::empty()).unwrap(),
    };
    let emission_out = ErgoBoxCandidate::from_trusted_raw_parts(
        EMISSION_BOX_VALUE,
        tree.clone(),
        tree_bytes.clone(),
        PARENT_HEIGHT,
        Vec::new(),
        AdditionalRegisters::empty(),
        vec![0x00],
    );
    let miner_out = ErgoBoxCandidate::from_trusted_raw_parts(
        65_000_000_000,
        tree,
        tree_bytes,
        PARENT_HEIGHT,
        Vec::new(),
        AdditionalRegisters::empty(),
        vec![0x00],
    );
    Transaction {
        inputs: vec![input],
        data_inputs: Vec::new(),
        output_candidates: vec![emission_out, miner_out],
    }
}

/// Recover the emission box (`tx[0].output[0]`) exactly as
/// `lookup_emission_box_from_parent` reconstructs it.
fn emission_box_from(tx: &Transaction) -> ErgoBox {
    let bts = ergo_ser::transaction::bytes_to_sign(tx).expect("bytes_to_sign");
    let tx_id: ModifierId = ergo_primitives::digest::blake2b256(&bts).into();
    ErgoBox {
        candidate: tx.output_candidates[0].clone(),
        transaction_id: tx_id,
        index: 0,
    }
}

/// Header for `height`, chained to `parent_id`, carrying the committed
/// `state_root` and caller-chosen section digests. `timestamp` is supplied so
/// the parent sits near wall-clock now (see the module doc: keeps the candidate
/// timestamp inside the future-timestamp drift cap the submit path enforces).
fn header(
    height: u32,
    parent_id: ModifierId,
    state_root: ADDigest,
    transactions_root: Digest32,
    extension_root: Digest32,
    timestamp: u64,
) -> Header {
    Header {
        version: HEADER_VERSION,
        parent_id,
        ad_proofs_root: Digest32::from_bytes([0u8; 32]),
        transactions_root,
        state_root,
        timestamp,
        extension_root,
        n_bits: N_BITS,
        height,
        votes: [0u8; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: ergo_primitives::group_element::GroupElement::from(MINER_PK),
            nonce: [0u8; 8],
        },
    }
}

/// Serialize the parent's Extension section in the canonical Scala wire shape
/// `read_parent_extension_bytes` / `unpack_interlinks_from_extension` read —
/// the exact bytes `ergo_ser::extension::write_extension` emits and that
/// `apply_mined_block` / peer ingest persist (`[32-byte header_id][u16
/// n_fields]` then per field `[2-byte key][u8 val_len][val]`). The interlinks
/// keys come from `pack_interlinks`, which are exactly 2 bytes.
fn extension_section_bytes(header_id: &[u8; 32], fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    use ergo_ser::extension::{write_extension, Extension, ExtensionField};
    let ext = Extension {
        header_id: ModifierId::from_bytes(*header_id),
        fields: fields
            .iter()
            .map(|(k, v)| ExtensionField {
                key: <[u8; 2]>::try_from(k.as_slice()).expect("interlinks key is 2 bytes"),
                value: v.clone(),
            })
            .collect(),
    };
    let mut w = VlqWriter::new();
    write_extension(&mut w, &ext).expect("write extension");
    w.result()
}

fn write_box_bytes(b: &ErgoBox) -> Vec<u8> {
    let mut w = VlqWriter::new();
    write_ergo_box(&mut w, b).expect("serialize emission box");
    w.result()
}

/// HEADER_META timestamp the test-apply persist path stamps for height `h`
/// (`ergo-state` `persist.rs`: `1_700_000_000 + height`). The header bytes the
/// candidate build and the boot hydration read MUST carry this same value, or
/// boot's `hydrate_from_store` trips `MetaTimestampMismatch` comparing the
/// re-parsed header timestamp against the synthesized meta row. (It is a
/// seconds-magnitude value used as ms — i.e. ~1970 — so it stays comfortably in
/// the past: the candidate timestamp `max(now_ms, parent.ts + 1)` resolves to
/// wall-clock `now_ms`, monotonic above the parent and inside the
/// future-timestamp drift cap the submit path enforces.)
fn meta_timestamp(h: u32) -> u64 {
    1_700_000_000 + h as u64
}

/// Mainnet launch params with `block_version` bumped to 2 — the Autolykos-v2
/// header era. The seed store is opened with these so the height-0 voted-params
/// row (seeded by `reconcile_voted_params` from the launch params) reports
/// version 2, and the store's active params therefore report version 2 at every
/// tip below the first epoch boundary.
///
/// This matters because the candidate's header version is
/// `active_params.block_version`. With the stock launch row (block_version 1, a
/// v1-era default) the candidate builds a VERSION-1 header, whose Autolykos V1
/// solution layout (`pk + w + nonce + d`) does not match the V2 solution
/// `verify_solution` reconstructs (`pk + nonce`); the submit path then fails
/// decoding the re-serialized header (`process_header: UnexpectedEnd … needed
/// 33`, the missing `w` group element). A v2 active-params row aligns the
/// header version, the PoW (`hit_for_v2`), and the solution layout. The node's
/// own boot opens the same redb file with stock (v1) launch params, but
/// `reconcile_voted_params` only seeds the height-0 row when absent, so the
/// v2 row this writes survives. Only the version differs from the mainnet
/// launch default; every other field stays as the emission-tx validation
/// expects, and `epoch_start_height` stays 0 so it keys the height-0 row.
fn v2_launch_params() -> ergo_validation::ActiveProtocolParameters {
    let mut p = ergo_validation::scala_launch_mainnet();
    p.block_version = 2;
    p
}

/// Seed a synced chain into `db` exactly as `engine_published_parity::
/// synced_store`, but seeded from height 1 (boot hydration needs the full
/// chain) with header timestamps matching the test-apply HEADER_META stamp and
/// a `block_version = 2` height-0 voted-params row (see [`v2_launch_params`]).
/// The store is dropped before returning so the node can reopen the same redb
/// path. Returns the parent (tip) header id at `PARENT_HEIGHT`.
fn seed_synced_chain(db: &std::path::Path) -> [u8; 32] {
    let mut store = StateStore::open_with_launch_params(db, v2_launch_params()).unwrap();

    let em_tx = parent_emission_tx();
    let em_box = emission_box_from(&em_tx);
    let em_box_id = *em_box.box_id().expect("emission box id").as_bytes();
    let em_box_bytes = write_box_bytes(&em_box);

    store
        .initialize_genesis(&[(em_box_id, em_box_bytes)])
        .unwrap();
    let committed_root = store.root_digest();

    // Parent header roots are chosen freely (they only key the stored
    // sections); distinct non-zero digests so the two section-ids differ.
    let parent_tx_root = Digest32::from_bytes([0x77u8; 32]);
    let parent_ext_root = Digest32::from_bytes([0x55u8; 32]);

    // Seed the FULL header chain from height 1 — not just the last-10 window
    // `engine_published_parity` gets away with. The node's boot hydration runs a
    // HEADER_META backfill that walks `best_header` backward requiring strict
    // height continuity all the way to height 1 (no gaps); a window-only chain
    // starting at height 5 trips `backfill: row missing at expected height 4`.
    // (Ergo's header chain starts at height 1; genesis is the height-0 UTXO
    // seed, not a header-chain entry.) The last-10 window the candidate build
    // needs is the tail of this full chain.
    let mut parent_id: ModifierId = Digest32::from_bytes([0u8; 32]).into();
    let mut tip = [0u8; 32];
    for h in 1..=PARENT_HEIGHT {
        // Only the parent (top) header needs real section roots; the earlier
        // headers just need to chain + index, so zeroed roots are fine. The
        // timestamp MUST equal what the test-apply path writes into HEADER_META
        // (see `meta_timestamp`), or boot hydration rejects the chain.
        let ts = meta_timestamp(h);
        let hdr = if h == PARENT_HEIGHT {
            header(
                h,
                parent_id,
                committed_root,
                parent_tx_root,
                parent_ext_root,
                ts,
            )
        } else {
            header(
                h,
                parent_id,
                committed_root,
                Digest32::from_bytes([0u8; 32]),
                Digest32::from_bytes([0u8; 32]),
                ts,
            )
        };
        let (bytes, id) = serialize_header(&hdr).expect("serialize header");
        let id_bytes: [u8; 32] = *id.as_bytes();
        store.store_header(&id_bytes, &bytes).expect("store_header");
        if h == 1 {
            // Seed the best-header chain index at height 1 before the first
            // apply: the rewrite walk from the new tip down via HEADER_META
            // parent links terminates on the `already_matches` fork-point here
            // instead of running off the bottom past height 1.
            store
                .test_force_put_header_chain_index(h, &id_bytes)
                .expect("seed header chain index at height 1");
        }
        store
            .apply_block_unchecked_for_test(h, &id_bytes, &committed_root, &[])
            .expect("apply empty block");
        parent_id = id;
        tip = id_bytes;
    }

    // Parent BlockTransactions section (emission tx at index 0).
    let bt = BlockTransactions {
        header_id: ModifierId::from_bytes(tip),
        transactions: vec![em_tx],
    };
    let mut w = VlqWriter::new();
    write_block_transactions_with_version(&mut w, &bt, HEADER_VERSION).expect("write block txs");
    let bt_section_id =
        compute_section_id(TYPE_BLOCK_TRANSACTIONS, &tip, parent_tx_root.as_bytes());
    store
        .store_block_section_typed(&bt_section_id, &w.result(), TYPE_BLOCK_TRANSACTIONS)
        .expect("store block-transactions section");

    // Parent Extension section: a single-entry interlinks vector — non-empty so
    // `update_interlinks` never hits its empty-vector assertion, well-formed so
    // `unpack_interlinks` accepts it.
    let interlinks_fields = pack_interlinks(&[ModifierId::from_bytes(tip)]);
    let ext_bytes = extension_section_bytes(&tip, &interlinks_fields);
    let ext_section_id = compute_section_id(TYPE_EXTENSION, &tip, parent_ext_root.as_bytes());
    store
        .store_block_section_typed(&ext_section_id, &ext_bytes, TYPE_EXTENSION)
        .expect("store extension section");

    // Drop the store so the node's `run_inner` can reopen the same redb file.
    drop(store);
    tip
}

// ----- boot harness -----

/// Pre-seed the data dir with a synced trivial-difficulty UTXO chain at
/// `PARENT_HEIGHT`, then boot a real node with mining enabled and a pinned
/// reward key. Returns the temp-dir guard (kept alive for the node's lifetime),
/// the live handle, and the parent (tip) header id at `PARENT_HEIGHT`. The node
/// boots already synced, so the off-loop engine primes a Startup candidate
/// build for `CANDIDATE_HEIGHT`.
async fn boot_synced_mining_node() -> (tempfile::TempDir, RunHandle, [u8; 32]) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("state.redb");
    let parent_tip = seed_synced_chain(&db);

    let mut config = make_test_config(dir.path().to_path_buf());
    config.mining_config.enabled = true;
    config.mining_config.miner_public_key_hex = Some(hex::encode(MINER_PK));
    let handle = spawn_node(config).await;
    (dir, handle, parent_tip)
}

// ----- raw-HTTP helpers (no HTTP-client dev-dep; mimic submit_e2e) -----

/// A parsed HTTP response: status line code + body (everything past the blank
/// line). Sufficient for the small JSON payloads the mining routes return.
struct HttpResponse {
    status: u16,
    body: String,
}

/// Send one `Connection: close` request to `addr` and read the whole response.
/// `body` is `None` for GET, `Some(json)` for a JSON POST.
async fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> HttpResponse {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to bound api port");
    let req = match body {
        Some(b) => format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {len}\r\nConnection: close\r\n\r\n{b}",
            len = b.len(),
        ),
        None => format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    };
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();

    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status code in HTTP response: {text:?}"));
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    HttpResponse { status, body }
}

/// Poll `GET /mining/candidate` until it returns 200, parsing the body as a
/// `WorkMessageJson`. The off-loop engine primes a Startup build at boot but
/// the publish lands a tick or two after `run_inner` returns, so poll briefly
/// (mirrors the submit_e2e poll cadence). Panics if no candidate appears within
/// the bound.
async fn poll_candidate(addr: std::net::SocketAddr) -> ergo_rest_json::mining::WorkMessageJson {
    for _ in 0..80 {
        let resp = http_request(addr, "GET", "/mining/candidate", None).await;
        if resp.status == 200 {
            return serde_json::from_str(&resp.body)
                .unwrap_or_else(|e| panic!("parse candidate body {:?}: {e}", resp.body));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no mining candidate served within ~4s");
}

/// Poll `GET /mining/candidate` until it serves a candidate whose height equals
/// `height`. After a block applies, the engine rebuilds and republishes for the
/// new tip, but the published template lags the tip advance by a tick or two, so
/// the served candidate may briefly still be the previous-height one. Poll until
/// the height catches up. Panics if no candidate at `height` appears in the bound.
async fn poll_candidate_at_height(
    addr: std::net::SocketAddr,
    height: u32,
) -> ergo_rest_json::mining::WorkMessageJson {
    for _ in 0..160 {
        let resp = http_request(addr, "GET", "/mining/candidate", None).await;
        if resp.status == 200 {
            let work: ergo_rest_json::mining::WorkMessageJson = serde_json::from_str(&resp.body)
                .unwrap_or_else(|e| panic!("parse candidate body {:?}: {e}", resp.body));
            if work.h == Some(height) {
                return work;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no mining candidate at height {height} served within ~8s");
}

/// CPU-solve a candidate at difficulty 1: find the first 8-byte nonce whose
/// Autolykos v2 hit is strictly below the target. Strict `<` (not `<=`) so the
/// solution also passes the submit path's authoritative re-verify
/// (`verify_pow_solution` rejects `hit >= target`). At `n_bits = 0x01010000`
/// the target is the secp256k1 order, so the very first nonce essentially
/// always wins — the loop is a guard, not real work.
fn solve(msg: &[u8; 32], height: u32, target: &BigUint) -> [u8; 8] {
    let n = calc_n(HEADER_VERSION, height);
    for nonce_u64 in 0u64.. {
        let nonce = nonce_u64.to_be_bytes();
        if &hit_for_v2(msg, &nonce, height, n) < target {
            return nonce;
        }
    }
    unreachable!("difficulty-1 target is always satisfiable by some 8-byte nonce");
}

/// Decode a candidate's 64-char hex `msg` into the 32-byte array the solver
/// hashes against.
fn msg_bytes(work: &ergo_rest_json::mining::WorkMessageJson) -> [u8; 32] {
    let raw = hex::decode(&work.msg).expect("candidate msg is hex");
    raw.as_slice()
        .try_into()
        .expect("candidate msg is 32 bytes")
}

/// Poll `handle.read.status().best_full_block_height` until it reaches
/// `target`. The read snapshot is republished on the action loop's ~1s sync
/// tick, so the in-process reader lags the live store by up to a tick — both at
/// boot (initial publish) and after a block applies. Returns `true` if `target`
/// was observed within the bound.
async fn poll_best_full_height(handle: &RunHandle, target: u32) -> bool {
    for _ in 0..160 {
        if handle.read.status().best_full_block_height == target {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ----- happy path -----

/// A booted synced mining node publishes a well-formed candidate for the next
/// height, served over real HTTP at the bound port. Pins the WorkMessage wire
/// shape an external miner consumes: 64-char hex `msg`, decimal `b`, height
/// `N+1`, the configured pubkey, and the pool-versioning extensions.
#[tokio::test]
async fn boots_synced_and_serves_a_candidate() {
    let (_dir, handle, _parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    let work = poll_candidate(addr).await;

    assert_eq!(work.msg.len(), 64, "msg is a 32-byte blake2b hex digest");
    assert!(
        hex::decode(&work.msg).is_ok(),
        "msg must be valid hex: {}",
        work.msg,
    );
    // `b` deserialized as a BigUint via the decimal-string serde — its presence
    // as a parsed value is the contract; pin it positive (difficulty-1 target).
    assert!(work.b > BigUint::from(0u8), "target b must be positive");
    assert_eq!(work.h, Some(CANDIDATE_HEIGHT), "candidate is for N+1");
    assert_eq!(
        work.pk,
        hex::encode(MINER_PK),
        "pk is the configured miner key"
    );
    // Pool-versioning extensions are always emitted by this node.
    assert!(
        work.proof.is_none(),
        "no mandatory-tx proof on a plain candidate"
    );
    let _ = work.template_seq; // present (u64, defaults 0)
    let _ = work.clean_jobs; // present (bool)

    handle.shutdown().await.expect("clean shutdown");
}

/// The headline: GET the candidate, CPU-solve it, POST the solution, and watch
/// the booted node's best-full tip advance from N to N+1. This drives the whole
/// authoritative submit path inside the action loop — `verify_solution` →
/// `apply_mined_block` → `process_header_cfg` (PoW re-verify, `n_bits`
/// re-derivation off the synthetic parent, height check) → `AssembleBlock`.
#[tokio::test]
async fn solve_and_submit_advances_the_tip() {
    let (_dir, handle, parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    // Sanity: the node booted at the synced parent tip (height N). The read
    // snapshot publishes on the first sync tick, so poll rather than read once.
    assert!(
        poll_best_full_height(&handle, PARENT_HEIGHT).await,
        "node must boot already synced at the seeded parent height {PARENT_HEIGHT}, \
         read snapshot shows {}",
        handle.read.status().best_full_block_height,
    );
    assert_eq!(
        handle.read.tip().best_full_block.header_id,
        hex::encode(parent_tip),
        "booted tip id must be the seeded parent",
    );

    let work = poll_candidate(addr).await;
    assert_eq!(work.h, Some(CANDIDATE_HEIGHT));

    let nonce = solve(&msg_bytes(&work), CANDIDATE_HEIGHT, &work.b);

    // Post the solution — `n` is the only required field; `pk` is omitted so the
    // node injects the candidate's miner pubkey (Scala accept-time inject).
    let solution_body = format!(r#"{{"n":"{}"}}"#, hex::encode(nonce));
    let resp = http_request(addr, "POST", "/mining/solution", Some(&solution_body)).await;
    assert_eq!(
        resp.status, 200,
        "solution must be accepted (200); body: {}",
        resp.body,
    );

    // The mined block applies inside the action loop; the read snapshot
    // republishes on the next sync tick (~1s cadence). Poll until the tip
    // advances by exactly one.
    assert!(
        poll_best_full_height(&handle, CANDIDATE_HEIGHT).await,
        "best-full tip did not advance to N+1 ({CANDIDATE_HEIGHT}) after submit; \
         stuck at height {}",
        handle.read.status().best_full_block_height,
    );

    // The advance is genuine, not a transient mis-read: the new best-full tip
    // is a real, distinct block id (the mined block at N+1), and the read
    // snapshot's height/id agree on it. This is the full solve → submit →
    // verify_solution → apply_mined_block → process_header_cfg → AssembleBlock
    // path having landed a block through a booted node.
    let new_tip = handle.read.tip();
    assert_eq!(
        new_tip.best_full_block.height, CANDIDATE_HEIGHT,
        "tip ref height must be N+1",
    );
    assert_ne!(
        new_tip.best_full_block.header_id,
        hex::encode(parent_tip),
        "the new tip must be a different block than the seeded parent",
    );
    assert_eq!(
        new_tip.best_full_block.parent_id,
        hex::encode(parent_tip),
        "the mined block's parent must be the seeded tip — it built directly on N",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// After a mined block applies and the tip advances N → N+1, the off-loop engine
/// builds the NEXT candidate against the just-applied block's parent — reading
/// N+1's canonical `write_extension` Extension via
/// `unpack_interlinks_from_extension`, recovering its interlinks vector, and
/// publishing a candidate for N+2. This pins the successive-candidate path
/// end-to-end: the second build's parent is a real applied block whose extension
/// went through the canonical writer, the exact scenario the candidate engine
/// must read back. A candidate for N+2 (with a distinct `msg` from the N+1
/// candidate) is the regression guard.
#[tokio::test]
async fn engine_builds_second_candidate_after_block_applies() {
    let (_dir, handle, _parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    // Boot synced at N, serve + solve + submit the N+1 candidate.
    assert!(
        poll_best_full_height(&handle, PARENT_HEIGHT).await,
        "node must boot synced at the seeded parent height {PARENT_HEIGHT}",
    );
    let first = poll_candidate(addr).await;
    assert_eq!(
        first.h,
        Some(CANDIDATE_HEIGHT),
        "first candidate is for N+1"
    );

    let nonce = solve(&msg_bytes(&first), CANDIDATE_HEIGHT, &first.b);
    let solution_body = format!(r#"{{"n":"{}"}}"#, hex::encode(nonce));
    let resp = http_request(addr, "POST", "/mining/solution", Some(&solution_body)).await;
    assert_eq!(
        resp.status, 200,
        "solution must be accepted (200); body: {}",
        resp.body,
    );

    // Tip advances to N+1.
    assert!(
        poll_best_full_height(&handle, CANDIDATE_HEIGHT).await,
        "best-full tip did not advance to N+1 ({CANDIDATE_HEIGHT}) after submit; \
         stuck at height {}",
        handle.read.status().best_full_block_height,
    );

    // The headline guard: the engine builds a SECOND candidate for the new tip.
    // This build reads the just-applied N+1 block's Extension section — written
    // by `apply_mined_block` via the canonical `write_extension` — back through
    // `unpack_interlinks_from_extension`. Before the parser matched the canonical
    // layout the recovered interlinks were empty and `update_interlinks` panicked
    // the engine task; now the parser recovers the full vector and the build
    // succeeds. Poll until the served candidate targets N+2.
    let second_height = CANDIDATE_HEIGHT + 1;
    let second = poll_candidate_at_height(addr, second_height).await;
    assert_eq!(
        second.h,
        Some(second_height),
        "engine must publish a candidate for the NEW tip (N+2)",
    );
    assert_eq!(
        second.pk,
        hex::encode(MINER_PK),
        "second candidate is for the configured miner key",
    );
    assert_ne!(
        second.msg, first.msg,
        "the N+2 candidate's work message must differ from the N+1 candidate's \
         (distinct parent / height)",
    );

    handle.shutdown().await.expect("clean shutdown");
}

/// §4.2 regression guard: after a block applies, the candidate for the NEW
/// tip must become servable promptly (the minimal publish), not after a
/// full enrichment pass. The bound is generous for CI; the property pinned
/// is "serving resumes without an unbounded gap".
#[tokio::test]
async fn new_tip_candidate_serves_promptly_after_block_apply() {
    let (_dir, handle, _parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    // Boot synced at N; serve the N+1 candidate.
    assert!(
        poll_best_full_height(&handle, PARENT_HEIGHT).await,
        "node must boot synced at the seeded parent height {PARENT_HEIGHT}",
    );
    let work = poll_candidate(addr).await;
    let h0 = work.h.expect("candidate carries a height");
    assert_eq!(h0, CANDIDATE_HEIGHT, "boot candidate is for N+1");

    // Solve + submit the N+1 block.
    let nonce = solve(&msg_bytes(&work), h0, &work.b);
    let solution_body = format!(r#"{{"n":"{}"}}"#, hex::encode(nonce));
    let resp = http_request(addr, "POST", "/mining/solution", Some(&solution_body)).await;
    assert_eq!(
        resp.status, 200,
        "solution must be accepted (200); body: {}",
        resp.body,
    );

    // The tip advances; time how long until the N+2 candidate appears.
    let started = std::time::Instant::now();
    let next_work = poll_candidate_at_height(addr, h0 + 1).await;
    let elapsed = started.elapsed();

    assert_eq!(
        next_work.h,
        Some(h0 + 1),
        "served candidate must be for the new tip (N+2)",
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "new-tip candidate must become servable within 10s of submit; took {elapsed:?}",
    );
}

/// `GET /mining/candidate?longpoll=<msg>` semantics, end-to-end through a booted
/// node over real HTTP:
///   - a value that does NOT match the current template returns immediately
///     (the client is already behind, gets the current template at once);
///   - a value that DOES match parks (does not return promptly) until the
///     bounded `LONGPOLL_TIMEOUT` elapses, then returns the current template.
///
/// Both arms thread the `longpoll` query parameter from axum → bridge → action
/// loop and back, which is the production longpoll plumbing.
///
/// What this does NOT assert: that the longpoll wakes with a *different* msg on
/// a fresh publish. The only way to publish a fresh template here is to advance
/// the tip (mine a block) or mutate the mempool; the end-to-end post-apply
/// republish is pinned separately by
/// `engine_builds_second_candidate_after_block_applies`. The wake-on-serve-change
/// and wake-on-channel-close mechanisms are covered at the bridge level in
/// `ergo-node::mining_bridge` (`candidate_longpoll_matching_value_wakes_on_serve_change`,
/// `candidate_longpoll_wakes_on_channel_close`); `shutdown_with_a_parked_longpoll_drains`
/// below pins the channel-close wake end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn longpoll_parks_on_match_and_returns_current_immediately_on_mismatch() {
    let (_dir, handle, _parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    let work = poll_candidate(addr).await;
    let held_msg = work.msg.clone();

    // Mismatch arm: a longpoll value that is not the current template returns
    // the current template right away (no parking).
    let mismatch = tokio::time::timeout(
        Duration::from_secs(2),
        http_request(addr, "GET", "/mining/candidate?longpoll=deadbeef", None),
    )
    .await
    .expect("non-matching longpoll must return without parking");
    assert_eq!(
        mismatch.status, 200,
        "mismatch longpoll body: {}",
        mismatch.body
    );
    let got: ergo_rest_json::mining::WorkMessageJson =
        serde_json::from_str(&mismatch.body).expect("parse mismatch candidate");
    assert_eq!(
        got.msg, held_msg,
        "a non-matching longpoll returns the CURRENT template immediately",
    );

    // Match arm: a longpoll on the current template parks. With a quiet chain
    // (no publish) it must NOT return before a short delay, proving it is
    // genuinely blocked — then it returns the current template once the bound
    // (30s in production) elapses. We don't wait the full 30s; we only prove it
    // parked past a window far longer than the ~immediate mismatch return.
    let held_for_task = held_msg.clone();
    let parked = tokio::spawn(async move {
        let path = format!("/mining/candidate?longpoll={held_for_task}");
        http_request(addr, "GET", &path, None).await
    });
    // The parked request must still be pending after 1s (it would have returned
    // in milliseconds if it weren't blocking on the matching value).
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !parked.is_finished(),
        "a longpoll on the current template must park, not return immediately",
    );
    // It is parked on the 30s bound; we don't wait it out. Shutdown wakes it via
    // the channel-close path (the dedicated coverage for that is the next test),
    // so abort the prober and let the node stop cleanly.
    parked.abort();
    let _ = parked.await;

    handle.shutdown().await.expect("clean shutdown");
}

// ----- graceful shutdown -----

/// A `?longpoll=` request parked at shutdown must drain promptly: the action
/// loop drops the mining-request receiver on shutdown, which resolves the
/// bridge's `tx.closed()` and wakes the parked longpoll, so `shutdown()`
/// completes well under the 30s longpoll bound rather than hanging on it. The
/// bridge-level mechanism is unit-tested in `mining_bridge.rs`
/// (`candidate_longpoll_wakes_on_channel_close`); this pins it end-to-end
/// through a booted node.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_with_a_parked_longpoll_drains() {
    let (_dir, handle, _parent_tip) = boot_synced_mining_node().await;
    let addr = handle.api_addr.expect("api bound");

    let work = poll_candidate(addr).await;
    let held_msg = work.msg.clone();

    // Park a longpoll on the current template (matching msg → it blocks).
    let longpoll = tokio::spawn(async move {
        let path = format!("/mining/candidate?longpoll={held_msg}");
        http_request(addr, "GET", &path, None).await
    });

    // Let it park, then shut down. The longpoll is sitting on `tx.closed()` /
    // the serve watch; shutdown drops the mining receiver and wakes it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let shutdown_started = std::time::Instant::now();
    handle.shutdown().await.expect("clean shutdown");
    let elapsed = shutdown_started.elapsed();
    assert!(
        elapsed < Duration::from_secs(20),
        "shutdown must not block on the parked longpoll's 30s bound; took {elapsed:?}",
    );

    // The longpoll itself unblocks too (it re-fetches against the now-closed
    // channel → Unavailable / 503, or returns the last template) rather than
    // hanging until the 30s bound.
    let resp = tokio::time::timeout(Duration::from_secs(5), longpoll)
        .await
        .expect("parked longpoll must drain at shutdown, not hang")
        .expect("longpoll task");
    assert!(
        resp.status == 503 || resp.status == 200,
        "a longpoll drained at shutdown returns 503 (shutting down) or a final 200, got {}",
        resp.status,
    );
}

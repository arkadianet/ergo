//! Mode 5 gate-lifting oracle: drive the mainnet ADProof-replay corpus
//! through the REAL executor digest path and assert the Rust digest node
//! reproduces mainnet's authenticated state transition, block by block.
//!
//! This is the test that justifies lifting the Mode 5 boot gate. It calls
//! `ergo_sync::block_proc::process_block` against a
//! `StateBackendKind::Digest`, which dispatches to `process_block_digest`:
//! load header + block-tx + extension + ADProofs sections from the store,
//! compute epoch voted-params, run linear preflights, resolve the spent /
//! data-input boxes from the ADProofs against the parent digest, build a
//! `DigestUtxoView`, run FULL `validate_full_block` (scripts, amounts,
//! merkle roots), and commit via `apply_block_digest`. For every applied
//! height the post-apply root MUST equal mainnet's `header.state_root` and
//! the full-block tip MUST advance by one. A single divergence fails the
//! test — that is the point.
//!
//! ## Applied range
//!
//! `1_795_978 ..= 1_796_160` (183 blocks). The lower bound is chosen so the
//! prior 10 headers (`1_795_968 ..= 1_795_977`, all in the corpus) are
//! available for `cached_last_headers`. The range crosses the voting-epoch
//! boundary `1_796_096` (exercising the voted-params recompute path) and
//! includes 55 data-input blocks.
//!
//! ## Active parameters
//!
//! The corpus heights sit at ~1.79M, far above genesis launch. The digest
//! path sources params from `store.active_params()` and
//! `store.validation_settings()`, so the store is seeded with the parameters
//! mainnet actually used at these heights: a `voted_params` row at the
//! epoch start `1_795_072`, parsed from that block's extension through the
//! production `parse_active_params` / `parse_validation_settings_update`
//! parsers by `extract_mode5_prior_headers`. Those are `max_block_cost =
//! 8_001_091`, `max_block_size = 1_271_009`, `block_version = 4`, and the
//! cumulative validation-settings update disabling rules 215 and 409 (the
//! soft-fork state mainnet had reached before this window). Launch params
//! alone do NOT suffice — they cap block cost at 1_000_000 and leave 215 /
//! 409 enabled, which would reject blocks mainnet accepted.
//!
//! ## Epoch-boundary vote recompute
//!
//! At `1_796_096` the digest path recomputes the epoch's voted params by
//! walking the previous epoch's 1024 headers' `votes`
//! (`compute_epoch_votes`), reading each through `get_header_id_at_height`.
//! The corpus only carries headers from `1_795_968`, so the prefix
//! `1_795_072 ..= 1_795_967` is supplied by `prior_headers.json` (canonical
//! header bytes, each id-gated by the companion extractor) and the full
//! `1_795_072 ..= 1_796_095` range is stamped into `HEADER_CHAIN_INDEX`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ergo_primitives::digest::ModifierId;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::ad_proofs::{write_ad_proofs, ADProofs};
use ergo_ser::header::{read_header, Header};
use ergo_ser::modifier_id::{
    compute_section_id, TYPE_AD_PROOFS, TYPE_BLOCK_TRANSACTIONS, TYPE_EXTENSION,
};
use ergo_state::chain::{ChainStateMeta, HeaderAvailability, HeaderMeta};
use ergo_state::{ChainStateRead, DigestStateStore, HeaderSectionStore, StateBackendKind};
use ergo_sync::block_proc::process_block;
use ergo_validation::active_params::ActiveProtocolParameters;
use ergo_validation::context::ProtocolParams;
use ergo_validation::header::CheckedHeader;

const APPLY_LO: u32 = 1_795_978;
const APPLY_HI: u32 = 1_796_160;
const EPOCH_BOUNDARY: u32 = 1_796_096;
/// Lowest height the vote recompute at the boundary reads.
const PRIOR_LO: u32 = 1_795_072;
/// Highest height present in `prior_headers.json` (one below the corpus).
const PRIOR_HI: u32 = 1_795_967;
/// Lowest height the ADProof-replay corpus covers.
const CORPUS_LO: u32 = 1_795_968;

// ----- fixture loading -----

struct CorpusRow {
    header_id: [u8; 32],
    parent_state_root: [u8; 33],
    state_root: [u8; 33],
    header_bytes: Vec<u8>,
    block_tx_bytes: Vec<u8>,
    extension_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors")
        .join("mode5")
        .join("ad_proofs_replay")
}

fn hexn<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s}: {e}"));
    v.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected {N} bytes, got {}", v.len()))
}

fn load_corpus_row(h: u32) -> CorpusRow {
    let path = corpus_dir().join(format!("{h}.json"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {h}.json: {e}"));
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{h}.json: {e}"));
    let s = |k: &str| {
        v[k].as_str()
            .unwrap_or_else(|| panic!("{h}.json missing {k}"))
            .to_string()
    };
    CorpusRow {
        header_id: hexn::<32>(&s("header_id")),
        parent_state_root: hexn::<33>(&s("parent_state_root")),
        state_root: hexn::<33>(&s("state_root")),
        header_bytes: hex::decode(s("header_bytes")).expect("header_bytes hex"),
        block_tx_bytes: hex::decode(s("block_tx_bytes")).expect("block_tx_bytes hex"),
        extension_bytes: hex::decode(s("extension_bytes")).expect("extension_bytes hex"),
        proof_bytes: hex::decode(s("proof_bytes")).expect("proof_bytes hex"),
    }
}

/// Prior-epoch header bytes (`PRIOR_LO ..= PRIOR_HI`) plus the start-epoch
/// active params, both from `extract_mode5_prior_headers`.
struct PriorFixture {
    headers: BTreeMap<u32, Vec<u8>>,
    start_params: ActiveProtocolParameters,
}

fn load_prior_fixture() -> PriorFixture {
    // One level up from `ad_proofs_replay` so the in-memory replay test's
    // per-height directory scan never tries to parse it as a `Row`.
    let path = corpus_dir().join("..").join("prior_headers.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read prior_headers.json: {e}\n\
             Generate it with: cargo run -p ergo-state --example extract_mode5_prior_headers"
        )
    });
    let v: serde_json::Value = serde_json::from_str(&raw).expect("prior_headers.json");
    let mut headers = BTreeMap::new();
    let obj = v["headers"].as_object().expect("headers object");
    for (k, val) in obj {
        let h: u32 = k.parse().expect("header height key");
        let bytes = hex::decode(val.as_str().expect("header bytes hex")).expect("header bytes");
        headers.insert(h, bytes);
    }
    // The recompute prefix must be fully present: PRIOR_LO..=PRIOR_HI.
    for h in PRIOR_LO..=PRIOR_HI {
        assert!(
            headers.contains_key(&h),
            "prior_headers.json missing height {h} (recompute prefix incomplete)"
        );
    }

    let params_hex = v["start_active_params_hex"]
        .as_str()
        .expect("start_active_params_hex");
    let start_params =
        ActiveProtocolParameters::deserialize(&hex::decode(params_hex).expect("params hex"))
            .expect("deserialize start params");
    PriorFixture {
        headers,
        start_params,
    }
}

// ----- helpers -----

fn parse_header(bytes: &[u8]) -> Header {
    let mut r = VlqReader::new(bytes);
    read_header(&mut r).expect("parse header")
}

fn header_meta(header: &Header) -> HeaderMeta {
    HeaderMeta {
        parent_id: *header.parent_id.as_bytes(),
        height: header.height,
        // Fork choice is not exercised here (every header is stored as an
        // orphan; no best-header rewrite runs), so a height-derived
        // monotonic score is sufficient and keeps the chain-state invariant
        // (`best_header_score` non-empty) satisfied.
        cumulative_score: (header.height as u64).to_be_bytes().to_vec(),
        pow_validity: 1,
        timestamp: header.timestamp,
    }
}

fn ad_proofs_section_bytes(header_id: [u8; 32], proof_bytes: &[u8]) -> Vec<u8> {
    let ap = ADProofs {
        header_id: ModifierId::from_bytes(header_id),
        proof_bytes: proof_bytes.to_vec(),
    };
    let mut w = VlqWriter::new();
    write_ad_proofs(&mut w, &ap);
    w.result()
}

/// Store one header's three full-block sections under their computed ids.
fn store_sections(store: &DigestStateStore, header: &Header, row: &CorpusRow) {
    let header_id = row.header_id;
    let tx_id = compute_section_id(
        TYPE_BLOCK_TRANSACTIONS,
        &header_id,
        header.transactions_root.as_bytes(),
    );
    let ext_id = compute_section_id(TYPE_EXTENSION, &header_id, header.extension_root.as_bytes());
    let ad_id = compute_section_id(TYPE_AD_PROOFS, &header_id, header.ad_proofs_root.as_bytes());

    store
        .store_block_section_typed(&tx_id, &row.block_tx_bytes, TYPE_BLOCK_TRANSACTIONS)
        .expect("store block_tx section");
    store
        .store_block_section_typed(&ext_id, &row.extension_bytes, TYPE_EXTENSION)
        .expect("store extension section");
    store
        .store_block_section_typed(
            &ad_id,
            &ad_proofs_section_bytes(header_id, &row.proof_bytes),
            TYPE_AD_PROOFS,
        )
        .expect("store ad_proofs section");
}

/// Open a digest store in `dir` seeded to a committed tip at
/// `APPLY_LO - 1`, with every header / section / index / params row the
/// digest path needs to apply `APPLY_LO ..= APPLY_HI`. Returns the store
/// and the per-height corpus rows.
fn build_seeded_store(dir: &std::path::Path) -> (DigestStateStore, BTreeMap<u32, CorpusRow>) {
    let prior = load_prior_fixture();

    // Voting cadence: mainnet epoch length (1024) so the boundary lands at
    // 1_796_096 exactly as on-chain.
    let voting = ergo_chain_spec::VotingParams::mainnet();
    let mut store = DigestStateStore::open(
        &dir.join("digest_state.redb"),
        ergo_validation::scala_launch(),
        voting,
        ergo_chain_spec::GenesisParams::mainnet().state_digest,
    )
    .expect("open digest store");

    // Seed the epoch-start params row so active_params() / validation_settings()
    // reflect the real pre-window state (cost limits + disabled rules 215/409).
    store
        .seed_voted_params_row_for_test(&prior.start_params)
        .expect("seed voted_params row");

    // Load every corpus row once.
    let mut rows: BTreeMap<u32, CorpusRow> = BTreeMap::new();
    for h in CORPUS_LO..=APPLY_HI {
        rows.insert(h, load_corpus_row(h));
    }

    // Store prior-epoch headers (PRIOR_LO..=PRIOR_HI): bytes + meta as
    // orphans, plus the height index for the vote recompute.
    for (&h, bytes) in &prior.headers {
        let header = parse_header(bytes);
        assert_eq!(header.height, h, "prior header height mismatch at {h}");
        let id = *ergo_primitives::digest::blake2b256(bytes).as_bytes();
        let meta = header_meta(&header);
        store
            .store_validated_header(&id, bytes, &meta, None)
            .expect("store prior header orphan");
        store
            .seed_header_chain_index_for_test(h, &id)
            .expect("seed prior chain index");
    }

    // Store corpus headers (CORPUS_LO..=APPLY_HI): bytes + meta as orphans.
    // Index the [CORPUS_LO, EPOCH_BOUNDARY - 1] slice too so the vote
    // recompute's [PRIOR_LO, EPOCH_BOUNDARY - 1] read range is fully dense.
    for (&h, row) in &rows {
        let header = parse_header(&row.header_bytes);
        assert_eq!(header.height, h, "corpus header height mismatch at {h}");
        let meta = header_meta(&header);
        store
            .store_validated_header(&row.header_id, &row.header_bytes, &meta, None)
            .expect("store corpus header orphan");
        store
            .seed_header_chain_index_for_test(h, &row.header_id)
            .expect("seed corpus chain index");
        store_sections(&store, &header, row);
    }

    // Seed the committed tip at APPLY_LO - 1. root_digest is the parent
    // state root of the first applied block; best_full_block_id is the
    // APPLY_LO - 1 header. best_header is pushed past APPLY_HI so the
    // `best_header >= best_full_block` shape invariant holds across the run.
    let h0 = APPLY_LO - 1;
    let h0_row = &rows[&h0];
    let first_row = &rows[&APPLY_LO];
    let tip_chain_state = ChainStateMeta {
        best_header_id: rows[&APPLY_HI].header_id,
        best_header_height: APPLY_HI,
        best_header_score: ((APPLY_HI as u64) + 1).to_be_bytes().to_vec(),
        best_full_block_id: h0_row.header_id,
        best_full_block_height: h0,
        header_availability: HeaderAvailability::Dense,
    };
    store.seed_tip_for_test(first_row.parent_state_root, tip_chain_state);

    // Sanity: the seeded tip root is the parent root the first block applies
    // on, and the seeded params took effect.
    assert_eq!(store.height(), h0);
    assert_eq!(store.root_digest(), first_row.parent_state_root);
    assert_eq!(
        store.active_params().epoch_start_height,
        PRIOR_LO,
        "active params must be the seeded epoch-start row, not launch"
    );
    assert_eq!(store.active_params().max_block_cost, 8_001_091);
    assert!(
        store.validation_settings().is_rule_disabled(215)
            && store.validation_settings().is_rule_disabled(409),
        "rules 215 and 409 must be disabled in the seeded validation settings"
    );

    (store, rows)
}

/// Build `cached_last_headers` for the block at `h`: the prior up-to-10
/// headers, most-recent first, from the corpus header bytes.
fn last_headers_for(h: u32, rows: &BTreeMap<u32, CorpusRow>) -> Vec<CheckedHeader> {
    let mut out = Vec::with_capacity(10);
    let mut cur = h.saturating_sub(1);
    for _ in 0..10 {
        if cur < CORPUS_LO {
            break;
        }
        let row = &rows[&cur];
        let checked = CheckedHeader::from_persisted_parts(
            &row.header_bytes,
            row.header_id,
            1,
            cur,
            *parse_header(&row.header_bytes).parent_id.as_bytes(),
            parse_header(&row.header_bytes).timestamp,
        )
        .expect("rebuild last header");
        out.push(checked);
        if cur == 0 {
            break;
        }
        cur -= 1;
    }
    out
}

// ----- oracle parity -----

#[test]
fn mode5_executor_replay_reproduces_mainnet_state_roots() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, rows) = build_seeded_store(tmp.path());
    let mut backend = StateBackendKind::Digest(store);

    // `params` is ignored by the digest arm (it sources params from
    // store.active_params()), but the signature requires one.
    let params = ProtocolParams::mainnet_default();

    let mut crossed_boundary = false;
    let mut data_input_blocks = 0usize;

    for h in APPLY_LO..=APPLY_HI {
        let row = &rows[&h];
        let last_headers = last_headers_for(h, &rows);

        let processed = process_block(
            &mut backend,
            &row.header_id,
            &params,
            Some(&last_headers),
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("process_block failed at h={h}: {e}"));

        assert_eq!(processed.height, h, "processed height mismatch at {h}");

        // Post-apply root MUST equal mainnet's header.state_root, and the
        // full-block tip MUST have advanced to h.
        let StateBackendKind::Digest(ref d) = backend else {
            unreachable!("backend is Digest");
        };
        assert_eq!(
            d.root_digest(),
            row.state_root,
            "post-apply root mismatch at h={h}: digest node diverged from mainnet"
        );
        assert_eq!(d.height(), h, "full-block tip did not advance to {h}");

        if h == EPOCH_BOUNDARY {
            crossed_boundary = true;
        }
        // Count data-input blocks (their tx data-inputs drive proof lookups).
        let bt = ergo_ser::block_transactions::read_block_transactions(&mut VlqReader::new(
            &row.block_tx_bytes,
        ))
        .expect("parse block tx");
        if bt.transactions.iter().any(|tx| !tx.data_inputs.is_empty()) {
            data_input_blocks += 1;
        }
    }

    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!()
    };
    assert_eq!(d.height(), APPLY_HI, "final tip must be APPLY_HI");
    assert_eq!(
        d.root_digest(),
        rows[&APPLY_HI].state_root,
        "final root must equal mainnet's"
    );
    assert!(crossed_boundary, "run must cross the epoch boundary");
    assert!(
        data_input_blocks > 0,
        "run must include data-input blocks, got {data_input_blocks}"
    );
}

// ----- error paths -----

/// Drive the first applied block (`APPLY_LO`) and return its rejection
/// error and the post-call backend. The tip is seeded at `APPLY_LO - 1`, so
/// this block is always linearly applicable — any `Err` therefore comes from
/// the digest path's content checks, not a fork / out-of-order gate.
fn process_first_applied(
    backend: &mut StateBackendKind,
    rows: &BTreeMap<u32, CorpusRow>,
) -> Result<(), String> {
    let row = &rows[&APPLY_LO];
    let last_headers = last_headers_for(APPLY_LO, rows);
    let params = ProtocolParams::mainnet_default();
    process_block(
        backend,
        &row.header_id,
        &params,
        Some(&last_headers),
        None,
        None,
        None,
        None,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Negative — proof commitment gate. Flipping a byte inside the stored
/// ADProofs proof changes `blake2b256(proof_bytes)`, so it no longer matches
/// `header.ad_proofs_root`; the verifier rejects at its root-hash gate
/// (`AdProofsRootMismatch`) before any replay. Proves the digest path is not
/// vacuously accepting a tampered proof section.
#[test]
fn mode5_executor_replay_rejects_corrupted_ad_proofs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, rows) = build_seeded_store(tmp.path());

    let row = &rows[&APPLY_LO];
    let header = parse_header(&row.header_bytes);
    let ad_id = compute_section_id(
        TYPE_AD_PROOFS,
        &row.header_id,
        header.ad_proofs_root.as_bytes(),
    );

    let mut corrupted = row.proof_bytes.clone();
    // Flip a byte well inside the proof stream (not the leading framing) so
    // the section still parses cleanly — the rejection must come from proof
    // verification, not an envelope decode error.
    let mid = corrupted.len() / 2;
    corrupted[mid] ^= 0xFF;
    store
        .store_block_section_typed(
            &ad_id,
            &ad_proofs_section_bytes(row.header_id, &corrupted),
            TYPE_AD_PROOFS,
        )
        .expect("overwrite ad_proofs section with corrupted proof");

    // The seeded tip root (= the first block's parent root) before the call;
    // a clean rejection must leave it byte-for-byte unchanged.
    let pre_root = rows[&APPLY_LO].parent_state_root;
    let mut backend = StateBackendKind::Digest(store);
    let msg = process_first_applied(&mut backend, &rows)
        .expect_err("corrupted ADProofs must be rejected");

    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!()
    };
    assert_eq!(d.height(), APPLY_LO - 1, "no state advance on rejection");
    assert_eq!(
        d.root_digest(),
        pre_root,
        "root must be unchanged on rejection"
    );
    assert!(
        msg.contains("digest proof verification") && msg.contains("ADProofs root mismatch"),
        "expected an ADProofs root-hash mismatch rejection, got: {msg}"
    );
}

/// Negative — parent-root replay gate. Leave the proof + all sections
/// intact (so the `ad_proofs_root` commitment gate passes) but seed the tip
/// at a parent digest one bit off the real one. The proof's embedded
/// starting digest binds to the TRUE parent root, so seeding the verifier at
/// the wrong root makes construction reject
/// (`starting_digest.starts_with(tree.label(root))` fails). This is the gate
/// that anchors the digest node to the correct parent state — a digest node
/// that accepted a block against the wrong parent root would silently fork
/// off mainnet. Distinct from the commitment gate above: the proof bytes are
/// untouched, only the state we replay them against is wrong.
#[test]
fn mode5_executor_replay_rejects_wrong_parent_root() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (mut store, rows) = build_seeded_store(tmp.path());

    // Re-seed the tip with a parent root one bit off the real one, keeping
    // the rest of the (already-coherent) chain state.
    let mut bad_root = rows[&APPLY_LO].parent_state_root;
    bad_root[1] ^= 0x01;
    let mut cs = store.chain_state().clone();
    cs.best_full_block_id = rows[&(APPLY_LO - 1)].header_id;
    cs.best_full_block_height = APPLY_LO - 1;
    store.seed_tip_for_test(bad_root, cs);
    assert_eq!(store.root_digest(), bad_root);

    let mut backend = StateBackendKind::Digest(store);
    let msg =
        process_first_applied(&mut backend, &rows).expect_err("wrong parent root must be rejected");

    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!()
    };
    assert_eq!(d.height(), APPLY_LO - 1, "no state advance on rejection");
    // The (deliberately wrong) seeded root must be left untouched — the
    // rejection writes nothing.
    assert_eq!(
        d.root_digest(),
        bad_root,
        "root must be unchanged on rejection"
    );
    assert_ne!(
        d.root_digest(),
        rows[&APPLY_LO].state_root,
        "must not have advanced to mainnet's post-root"
    );
    assert!(
        msg.contains("digest proof verification") && msg.contains("construction failed"),
        "expected a parent-root replay rejection at verifier construction, got: {msg}"
    );
}

/// Negative — NiPoPoW interlinks wiring (BV-01). With the parent extension now
/// threaded into `BlockValidationContext`, rules 401/402 fire. Corrupt the
/// PARENT's stored interlink vector (truncate one interlink entry so the
/// parent's interlinks no longer decode) and assert the child at `APPLY_LO` is
/// rejected with an interlink structure mismatch (Scala `exIlStructure`, rule
/// 402). This proves the wiring is ACTIVE — a `None` parent extension would
/// take Scala's recoverable `exIlUnableToValidate` (rule 413) path and ACCEPT,
/// so the green replay alone could not distinguish a wired Some from an inert
/// None. Everything else (proof, child sections, parent root) is intact, so the
/// rejection can only come from the interlink comparison.
#[test]
fn mode5_executor_replay_rejects_mutated_parent_interlinks() {
    use ergo_ser::extension::{read_extension, write_extension};

    let tmp = tempfile::tempdir().expect("tempdir");
    let (store, rows) = build_seeded_store(tmp.path());

    // The parent of the first applied block; its extension was seeded by
    // `store_sections` under `compute_section_id(TYPE_EXTENSION, ..)`.
    let parent = &rows[&(APPLY_LO - 1)];
    let parent_header = parse_header(&parent.header_bytes);
    let parent_ext_id = compute_section_id(
        TYPE_EXTENSION,
        &parent.header_id,
        parent_header.extension_root.as_bytes(),
    );

    // Truncate one interlink entry's value (a 33-byte run-length+id) so
    // `unpack_interlinks` rejects the parent vector → rule 402.
    let mut ext =
        read_extension(&mut VlqReader::new(&parent.extension_bytes)).expect("parent ext decodes");
    let il = ext
        .fields
        .iter_mut()
        .find(|f| f.key[0] == 0x01) // INTERLINKS_VECTOR_PREFIX
        .expect("parent extension carries an interlink field");
    assert!(!il.value.is_empty(), "interlink value is non-empty");
    il.value.pop();
    let mut w = VlqWriter::new();
    write_extension(&mut w, &ext).expect("re-serialize mutated extension");
    store
        .store_block_section_typed(&parent_ext_id, &w.result(), TYPE_EXTENSION)
        .expect("overwrite parent extension with corrupted interlinks");

    // The seeded tip root before the call; a clean rejection must leave it
    // byte-for-byte unchanged (a partial write that left height alone would
    // otherwise slip past the height check).
    let pre_root = rows[&APPLY_LO].parent_state_root;
    let mut backend = StateBackendKind::Digest(store);
    let msg = process_first_applied(&mut backend, &rows)
        .expect_err("corrupted parent interlinks must be rejected via the wired 401/402 path");

    let StateBackendKind::Digest(ref d) = backend else {
        unreachable!()
    };
    assert_eq!(d.height(), APPLY_LO - 1, "no state advance on rejection");
    assert_eq!(
        d.root_digest(),
        pre_root,
        "root must be unchanged on rejection"
    );
    assert!(
        msg.contains("interlink structure mismatch") && msg.contains("rule 402"),
        "expected an interlink structure-mismatch rejection (rule 402), got: {msg}"
    );
}

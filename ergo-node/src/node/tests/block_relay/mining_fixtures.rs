use super::super::block_relay::Announcement;
use super::*;
use ergo_mining::candidate::Candidate;
use ergo_mining::engine::{BestTip, BuildReason};
use ergo_mining::handle::MiningHandle;
use ergo_primitives::digest::{ADDigest, ModifierId};
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::header::{read_header, serialize_header};
use ergo_ser::modifier_id::ExpectedSections;
use ergo_state::ChainStateRead;

// ----- helpers -----

/// Inventories in queue order, each as (modifier type, ids).
type Inventory = Vec<(u8, Vec<[u8; 32]>)>;

/// Alters a candidate after the production builder made it.
type Tamper = fn(&mut Candidate);

/// Compressed secp256k1 point the mined fixtures pay and sign with.
const MINER_PK: [u8; 33] = [0x02; 33];

/// Difficulty one: the target is the group order, so the first nonce
/// essentially always solves. It is the testnet genesis difficulty, which
/// the synthetic height-one fixtures ([`solved_block`]) run under.
const DIFFICULTY_ONE: u32 = 0x0101_0000;

/// A block solved against a cached candidate, as a miner would submit it.
struct SolvedBlock {
    candidate: Candidate,
    nonce: [u8; 8],
    id: [u8; 32],
    header_bytes: Vec<u8>,
    sections: ExpectedSections,
}

/// Solve a one-transaction block on `parent` whose header passes the real
/// header pipeline under the testnet difficulty schedule. Its roots commit
/// to its sections; `state_root` decides whether height one applies.
fn solved_block(
    parent: [u8; 32],
    height: u32,
    timestamp: u64,
    state_root: ADDigest,
) -> SolvedBlock {
    use ergo_crypto::autolykos::common::{blake2b256, calc_n};
    use ergo_primitives::digest::Digest32;
    use ergo_primitives::group_element::GroupElement;
    use ergo_ser::autolykos::AutolykosSolution;
    use ergo_ser::header::{serialize_header_without_pow, Header};
    use ergo_validation::pre_header::{
        build_last_block_utxo_root, CandidatePreHeader, CandidateValidationContext,
    };

    let transactions = vec![ergo_ser::transaction::Transaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
    }];
    let tx_id = *ergo_ser::transaction::transaction_id(&transactions[0])
        .unwrap()
        .as_bytes();
    let witness_id = blake2b256(&[])[1..].to_vec();
    let ad_proof_bytes = vec![1, 2, 3];
    let mut header = Header {
        version: 2,
        parent_id: ModifierId::from_bytes(parent),
        ad_proofs_root: Digest32::from_bytes(blake2b256(&ad_proof_bytes)),
        transactions_root: Digest32::from_bytes(ergo_crypto::merkle::transactions_root(
            &[&tx_id],
            Some(&[&witness_id]),
        )),
        state_root,
        timestamp,
        extension_root: Digest32::from_bytes(ergo_crypto::merkle::extension_root(&[])),
        n_bits: DIFFICULTY_ONE,
        height,
        votes: [0; 3],
        unparsed_bytes: Vec::new(),
        solution: AutolykosSolution::V2 {
            pk: GroupElement::from(MINER_PK),
            nonce: [0; 8],
        },
    };
    let candidate_header = header.clone();
    let msg = blake2b256(&serialize_header_without_pow(&header).unwrap());
    let target = ergo_crypto::difficulty::get_target(DIFFICULTY_ONE);
    let n = calc_n(header.version, height);
    let nonce = (0u64..)
        .map(u64::to_be_bytes)
        .find(|nonce| ergo_crypto::autolykos::v2::hit_for_v2(&msg, nonce, height, n) < target)
        .unwrap();
    header.solution = AutolykosSolution::V2 {
        pk: GroupElement::from(MINER_PK),
        nonce,
    };
    let (header_bytes, id) = serialize_header(&header).unwrap();
    let id = *id.as_bytes();
    let sections = ExpectedSections::from_header(
        &id,
        header.transactions_root.as_bytes(),
        header.extension_root.as_bytes(),
        header.ad_proofs_root.as_bytes(),
    );
    let candidate = Candidate {
        header: candidate_header,
        validation_ctx: CandidateValidationContext {
            pre_header: CandidatePreHeader {
                version: 2,
                parent_id: parent,
                height,
                timestamp,
                n_bits: DIFFICULTY_ONE,
                votes: [0; 3],
                miner_pubkey: MINER_PK,
            },
            activated_script_version: 2,
            last_headers: Vec::new(),
            last_block_utxo_root: build_last_block_utxo_root(state_root),
        },
        transactions,
        ad_proof_bytes,
        extension_fields: Vec::new(),
        msg,
        target,
        parent_id: parent,
    };
    SolvedBlock {
        candidate,
        nonce,
        id,
        header_bytes,
        sections,
    }
}

/// A synced mining handle on the testnet schedule serving `block`'s
/// candidate. [`genesis_state`] puts the executor on the same schedule.
fn mining_handle(block: &SolvedBlock) -> MiningHandle {
    let spec = ergo_chain_spec::ChainSpec::testnet();
    let handle = MiningHandle::new(MINER_PK, spec.monetary, None, spec.difficulty, spec.voting)
        .with_network(spec.network);
    let parent = block.candidate.parent_id;
    handle.set_best_tip(BestTip {
        parent_id: parent,
        chain_seq: 1,
        synced: true,
    });
    let work = ergo_mining::work_message::WorkMessage {
        msg: block.candidate.msg,
        target: block.candidate.target.clone(),
        height: block.candidate.header.height,
        pk: MINER_PK,
        metrics: Default::default(),
    };
    assert!(handle
        .publish_if_current(
            block.candidate.clone(),
            work,
            &parent,
            || 0,
            BuildReason::Tip
        )
        .is_some());
    handle
}

/// What the real `POST /mining/solution` handler did with one solution.
struct Submitted {
    result: Result<(), ergo_api::MiningApiError>,
    /// Whether the handler asked the action loop to rebuild the candidate
    /// on the current tip now.
    rebuild: bool,
}

/// Submit `nonce` through the real `POST /mining/solution` handler.
fn submit(state: &mut NodeState, handle: &MiningHandle, nonce: [u8; 8]) -> Submitted {
    let (reply, mut rx) = tokio::sync::oneshot::channel();
    let rebuild = super::super::mining_dispatch::handle_mining_request(
        state,
        Some(handle),
        false,
        crate::mining_bridge::MiningRequest::SubmitSolution {
            solution: ergo_rest_json::mining::AutolykosSolutionJson {
                pk: None,
                w: None,
                n: hex::encode(nonce),
                d: None,
            },
            reply,
        },
    );
    Submitted {
        result: rx
            .try_recv()
            .expect("the mining handler replies before returning"),
        rebuild,
    }
}

/// [`submit`], keeping only the reply.
fn submit_solution(
    state: &mut NodeState,
    handle: &MiningHandle,
    nonce: [u8; 8],
) -> Result<(), ergo_api::MiningApiError> {
    submit(state, handle, nonce).result
}

/// Fetch work through the real `GET /mining/candidate` handler.
fn get_candidate(
    state: &mut NodeState,
    handle: &MiningHandle,
) -> Result<ergo_rest_json::mining::WorkMessageJson, ergo_api::MiningApiError> {
    let (reply, mut rx) = tokio::sync::oneshot::channel();
    let rebuild = super::super::mining_dispatch::handle_mining_request(
        state,
        Some(handle),
        false,
        crate::mining_bridge::MiningRequest::GetCandidate { reply },
    );
    assert!(!rebuild, "serving work never asks for a rebuild");
    rx.try_recv()
        .expect("the mining handler replies before returning")
}

/// Submit `block` through the real `POST /blocks` loop handler; true when
/// the node answers 200.
fn post_block(state: &mut NodeState, block: &SolvedBlock) -> bool {
    let header_id = ModifierId::from_bytes(block.id);
    let mut bt = VlqWriter::new();
    ergo_ser::block_transactions::write_block_transactions_with_version(
        &mut bt,
        &ergo_ser::block_transactions::BlockTransactions {
            header_id,
            transactions: block.candidate.transactions.clone(),
        },
        block.candidate.header.version,
    )
    .unwrap();
    let mut ext = VlqWriter::new();
    ergo_ser::extension::write_extension(
        &mut ext,
        &ergo_ser::extension::Extension {
            header_id,
            fields: vec![],
        },
    )
    .unwrap();
    let mut proofs = VlqWriter::new();
    ergo_ser::ad_proofs::write_ad_proofs(
        &mut proofs,
        &ergo_ser::ad_proofs::ADProofs {
            header_id,
            proof_bytes: block.candidate.ad_proof_bytes.clone(),
        },
    );
    let (reply, mut rx) = tokio::sync::oneshot::channel();
    super::super::events::handle_event_batch(
        state,
        vec![PeerEvent::LocalFullBlock {
            header_bytes: block.header_bytes.clone(),
            bt_bytes: bt.result(),
            ext_bytes: ext.result(),
            ad_proofs_bytes: Some(proofs.result()),
            reply,
        }],
    );
    rx.try_recv()
        .expect("the POST /blocks handler replies before returning")
        .is_ok()
}

/// A fresh UTXO state at the empty genesis, returning its state root. The
/// executor runs the testnet difficulty schedule, as [`mining_handle`]
/// does.
fn genesis_state(dir: &Path) -> (NodeState, ADDigest) {
    let mut state = make_state(&dir.join("state.redb"));
    state.executor = SyncExecutor::new(
        ProtocolParams::mainnet_default(),
        ergo_chain_spec::ChainSpec::testnet().difficulty,
    );
    let store = state.store.as_utxo_mut().unwrap();
    store.initialize_genesis(&[]).unwrap();
    let root = store.root_digest();
    (state, root)
}

/// [`section_inventory`] for a synthetic solved block.
fn full_inventory(block: &SolvedBlock) -> Inventory {
    section_inventory(block.id, &block.sections)
}

/// The Inv set a block announces when every section is servable: header
/// first, then ADProofs, transactions and extension.
fn section_inventory(id: [u8; 32], sections: &ExpectedSections) -> Inventory {
    vec![
        (101, vec![id]),
        (104, vec![sections.ad_proofs_id]),
        (102, vec![sections.transactions_id]),
        (108, vec![sections.extension_id]),
    ]
}

/// [`section_inventory`] for a header already in the store.
fn stored_inventory(state: &NodeState, id: [u8; 32]) -> Inventory {
    let bytes = state.store.get_header(&id).unwrap().unwrap();
    let header = read_header(&mut VlqReader::new(&bytes)).unwrap();
    section_inventory(
        id,
        &ExpectedSections::from_header(
            &id,
            header.transactions_root.as_bytes(),
            header.extension_root.as_bytes(),
            header.ad_proofs_root.as_bytes(),
        ),
    )
}

/// Every announced id is served by the RequestModifier handler, and the
/// served bytes pass the check a receiving peer runs before accepting
/// them: the header hashes to its id, and each section re-hashes to the
/// id its header's root commits to.
fn assert_announced_ids_served(state: &mut NodeState, announced: &[(u8, Vec<[u8; 32]>)]) {
    for (kind, ids) in announced {
        let request = message::serialize_inv(&InvData {
            type_id: *kind,
            ids: ids.clone(),
        })
        .unwrap();
        let actions = handle_message(
            state,
            test_peer(),
            message::CODE_REQUEST_MODIFIER,
            &request,
            Instant::now(),
        );
        let [Action::SendToPeer { code, payload, .. }] = actions.as_slice() else {
            panic!("announced type {kind} id is not served: {actions:?}")
        };
        assert_eq!(*code, message::CODE_MODIFIER, "kind={kind}");
        let served = message::deserialize_modifiers(payload).unwrap();
        assert_eq!(served.type_id, *kind);
        let served_ids: Vec<_> = served.modifiers.iter().map(|(id, _)| *id).collect();
        assert_eq!(&served_ids, ids, "kind={kind}");
        for (id, bytes) in &served.modifiers {
            if *kind == 101 {
                assert_eq!(
                    ergo_crypto::autolykos::common::blake2b256(bytes),
                    *id,
                    "served header bytes hash to the announced id"
                );
            } else {
                ergo_sync::coordinator::verify_section_modifier_id(*kind, id, bytes)
                    .unwrap_or_else(|e| panic!("served type {kind} fails the peer check: {e}"));
            }
        }
    }
}

/// A devnet UTXO node at the shared testnet genesis state, with the
/// store, executor and mining handle on the devnet chain spec, as boot
/// wires them.
fn devnet_node(dir: &Path) -> (NodeState, MiningHandle) {
    let spec = ergo_chain_spec::ChainSpec::devnet();
    let mut store = StateStore::open_with_cache_launch_voting(
        &dir.join("state.redb"),
        StateStore::DEFAULT_CACHE_BYTES,
        ergo_validation::scala_launch_for_network(spec.network),
        spec.voting,
    )
    .unwrap();
    store.set_difficulty_params(spec.difficulty.clone());
    store
        .initialize_genesis(&crate::genesis::genesis_boxes_for(spec.network))
        .unwrap();
    let mut state = make_state_with_store(store);
    state.executor = SyncExecutor::new(ProtocolParams::mainnet_default(), spec.difficulty.clone());
    let handle = MiningHandle::new(
        MINER_PK,
        spec.monetary,
        spec.reemission,
        spec.difficulty,
        spec.voting,
    )
    .with_network(spec.network);
    (state, handle)
}

/// Point the handle at the applied tip as the action loop does once the
/// mining latch is closed.
fn sync_handle_to_tip(state: &NodeState, handle: &MiningHandle) -> ([u8; 32], u32) {
    let chain = state.store.chain_state_meta();
    handle.set_best_tip(BestTip {
        parent_id: chain.best_full_block_id,
        chain_seq: u64::from(chain.best_full_block_height) + 1,
        synced: true,
    });
    (chain.best_full_block_id, chain.best_full_block_height)
}

/// Build and publish the next candidate on the applied tip with the
/// production engine, as the off-loop build worker does.
fn publish_candidate(state: &NodeState, handle: &MiningHandle) {
    use ergo_mining::engine::{build_and_publish, BuildIntent, BuildOutcome};
    let (parent, height) = sync_handle_to_tip(state, handle);
    let intent = BuildIntent {
        expected_parent: parent,
        expected_height: height,
        mempool: std::sync::Arc::new(ergo_mempool::MempoolReadSnapshot::from_pool(&state.mempool)),
        miner_pk: MINER_PK,
        reason: BuildReason::Tip,
    };
    let outcome = build_and_publish(
        &state.store.as_utxo().unwrap().reader_handle(),
        handle,
        &intent,
        ergo_mining::candidate::BuildMode::Full,
        None,
        wall_clock_ms,
        |_, _| Vec::new(),
        &mut None,
    )
    .unwrap();
    assert!(
        matches!(outcome, BuildOutcome::Published { .. }),
        "{outcome:?}"
    );
}

/// Let the production clock advance so a same-parent build has a distinct header.
fn publish_candidate_after(state: &NodeState, handle: &MiningHandle, timestamp: u64) {
    while wall_clock_ms() <= timestamp {
        std::thread::sleep(Duration::from_millis(1));
    }
    publish_candidate(state, handle);
}

/// Build the next candidate with the production candidate builder, let
/// `tamper` alter it, recommit its PoW message to the altered header,
/// and publish it. Every header check still passes.
fn publish_tampered_candidate(
    state: &NodeState,
    handle: &MiningHandle,
    tamper: impl FnOnce(&mut Candidate),
) {
    let spec = ergo_chain_spec::ChainSpec::devnet();
    let (mut candidate, mut work, _) = ergo_mining::candidate::generate_candidate(
        state.store.as_utxo().unwrap(),
        spec.network,
        ergo_mining::candidate::BuildMode::Full,
        &ergo_mempool::MempoolReadSnapshot::empty(),
        &MINER_PK,
        &spec.monetary,
        spec.reemission.as_ref(),
        None,
        &spec.difficulty,
        &[],
        &std::collections::BTreeMap::new(),
        &spec.voting,
        &[],
        &mut Vec::new(),
    )
    .unwrap()
    .unwrap();
    tamper(&mut candidate);
    candidate.msg = ergo_crypto::autolykos::common::blake2b256(
        &ergo_ser::header::serialize_header_without_pow(&candidate.header).unwrap(),
    );
    work.msg = candidate.msg;
    let (parent, _) = sync_handle_to_tip(state, handle);
    assert!(handle
        .publish_if_current(candidate, work, &parent, wall_clock_ms, BuildReason::Tip)
        .is_some());
}

/// Model an admission/block-validation disagreement by seeding the pool directly.
/// The unrelated entry is the valid emission transaction from the same template.
fn seed_failed_tx_pool(
    state: &mut NodeState,
    unrelated: &ergo_ser::transaction::Transaction,
) -> (ergo_mempool::TxId, ergo_mempool::TxId) {
    let bad = ergo_ser::transaction::Transaction {
        inputs: vec![],
        data_inputs: vec![],
        output_candidates: vec![],
    };
    let mut ids = Vec::new();
    for tx in [&bad, unrelated] {
        let tx_id = ergo_mempool::TxId::from_bytes(
            *ergo_ser::transaction::transaction_id(tx)
                .unwrap()
                .as_bytes(),
        );
        let mut writer = VlqWriter::new();
        ergo_ser::transaction::write_transaction(&mut writer, tx).unwrap();
        let bytes = writer.result();
        let size = bytes.len() as u32;
        state
            .mempool
            .pool_mut()
            .insert(ergo_mempool::Entry::new(
                tx_id,
                bytes.into(),
                vec![],
                vec![],
                vec![],
                1,
                1,
                size,
                1,
                ergo_mempool::TxSource::Api,
            ))
            .unwrap();
        ids.push(tx_id);
    }
    (ids[0], ids[1])
}

fn publish_failed_tx_candidate(state: &NodeState, handle: &MiningHandle) -> Candidate {
    let mut saved = None;
    publish_tampered_candidate(state, handle, |candidate| {
        candidate
            .transactions
            .push(ergo_ser::transaction::Transaction {
                inputs: vec![],
                data_inputs: vec![],
                output_candidates: vec![],
            });
        let ids: Vec<_> = candidate
            .transactions
            .iter()
            .map(|tx| ergo_ser::transaction::transaction_id(tx).unwrap())
            .collect();
        let witnesses: Vec<_> = candidate
            .transactions
            .iter()
            .map(|tx| {
                let proofs: Vec<_> = tx
                    .inputs
                    .iter()
                    .flat_map(|i| i.spending_proof.proof.iter().copied())
                    .collect();
                ergo_crypto::autolykos::common::blake2b256(&proofs)[1..].to_vec()
            })
            .collect();
        candidate.header.transactions_root =
            ergo_primitives::digest::Digest32::from_bytes(ergo_crypto::merkle::transactions_root(
                &ids.iter()
                    .map(|id| id.as_bytes().as_slice())
                    .collect::<Vec<_>>(),
                Some(&witnesses.iter().map(Vec::as_slice).collect::<Vec<_>>()),
            ));
        saved = Some(candidate.clone());
    });
    saved.unwrap()
}

/// A solution to the newest published template.
struct MinedSolution {
    nonce: [u8; 8],
    id: [u8; 32],
    header: ergo_ser::header::Header,
}

/// The `skip`-th nonce that solves the newest published template at the
/// devnet's difficulty one, with the header it produces.
fn solve(state: &NodeState, handle: &MiningHandle, skip: usize) -> MinedSolution {
    use ergo_crypto::autolykos::common::calc_n;
    let work = handle.cached_work_if_synced().unwrap();
    // Autolykos v2's N depends only on height for every version >= 2.
    let n = calc_n(2, work.height);
    let nonce = (0u64..)
        .map(u64::to_be_bytes)
        .filter(|nonce| {
            ergo_crypto::autolykos::v2::hit_for_v2(&work.msg, nonce, work.height, n) < work.target
        })
        .nth(skip)
        .unwrap();
    let solution =
        ergo_mining::work_message::MinerSolution::from_hex(&hex::encode(nonce), None).unwrap();
    let ergo_mining::solution::SolutionOutcome::Accepted(block) = handle
        .verify_solution(&solution, state.store.as_utxo().unwrap())
        .unwrap()
    else {
        panic!("the newest template accepts its own solution")
    };
    let (_, id) = serialize_header(&block.header).unwrap();
    MinedSolution {
        nonce,
        id: *id.as_bytes(),
        header: block.header,
    }
}

/// Mine the next block with the production engine and apply it through
/// the real mining handler; returns its id.
fn mine_and_apply(state: &mut NodeState, handle: &MiningHandle) -> [u8; 32] {
    publish_candidate(state, handle);
    let mined = solve(state, handle, 0);
    let result = submit_solution(state, handle, mined.nonce);
    assert!(
        result.is_ok(),
        "{result:?}: {:?}",
        state.executor.last_block_apply_error()
    );
    assert_eq!(state.store.chain_state_meta().best_full_block_id, mined.id);
    mined.id
}

/// Mine the next block on the applied tip with the production engine
/// through the real mining handler, and check that it applies, is
/// announced once before apply with its header and all three sections,
/// is not announced again by apply, and has every announced id served.
/// Returns its id.
fn mine_announced_before_apply(
    state: &mut NodeState,
    handle: &MiningHandle,
    queue: &SharedQueue,
) -> [u8; 32] {
    let height = state.store.chain_state_meta().best_full_block_height + 1;
    publish_candidate(state, handle);
    let mined = solve(state, handle, 0);
    let probed = submit_probing_apply(state, handle, mined.nonce, queue);
    assert!(
        probed.result.is_ok(),
        "height {height}: {:?}: {:?}",
        probed.result,
        state.executor.last_block_apply_error()
    );
    let chain = state.store.chain_state_meta();
    assert_eq!(
        (chain.best_full_block_id, chain.best_full_block_height),
        (mined.id, height)
    );
    assert_eq!(
        probed.before_apply,
        stored_inventory(state, mined.id),
        "height {height}: the header and every section are announced before apply"
    );
    assert!(
        probed.after_apply.is_empty(),
        "height {height}: apply must not announce it again: {:?}",
        probed.after_apply
    );
    assert_announced_ids_served(state, &probed.before_apply);
    mined.id
}


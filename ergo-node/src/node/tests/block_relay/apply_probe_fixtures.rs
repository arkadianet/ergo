/// The ids of `inventory` that the store at `image` does not hold.
fn missing_from(image: &StateStore, inventory: &[(u8, Vec<[u8; 32]>)]) -> Vec<[u8; 32]> {
    inventory
        .iter()
        .flat_map(|(kind, ids)| ids.iter().map(move |id| (*kind, *id)))
        .filter(|(kind, id)| {
            let stored = if *kind == ModifierTypeId::Header.as_byte() {
                image.get_header(id).unwrap()
            } else {
                image.get_block_section(id).unwrap()
            };
            stored.is_none()
        })
        .map(|(_, id)| id)
        .collect()
}

/// While armed on a thread, drains the peer's queued frames when the
/// executor starts applying a block there (the `handle_assemble_block`
/// span is created), so a test can tell inventories queued before apply
/// from those queued after it. Armed for a crash image instead, it copies
/// the state database file at that moment.
///
/// It is this test binary's process-wide default subscriber, installed
/// once, not a scoped one: tracing caches a callsite's interest when the
/// first thread reaches it, and while a scoped probe is the only live
/// dispatcher, a thread without it caches `never` for every thread. The
/// global dispatcher takes part in every interest computation, so the
/// span is always created.
struct ApplyEntryProbe;

/// The probe armed on one thread: the queue it drains, and what it
/// drained when apply started.
struct ArmedProbe {
    queue: SharedQueue,
    before_apply: Option<Inventory>,
}

thread_local! {
    static ARMED_PROBE: std::cell::RefCell<Option<ArmedProbe>> =
        const { std::cell::RefCell::new(None) };
    /// The state database file and the path to copy it to when apply next
    /// starts on this thread.
    static ARMED_CRASH_IMAGE: std::cell::RefCell<Option<(std::path::PathBuf, std::path::PathBuf)>> =
        const { std::cell::RefCell::new(None) };
}

fn is_apply_entry(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_span() && metadata.name() == "handle_assemble_block"
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ApplyEntryProbe {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if is_apply_entry(metadata) {
            tracing::subscriber::Interest::always()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        is_apply_entry(metadata)
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if !is_apply_entry(attrs.metadata()) {
            return;
        }
        ARMED_PROBE.with(|armed| {
            if let Some(probe) = armed.borrow_mut().as_mut() {
                if probe.before_apply.is_none() {
                    probe.before_apply = Some(drain(&probe.queue));
                }
            }
        });
        ARMED_CRASH_IMAGE.with(|armed| {
            if let Some((database, image)) = armed.borrow_mut().take() {
                std::fs::copy(database, image).expect("copy the state database");
            }
        });
    }
}

/// Make [`ApplyEntryProbe`] the process-wide default subscriber.
fn install_apply_entry_probe() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(ApplyEntryProbe),
        )
        .expect("no other ergo-node lib test installs a global subscriber");
    });
    // A thread that registered the span's callsite while the probe was
    // being installed can have cached a stale interest; recompute it.
    tracing::callsite::rebuild_interest_cache();
}

/// A handshaked peer whose outbound queue the test and an
/// [`ApplyEntryProbe`] share.
type SharedQueue = std::sync::Arc<std::sync::Mutex<crate::peer_loop::outbound::Receiver>>;

fn register_shared_peer(state: &mut NodeState) -> SharedQueue {
    std::sync::Arc::new(std::sync::Mutex::new(register_connected_peer(
        state,
        test_peer(),
    )))
}

fn drain(queue: &SharedQueue) -> Inventory {
    inventories(&mut queue.lock().unwrap())
}

/// What one probed submission did and queued for the peer.
struct ProbedSubmission {
    result: Result<(), ergo_api::MiningApiError>,
    /// Whether the handler asked the action loop to rebuild the candidate
    /// on the current tip now.
    rebuild: bool,
    before_apply: Inventory,
    after_apply: Inventory,
}

/// [`submit`] with an [`ApplyEntryProbe`] armed on the peer queue. Also
/// returns what the probe drained when apply started, or `None` when the
/// handler never started apply.
fn submit_armed(
    state: &mut NodeState,
    handle: &MiningHandle,
    nonce: [u8; 8],
    queue: &SharedQueue,
) -> (Submitted, Option<Inventory>) {
    install_apply_entry_probe();
    ARMED_PROBE.with(|armed| {
        *armed.borrow_mut() = Some(ArmedProbe {
            queue: queue.clone(),
            before_apply: None,
        })
    });
    let submitted = submit(state, handle, nonce);
    let probe = ARMED_PROBE
        .with(|armed| armed.borrow_mut().take())
        .expect("the probe stays armed until the submission returns");
    (submitted, probe.before_apply)
}

/// Submit `nonce` through the real mining handler with an
/// [`ApplyEntryProbe`] armed on the peer queue; the handler must start
/// apply.
fn submit_probing_apply(
    state: &mut NodeState,
    handle: &MiningHandle,
    nonce: [u8; 8],
    queue: &SharedQueue,
) -> ProbedSubmission {
    let (submitted, before_apply) = submit_armed(state, handle, nonce, queue);
    let Some(before_apply) = before_apply else {
        panic!(
            "the handler never started apply: {:?}: {:?}",
            submitted.result,
            state.executor.last_block_apply_error()
        )
    };
    ProbedSubmission {
        result: submitted.result,
        rebuild: submitted.rebuild,
        before_apply,
        after_apply: drain(queue),
    }
}

/// Run `submit` and copy the state database file when apply starts: what
/// a process killed at that moment leaves on disk, since redb holds a
/// commit made with `Durability::None` in memory until a durable commit
/// follows. Returns the copy, opened as a store.
fn crash_image_at_apply(
    state: &mut NodeState,
    dir: &Path,
    submit: impl FnOnce(&mut NodeState),
) -> StateStore {
    install_apply_entry_probe();
    let image = dir.join("crash-image.redb");
    let database = state.store.database_path().to_path_buf();
    ARMED_CRASH_IMAGE.with(|armed| *armed.borrow_mut() = Some((database, image.clone())));
    submit(state);
    assert!(
        ARMED_CRASH_IMAGE
            .with(|armed| armed.borrow_mut().take())
            .is_none(),
        "the handler never started apply: {:?}",
        state.executor.last_block_apply_error()
    );
    StateStore::open(&image).unwrap()
}

/// A solved header on `parent`, one height up, at difficulty one.
fn solved_child(parent: &ergo_ser::header::Header, parent_id: [u8; 32]) -> Vec<u8> {
    use ergo_crypto::autolykos::common::{blake2b256, calc_n};
    let mut child = parent.clone();
    child.parent_id = ModifierId::from_bytes(parent_id);
    child.height = parent.height + 1;
    child.timestamp = parent.timestamp + 1;
    let msg = blake2b256(&ergo_ser::header::serialize_header_without_pow(&child).unwrap());
    let target = ergo_crypto::difficulty::get_target(child.n_bits);
    let n = calc_n(child.version, child.height);
    let nonce = (0u64..)
        .map(u64::to_be_bytes)
        .find(|nonce| ergo_crypto::autolykos::v2::hit_for_v2(&msg, nonce, child.height, n) < target)
        .unwrap();
    child.solution = ergo_ser::autolykos::AutolykosSolution::V2 {
        pk: ergo_primitives::group_element::GroupElement::from(MINER_PK),
        nonce,
    };
    serialize_header(&child).unwrap().0
}

/// Solve the current published candidate without submitting it.
fn prepared_solution(state: &NodeState, handle: &MiningHandle) -> ergo_mining::submit::MinedBlock {
    let mined = solve(state, handle, 0);
    let solution =
        ergo_mining::work_message::MinerSolution::from_hex(&hex::encode(mined.nonce), None)
            .unwrap();
    let ergo_mining::solution::SolutionOutcome::Accepted(block) = handle
        .verify_solution(&solution, state.store.as_utxo().unwrap())
        .unwrap()
    else {
        panic!("valid fixture solution");
    };
    ergo_mining::submit::prepare_mined_block(state.store.as_utxo().unwrap(), block).unwrap()
}

/// Drain stored blocks through the normal sequential executor.
fn drain_prepared(state: &mut NodeState) {
    state.executor.try_apply_next_blocks(
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
}

/// Validate a peer header through the remote executor path.
fn remote_header(state: &mut NodeState, bytes: &[u8]) {
    let id = *ergo_primitives::digest::blake2b256(bytes).as_bytes();
    let actions = state.executor.execute(
        Action::ValidateHeader {
            peer: test_peer(),
            modifier_id: id,
            header_bytes: bytes.to_vec(),
        },
        &mut state.store,
        &mut state.coordinator,
        Instant::now(),
        None,
    );
    assert!(!actions.iter().any(|a| matches!(a, Action::Penalize { .. })));
    assert!(state.store.get_header(&id).unwrap().is_some());
}

/// Deliver requested sections from a peer; optionally run assembly actions.
fn remote_sections(source: &NodeState, target: &mut NodeState, id: [u8; 32], assemble: bool) {
    for (kind, ids) in stored_inventory(source, id) {
        if kind == ModifierTypeId::Header.as_byte() {
            continue;
        }
        for section in ids {
            let bytes = source.store.get_block_section(&section).unwrap().unwrap();
            let now = Instant::now();
            target
                .coordinator
                .delivery_mut()
                .request(test_peer(), kind, &[section], now);
            let actions =
                target
                    .coordinator
                    .on_modifier_received(test_peer(), kind, section, bytes, now);
            assert!(!actions.iter().any(|a| matches!(a, Action::Penalize { .. })));
            for action in actions {
                if !assemble && matches!(action, Action::AssembleBlock { .. }) {
                    continue;
                }
                target.executor.execute(
                    action,
                    &mut target.store,
                    &mut target.coordinator,
                    now,
                    None,
                );
            }
        }
    }
}

/// Exercise a sibling arriving before or after failure, on either backend.
fn session_sibling(later: bool, digest: bool, assemble: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (mut source, handle) = devnet_node(dir.path());
    let mut state = if digest {
        digest_peer(&mut source, dir.path())
    } else {
        let path = dir.path().join("peer");
        std::fs::create_dir(&path).unwrap();
        devnet_node(&path).0
    };
    let parent = mine_and_apply(&mut source, &handle);
    copy_remote_block(&source, &mut state, parent);
    drain_prepared(&mut state);
    publish_candidate(&source, &handle);
    let sibling = prepared_solution(&source, &handle);
    publish_tampered_candidate(&source, &handle, replace_state_root);
    let bad = prepared_solution(&source, &handle);
    for block in [&bad, &sibling] {
        process_header(&mut source, &block.header_bytes);
        ergo_mining::submit::store_mined_sections(source.store.as_utxo().unwrap(), block).unwrap();
    }
    remote_header(&mut state, &bad.header_bytes);
    if !later {
        remote_header(&mut state, &sibling.header_bytes);
        // Recovery seeds the best chain only: the sibling has neither a
        // pending entry nor an assembly registration in this coordinator.
        state.coordinator = SyncCoordinator::new(1);
        state.coordinator.set_requires_proofs(digest);
    }
    remote_sections(&source, &mut state, bad.header_id, false);
    if assemble {
        state.executor.execute(
            Action::AssembleBlock {
                header_id: bad.header_id,
            },
            &mut state.store,
            &mut state.coordinator,
            Instant::now(),
            None,
        );
    } else {
        drain_prepared(&mut state);
    }
    assert!(state.store.is_invalid(&bad.header_id).unwrap());
    assert!(!state.store.is_durably_invalid(&bad.header_id).unwrap());
    if later {
        remote_header(&mut state, &sibling.header_bytes);
    }
    assert_eq!(
        state.store.chain_state_meta().best_header_id,
        sibling.header_id
    );
    let actions = state.coordinator.request_missing_sections_bucketed(
        &state.store,
        Instant::now(),
        &[test_peer()],
    );
    if !later {
        assert!(state
            .coordinator
            .sync_state()
            .pending_blocks_iter()
            .any(|b| b.header_id == sibling.header_id));
        assert!(
            actions.iter().any(|a| match a {
                Action::SendToPeer { code, payload, .. }
                    if *code == message::CODE_REQUEST_MODIFIER =>
                {
                    let inv = message::deserialize_inv(payload).unwrap();
                    stored_inventory(&source, sibling.header_id)
                        .iter()
                        .any(|(kind, ids)| {
                            *kind == inv.type_id && ids.iter().any(|id| inv.ids.contains(id))
                        })
                }
                _ => false,
            }),
            "promoted sibling must emit a section request: {actions:?}"
        );
    }
    remote_sections(&source, &mut state, sibling.header_id, true);
    drain_prepared(&mut state);
    assert_eq!(
        state.store.chain_state_meta().best_full_block_id,
        sibling.header_id
    );
    if digest {
        // A heavier header extension changes header selection, but cannot
        // roll back the applied sibling while its bodies are unavailable.
        let child = solved_child(
            &read_header(&mut VlqReader::new(&bad.header_bytes)).unwrap(),
            bad.header_id,
        );
        remote_header(&mut state, &child);
        drain_prepared(&mut state);
        assert_eq!(
            state.store.chain_state_meta().best_header_id,
            *ergo_primitives::digest::blake2b256(&child).as_bytes()
        );
        assert_eq!(
            state.store.get_header_id_at_height(2).unwrap(),
            Some(bad.header_id)
        );
        assert_eq!(
            state.store.chain_state_meta().best_full_block_id,
            sibling.header_id
        );
    }
}


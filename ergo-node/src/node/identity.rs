//! Mode-label projection, `/api/v1/identity` payload builder, and the
//! runtime-side activation gate that refuses to start with a config
//! combo the rest of the runtime doesn't yet support. Pure functions
//! over [`NodeConfig`].

use crate::config::NodeConfig;

use super::NodeError;

/// Bootstrap provenance inferred from store state. Used at boot
/// to refine the operator-facing mode label so a post-bootstrap
/// restart says "popow-bootstrapped" rather than collapsing to
/// the same string as a UTXO snapshot install. The protocol-level
/// projection (handshake `blocks_to_keep`, /identity history_mode)
/// follows Scala parity: config-driven, not sentinel-derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapKind {
    /// No detectable bootstrap state.
    None,
    /// Mode 2 UTXO snapshot install. Detected by
    /// `header_availability == Dense` AND the persistent
    /// `UTXO_BOOTSTRAP_INSTALLED_V1` provenance marker present
    /// (install does NOT rewrite the header_availability field).
    Utxo,
    /// NiPoPoW dense-from jump. Detected by
    /// `header_availability == PoPowSparse`.
    Nipopow,
    /// Both bootstrap mechanisms ran (Mode 4 with composed
    /// install + proof). Detected by `PoPowSparse` header
    /// availability AND the persistent UTXO bootstrap marker.
    /// Surfaced as a distinct variant so the operator label can
    /// name both provenance sources rather than silently
    /// dropping one — `mode_label_for_inputs` emits
    /// `"utxo+popow-bootstrapped"` for this case.
    Both,
}

/// Compose the human-readable mode label exposed via `/api/v1/identity`
/// from the three protocol-visible dimensions: `state_type`,
/// `verify_transactions`, and `blocks_to_keep`.
///
/// Live arms today: Mode 1 (archive), Mode 2 (utxo-bootstrapped via
/// the `utxo_bootstrap` short-circuit), Mode 3 (pruned, `n > 0` after
/// the rollback-window floor check), and Mode 6 (canonical
/// headers-only, `(Digest, false, 0)`). Mode 5 (Digest Verifier
/// without headers-only) is the remaining deferred arm.
#[cfg(test)]
pub(crate) fn mode_label_for(config: &NodeConfig) -> String {
    mode_label_for_inputs(&IdentityInputs::from_config(config), 1, BootstrapKind::None)
}

/// Cached `NodeConfig` fields the `/api/v1/identity` builder
/// reads. Held on `NodeState` so the post-bootstrap refresh
/// path can rebuild identity without holding the full
/// `NodeConfig` (which is consumed at boot and not Clone-able
/// as a whole).
#[derive(Clone, Debug)]
pub struct IdentityInputs {
    pub state_type: crate::config::StateType,
    pub verify_transactions: bool,
    pub blocks_to_keep: i32,
    /// Configured undo-retention window (`[node] keep_versions`); the
    /// pruning floor below is keyed to IT, not the compile-time default,
    /// so raising or lowering the window can't strand a loader-accepted
    /// `blocks_to_keep` at this defensive re-check.
    pub keep_versions: u32,
    pub utxo_bootstrap: bool,
    pub nipopow_bootstrap: bool,
    pub mining_enabled: bool,
    pub extra_index_enabled: bool,
    pub declared_addr: Option<std::net::SocketAddr>,
    pub bind_addr: Option<std::net::SocketAddr>,
}

impl IdentityInputs {
    pub fn from_config(config: &NodeConfig) -> Self {
        Self {
            state_type: config.state_type,
            verify_transactions: config.verify_transactions,
            blocks_to_keep: config.blocks_to_keep,
            keep_versions: config.keep_versions,
            utxo_bootstrap: config.utxo_bootstrap,
            nipopow_bootstrap: config.nipopow_bootstrap,
            mining_enabled: config.mining_config.enabled,
            extra_index_enabled: config.indexer_config.enabled,
            declared_addr: config.declared_addr,
            bind_addr: config.bind_addr,
        }
    }
}

/// Operating mode classification for a `NodeConfig`. The
/// `classify_node_mode` projection maps an `IdentityInputs` to
/// exactly one variant. Intended as the dispatch surface for
/// Mode 4 orchestration when the boot path needs to branch on
/// the configured mode; it is also the foundation for the
/// runtime mode-coherence checks.
///
/// The Scala node has no equivalent enum — it derives behavior
/// from the same field cross-product on demand. The enum here is
/// a Rust-side convenience that MUST stay consistent with the
/// rest of the runtime's mode predicates (storage gate, identity
/// label, config gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeMode {
    /// Mode 1 — full archive: utxo + verify_tx + keep = -1.
    Archive,
    /// Mode 2 — UTXO snapshot bootstrap without pruning. NiPoPoW
    /// may augment the header sync but the steady state is
    /// archive-shaped post-install.
    UtxoBootstrap { with_nipopow: bool },
    /// Mode 3 — pruned suffix window, no bootstrap mechanism.
    Pruned { keep: u32 },
    /// Mode 4 — pruned + bootstrap. At least one of `utxo` /
    /// `nipopow` is true; both true is the composed-bootstrap
    /// case.
    PrunedBootstrap {
        keep: u32,
        utxo: bool,
        nipopow: bool,
    },
    /// Mode 5 — Digest Verifier (deferred): digest + verify_tx +
    /// keep = -1. Reachable through classification but rejected at
    /// the runtime activation gate.
    DigestVerifier,
    /// Mode 6 — canonical headers-only: digest + !verify_tx +
    /// keep = 0 + !utxo_bootstrap. NiPoPoW may augment the header
    /// bootstrap (Scala parity: R3's `blocks_to_keep >= 0` arm
    /// admits this combo via the keep=0 case) but the
    /// orchestrator does not yet exercise that path.
    HeadersOnly { with_nipopow: bool },
    /// Any combination not covered by the Mode 1-6 taxonomy. The
    /// `reason` is a static string describing which axis violates
    /// the canonical shapes; the config loader rejects these
    /// combos at TOML time, so production callers should never see
    /// this variant.
    Invalid { reason: &'static str },
}

/// NiPoPoW bootstrap reducer resume-state classification. The
/// function is total over `(nipopow_bootstrap_enabled,
/// best_header_height, best_full_block_height,
/// header_availability)`; every store shape maps to exactly one
/// state.
///
/// `PartialHeaderSync` is classified but NOT a supported resume
/// state today: the reducer's constructor at
/// `ergo-sync/src/popow_bootstrap.rs` is contract-fresh-only, and
/// `apply_popow_proof` returns `ApplyPopowProofWrongMode` on a
/// non-fresh store. The boot path refuses to start on this row
/// rather than arming a reducer whose proof apply would later
/// trigger the sync-tick's terminal mark_applied. Lifting that
/// restriction needs new reducer + apply-path machinery and is
/// out of scope for the initial Mode 4 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NipopowResumeState {
    /// `nipopow_bootstrap = false`. No reducer is needed.
    Disabled,
    /// Fresh store — no headers yet. Arm a new reducer.
    Fresh,
    /// Headers partially downloaded but no full block ever
    /// applied. NOT resumable today; the boot path refuses on
    /// this row.
    PartialHeaderSync,
    /// Store has applied at least one full block; the
    /// `best_full_block_height > 0` discriminator marks it as a
    /// normal (non-bootstrap) store. DO NOT arm the reducer.
    NormalStore,
    /// `header_availability == PoPowSparse` — the proof has
    /// already been committed by a previous `apply_popow_proof`.
    /// Skip the reducer; the node is already in Mode 4.
    ProofCommitted,
}

/// Classify the NiPoPoW reducer resume state for a store.
///
/// The function takes the relevant chain-state fields directly
/// (rather than a `&ChainState` reference) so the unit tests can
/// drive every row of the truth table without constructing a
/// real `StateStore`. The boot path passes
/// `chain_state.header_availability`,
/// `chain_state.best_header_height`,
/// `chain_state.best_full_block_height` straight through.
pub fn classify_nipopow_resume(
    nipopow_bootstrap_enabled: bool,
    header_availability: &ergo_state::chain::HeaderAvailability,
    best_header_height: u32,
    best_full_block_height: u32,
) -> NipopowResumeState {
    if !nipopow_bootstrap_enabled {
        return NipopowResumeState::Disabled;
    }
    if matches!(
        header_availability,
        ergo_state::chain::HeaderAvailability::PoPowSparse { .. },
    ) {
        return NipopowResumeState::ProofCommitted;
    }
    // header_availability == Dense from here. The load-bearing
    // discriminator: best_full_block_height > 0 means at least
    // one full block has been applied, which is incompatible with
    // bootstrap resume regardless of header state.
    if best_full_block_height > 0 {
        return NipopowResumeState::NormalStore;
    }
    if best_header_height == 0 {
        NipopowResumeState::Fresh
    } else {
        NipopowResumeState::PartialHeaderSync
    }
}

/// Should the boot path engage the UTXO snapshot install
/// machinery? Returns `true` only when:
/// - the operator configured `utxo_bootstrap = true`, AND
/// - no full block has ever been applied
///   (`best_full_block_height == 0`), AND
/// - the persistent `UTXO_BOOTSTRAP_INSTALLED_V1` provenance
///   marker is absent (`!install_already_committed`).
///
/// The combination prevents re-install on subsequent boots with
/// the same Mode 4 config AND defends against the pathological
/// case where the marker is armed but full-block state was lost.
pub fn should_engage_utxo_install(
    config_utxo_bootstrap: bool,
    best_full_block_height: u32,
    install_already_committed: bool,
) -> bool {
    config_utxo_bootstrap && best_full_block_height == 0 && !install_already_committed
}

/// Classify `IdentityInputs` into exactly one `NodeMode`. The
/// projection is total: every combination of input fields maps
/// somewhere, with `Invalid` capturing the non-canonical shapes
/// the config loader rejects.
///
/// Cross-references that MUST stay in lockstep with the TOML
/// loader in `ergo-node/src/config/load.rs`:
/// - sub-floor pruning windows (`0 < keep < ROLLBACK_WINDOW +
///   SAFETY_MARGIN`)
/// - indexer + pruning, indexer + utxo_bootstrap (both rejected
///   because extra-index requires the full archive)
/// - nipopow_bootstrap without a downstream consumer
///   (`utxo_bootstrap` or pruning)
pub fn classify_node_mode(inputs: &IdentityInputs) -> NodeMode {
    use crate::config::StateType;

    // Indexer combos that the TOML loader rejects at
    // `config/load.rs:223,230`. Mirror the rejection here so
    // programmatic NodeConfig construction can't reach a
    // misclassified mode.
    if inputs.extra_index_enabled {
        if inputs.blocks_to_keep >= 0 {
            return NodeMode::Invalid {
                reason: "extra-index requires full archive (incompatible with blocks_to_keep >= 0)",
            };
        }
        if inputs.utxo_bootstrap {
            return NodeMode::Invalid {
                reason: "extra-index requires full archive (incompatible with utxo_bootstrap)",
            };
        }
    }

    // R3 (config/load.rs:253): nipopow_bootstrap requires a
    // downstream consumer — either utxo_bootstrap or a non-archive
    // blocks_to_keep value. Hoisted above the state_type dispatch
    // so a digest config with nipopow_bootstrap = true does not
    // misclassify as DigestVerifier.
    if inputs.nipopow_bootstrap && !(inputs.utxo_bootstrap || inputs.blocks_to_keep >= 0) {
        return NodeMode::Invalid {
            reason: "nipopow_bootstrap requires utxo_bootstrap or blocks_to_keep >= 0",
        };
    }

    // Digest-backed arms — Modes 5 and 6, plus the obvious
    // invalid combos.
    if inputs.state_type == StateType::Digest {
        if inputs.utxo_bootstrap {
            // Snapshot bootstrap installs a UTXO tree; nothing in
            // digest mode can consume it.
            return NodeMode::Invalid {
                reason: "digest backend cannot install a UTXO snapshot",
            };
        }
        if !inputs.verify_transactions && inputs.blocks_to_keep == 0 {
            // Mode 6 + nipopow_bootstrap is admitted by R3 via the
            // keep >= 0 arm (Scala-parity:
            // `ErgoSettingsReader.consistentSettings:191-194`).
            // Surface the flag in the variant instead of dropping
            // it so any downstream dispatch can decide whether to
            // exercise the path.
            return NodeMode::HeadersOnly {
                with_nipopow: inputs.nipopow_bootstrap,
            };
        }
        if inputs.verify_transactions && inputs.blocks_to_keep == -1 {
            // Mode 5 (digest verifier) is deferred; the runtime
            // gate at `validate_runtime_mode_support` rejects boot
            // attempts. Classification still names the mode so the
            // operator's diagnostic surface knows what they
            // intended.
            return NodeMode::DigestVerifier;
        }
        return NodeMode::Invalid {
            reason: "digest combo outside Mode 5 / Mode 6 canonical shapes",
        };
    }

    // Utxo backend without verify_transactions has no defined
    // mode — the validation core is the whole point of the utxo
    // backend.
    if !inputs.verify_transactions {
        return NodeMode::Invalid {
            reason: "utxo backend requires verify_transactions",
        };
    }

    match inputs.blocks_to_keep {
        -1 => {
            // R3 already filtered `nipopow_bootstrap` without a
            // consumer above; only `utxo_bootstrap=true` or
            // neither flag reaches this arm.
            if inputs.utxo_bootstrap {
                NodeMode::UtxoBootstrap {
                    with_nipopow: inputs.nipopow_bootstrap,
                }
            } else {
                NodeMode::Archive
            }
        }
        n if n > 0 => {
            // Sub-floor pruning windows are rejected by the
            // config loader (`config/load.rs:285`) because a
            // reorg into the pruned region would need section
            // bytes the wallet replay path can't reconstruct.
            // Mirror that rejection here.
            let floor =
                i64::from(inputs.keep_versions) + i64::from(ergo_state::store::SAFETY_MARGIN);
            if i64::from(n) < floor {
                return NodeMode::Invalid {
                    reason: "blocks_to_keep is below the rollback-window floor",
                };
            }
            let keep = n as u32;
            if inputs.utxo_bootstrap || inputs.nipopow_bootstrap {
                NodeMode::PrunedBootstrap {
                    keep,
                    utxo: inputs.utxo_bootstrap,
                    nipopow: inputs.nipopow_bootstrap,
                }
            } else {
                NodeMode::Pruned { keep }
            }
        }
        // blocks_to_keep == 0 reaches here only when state_type ==
        // Utxo, which violates the canonical Mode 6 shape. The
        // config loader rejects this at TOML time; we mirror the
        // rejection in the classifier so direct NodeConfig
        // construction can't reach a misclassified mode.
        0 => NodeMode::Invalid {
            reason: "blocks_to_keep = 0 is reserved for the canonical Mode 6 combo",
        },
        _ => NodeMode::Invalid {
            reason: "blocks_to_keep < -1 is not a valid sentinel",
        },
    }
}

/// Detect the live `BootstrapKind` for a store. Pulled out so
/// boot and the post-bootstrap refresh path agree on the
/// detection rule and can't drift. Returns `Err` when the
/// `UTXO_BOOTSTRAP_INSTALLED_V1` provenance read fails: callers
/// must surface that failure rather than silently downgrading
/// to `None`, which would misreport a real Mode 2 install as
/// `post-prune archive`.
pub fn detect_bootstrap_kind(
    store: &ergo_state::store::StateStore,
    sentinel: u32,
) -> Result<BootstrapKind, NodeError> {
    let was_utxo_bootstrapped = store.was_utxo_bootstrapped().map_err(|e| -> NodeError {
        format!("cannot read UTXO_BOOTSTRAP_INSTALLED_V1 provenance: {e}").into()
    })?;
    let kind = match (
        sentinel,
        &store.chain_state().header_availability,
        was_utxo_bootstrapped,
    ) {
        // PoPowSparse + UTXO marker = both bootstraps ran (Mode 4
        // composed lifecycle). Surface as a distinct variant so
        // the operator label can name both provenance sources.
        (s, ergo_state::chain::HeaderAvailability::PoPowSparse { .. }, true) if s > 1 => {
            BootstrapKind::Both
        }
        (s, ergo_state::chain::HeaderAvailability::PoPowSparse { .. }, false) if s > 1 => {
            BootstrapKind::Nipopow
        }
        (s, ergo_state::chain::HeaderAvailability::Dense, true) if s > 1 => BootstrapKind::Utxo,
        _ => BootstrapKind::None,
    };
    Ok(kind)
}

/// Rebuild `ApiIdentity` from cached config inputs plus the
/// current store-derived sentinel and bootstrap provenance, and
/// publish into the given lock-free slot. Returns `Ok(())` on
/// success, `Err(_)` with a human-readable reason on failure so
/// callers can log the staleness rather than swallowing it
/// silently.
pub fn rebuild_and_publish_identity(
    store: &ergo_state::store::StateStore,
    inputs: &IdentityInputs,
    slot: &crate::api_bridge::IdentitySlot,
) -> Result<(), NodeError> {
    let sentinel = store
        .read_minimal_full_block_height()
        .map_err(|e| -> NodeError {
            format!("identity refresh: cannot read prune sentinel: {e}").into()
        })?;
    let bootstrap_kind = detect_bootstrap_kind(store, sentinel)?;
    let identity = build_api_identity_from_inputs(inputs, sentinel, bootstrap_kind)?;
    slot.store(std::sync::Arc::new(identity));
    Ok(())
}

/// Rebuild `ApiIdentity` from cached config inputs plus the
/// current store-derived sentinel and bootstrap provenance.
/// Called from the action loop on bootstrap transitions
/// (post-`install_snapshot_state`, post-`apply_popow_proof`) so
/// `/api/v1/identity` reflects live state instead of the
/// boot-time snapshot.
pub(crate) fn build_api_identity_from_inputs(
    inputs: &IdentityInputs,
    boot_sentinel: u32,
    bootstrap_kind: BootstrapKind,
) -> Result<ergo_api::types::ApiIdentity, NodeError> {
    use crate::config::StateType;
    use ergo_api::types::ApiHistoryMode;

    if inputs.state_type == StateType::Digest
        && !inputs.verify_transactions
        && inputs.blocks_to_keep == 0
        && inputs.utxo_bootstrap
    {
        return Err(
            "IdentityInputs: headers-only + utxo_bootstrap=true is a contradictory mode.".into(),
        );
    }
    let history_mode = if inputs.state_type == StateType::Digest
        && !inputs.verify_transactions
        && inputs.blocks_to_keep == 0
    {
        ApiHistoryMode::HeadersOnly
    } else if inputs.utxo_bootstrap {
        ApiHistoryMode::UtxoBootstrapped
    } else if inputs.blocks_to_keep == -1 {
        ApiHistoryMode::Archive
    } else if inputs.blocks_to_keep >= 1 {
        ApiHistoryMode::Pruned {
            suffix_len: inputs.blocks_to_keep as u32,
        }
    } else {
        return Err(format!(
            "unreachable history_mode combo: state_type={} verify_tx={} blocks_to_keep={} utxo_bootstrap={}",
            inputs.state_type.as_str(),
            inputs.verify_transactions,
            inputs.blocks_to_keep,
            inputs.utxo_bootstrap,
        )
        .into());
    };
    let utxo_bootstrap_effective = inputs.utxo_bootstrap
        || matches!(bootstrap_kind, BootstrapKind::Utxo | BootstrapKind::Both);
    let nipopow_bootstrap_effective = inputs.nipopow_bootstrap
        || matches!(bootstrap_kind, BootstrapKind::Nipopow | BootstrapKind::Both);
    Ok(ergo_api::types::ApiIdentity {
        mode: mode_label_for_inputs(inputs, boot_sentinel, bootstrap_kind),
        state_type: match inputs.state_type {
            StateType::Utxo => ergo_api::types::ApiStateType::Utxo,
            StateType::Digest => ergo_api::types::ApiStateType::Digest,
        },
        verify_transactions: inputs.verify_transactions,
        history_mode,
        utxo_bootstrap: utxo_bootstrap_effective,
        nipopow_bootstrap: nipopow_bootstrap_effective,
        mining: inputs.mining_enabled,
        extra_index_enabled: inputs.extra_index_enabled,
        declared_addr: inputs.declared_addr.map(|a| a.to_string()),
        bind_addr: inputs.bind_addr.map(|a| a.to_string()),
    })
}

/// `mode_label_for_with_state` variant operating on cached
/// `IdentityInputs` so the action loop can refresh the label
/// without holding the full `NodeConfig`.
fn mode_label_for_inputs(
    inputs: &IdentityInputs,
    boot_sentinel: u32,
    bootstrap_kind: BootstrapKind,
) -> String {
    use crate::config::StateType;

    // Mode 4 — pruned + bootstrap. Detected when:
    // - `state_type = utxo, verify_tx = true, blocks_to_keep > 0`
    // - AND at least one bootstrap source is active, either by
    //   operator config (`utxo_bootstrap` / `nipopow_bootstrap`)
    //   or by detected runtime provenance
    //   (`BootstrapKind::Utxo / Nipopow / Both`).
    // The Mode 4 arm runs BEFORE the Mode 2 short-circuit so a
    // `(utxo_bootstrap = true, blocks_to_keep > 0)` config
    // doesn't collapse to the "utxo-bootstrapped" Mode 2 label.
    if inputs.state_type == StateType::Utxo
        && inputs.verify_transactions
        && inputs.blocks_to_keep > 0
    {
        let utxo_active = inputs.utxo_bootstrap
            || matches!(bootstrap_kind, BootstrapKind::Utxo | BootstrapKind::Both);
        let popow_active = inputs.nipopow_bootstrap
            || matches!(bootstrap_kind, BootstrapKind::Nipopow | BootstrapKind::Both);
        let bootstrap_suffix = match (utxo_active, popow_active) {
            (true, true) => Some("utxo+popow-bootstrapped"),
            (true, false) => Some("utxo-bootstrapped"),
            (false, true) => Some("popow-bootstrapped"),
            (false, false) => None,
        };
        if let Some(suffix) = bootstrap_suffix {
            return format!("mode-4 · {suffix} · keep {}", inputs.blocks_to_keep);
        }
    }

    // Mode 2 short-circuit: `utxo_bootstrap = true` with an
    // archive-shaped config labels as utxo-bootstrapped. Mode 4
    // already fired above for the `blocks_to_keep > 0` rows.
    if inputs.utxo_bootstrap && inputs.state_type == StateType::Utxo && inputs.verify_transactions {
        return "utxo · utxo-bootstrapped".to_string();
    }

    // Post-bootstrap archive label refinement: when the
    // operator's config says archive (`blocks_to_keep = -1`)
    // but the store has a sentinel `> 1`, the actual on-disk
    // shape is "post-bootstrap". The wire-visible field still
    // follows Scala parity; the operator label distinguishes
    // the source.
    if inputs.blocks_to_keep == -1
        && boot_sentinel > 1
        && inputs.state_type == StateType::Utxo
        && inputs.verify_transactions
        && !inputs.utxo_bootstrap
        && !inputs.nipopow_bootstrap
    {
        match bootstrap_kind {
            BootstrapKind::Both => return "utxo · utxo+popow-bootstrapped".to_string(),
            BootstrapKind::Nipopow => return "utxo · popow-bootstrapped".to_string(),
            BootstrapKind::Utxo => return "utxo · utxo-bootstrapped".to_string(),
            BootstrapKind::None => return "utxo · post-prune archive".to_string(),
        }
    }
    match (
        inputs.state_type,
        inputs.verify_transactions,
        inputs.blocks_to_keep,
    ) {
        (StateType::Utxo, true, -1) => "archive · utxo".to_string(),
        (StateType::Utxo, true, -2) => "utxo · utxo-bootstrapped".to_string(),
        (StateType::Utxo, true, n) if n >= 0 => format!("pruned · utxo · keep {n}"),
        (StateType::Digest, true, -1) => "digest-verifier".to_string(),
        (StateType::Digest, false, 0) => "headers-only · digest".to_string(),
        (st, vt, n) => format!(
            "invalid mode: state_type={} / verify_tx={} / blocks_to_keep={}",
            st.as_str(),
            vt,
            n,
        ),
    }
}

pub(crate) fn build_api_identity(
    config: &NodeConfig,
    boot_sentinel: u32,
    bootstrap_kind: BootstrapKind,
) -> Result<ergo_api::types::ApiIdentity, NodeError> {
    build_api_identity_from_inputs(
        &IdentityInputs::from_config(config),
        boot_sentinel,
        bootstrap_kind,
    )
}

pub(crate) fn validate_runtime_mode_support(config: &NodeConfig) -> Result<(), NodeError> {
    use crate::config::StateType;

    // Canonical Mode 6 (headers-only) combo passes through; everything
    // else still gated per its own part-2 status. Delegates to the
    // shared predicate in `crate::config` so this gate stays in lock-
    // step with `NodeConfig::load`'s TOML-time gate.
    let is_canonical_mode_6 = crate::config::is_canonical_mode_6_combo(
        config.state_type,
        config.verify_transactions,
        config.blocks_to_keep,
        config.utxo_bootstrap,
    );
    // Canonical Mode 5 (Digest Verifier) — full tx validation against an
    // authenticated UTXO digest, archive retention, no UTXO bootstrap.
    // The backend is wired (boot opens `DigestStateStore`), so the
    // `state_type != Utxo` arm below lets this combo through. The
    // unsupported-subsystem gates (mining / indexer / mempool) still
    // fire on `state_type == Digest`, so admitting the bare row here does
    // not loosen those.
    let is_canonical_mode_5 = crate::config::is_canonical_mode_5_combo(
        config.state_type,
        config.verify_transactions,
        config.blocks_to_keep,
        config.utxo_bootstrap,
    );

    // Targeted error for the "almost-Mode-6 except utxo_bootstrap"
    // case so the operator sees the real cause rather than a
    // downstream "blocks_to_keep = 0" complaint. `NodeConfig::load`
    // catches this at TOML time; this arm is the
    // programmatic-construction backstop.
    if config.state_type == StateType::Digest
        && !config.verify_transactions
        && config.blocks_to_keep == 0
        && config.utxo_bootstrap
    {
        return Err("NodeConfig: headers-only mode (state_type=digest, \
             verify_transactions=false, blocks_to_keep=0) cannot be \
             combined with utxo_bootstrap=true — there is no UTXO state \
             to bootstrap into. Set utxo_bootstrap=false."
            .into());
    }

    // Mode 3 runtime backstop. The TOML loader enforces the same
    // contract, but direct NodeConfig construction (test
    // harnesses, library embedders) bypasses that path. Mirror
    // the relevant checks here so a misconfigured config cannot
    // reach the action loop and defer failure to a deeper boot
    // step (build_api_identity rejection / rollback-time error).
    //
    // Three rejection arms:
    //   1. `< -1` (invalid sentinels like the wire-only `-2`
    //      UTXOSetBootstrapped or arbitrary negative configs).
    //   2. `> 0 && < ROLLBACK_WINDOW + SAFETY_MARGIN`
    //      (sub-floor pruning window).
    //   3. `== 0` outside the canonical Mode 6 combo (avoids the
    //      downstream `build_api_identity` rejection of the
    //      `(Utxo, verify=true, 0)` tuple).
    if config.blocks_to_keep < -1 {
        return Err(format!(
            "NodeConfig.blocks_to_keep = {} is invalid. Valid values: -1 (archive), \
             0 (canonical Mode 6 only), or >= keep_versions + SAFETY_MARGIN \
             ({}). Negative sentinels other than -1 are wire-only states, not \
             config values.",
            config.blocks_to_keep,
            i64::from(config.keep_versions) + i64::from(ergo_state::store::SAFETY_MARGIN),
        )
        .into());
    }
    if config.blocks_to_keep > 0 {
        let floor = i64::from(config.keep_versions) + i64::from(ergo_state::store::SAFETY_MARGIN);
        if i64::from(config.blocks_to_keep) < floor {
            return Err(format!(
                "NodeConfig.blocks_to_keep = {} is below the rollback-window floor \
                 ({} = keep_versions {} + SAFETY_MARGIN {}). Pruning must retain at \
                 least the reorg-resolver's worst-case rollback depth.",
                config.blocks_to_keep,
                floor,
                config.keep_versions,
                ergo_state::store::SAFETY_MARGIN,
            )
            .into());
        }
    }
    if config.blocks_to_keep == 0 && !is_canonical_mode_6 {
        return Err(format!(
            "NodeConfig.blocks_to_keep = 0 is reserved for the canonical Mode 6 \
             combo (state_type=digest, verify_transactions=false, \
             utxo_bootstrap=false). Got state_type={:?}, \
             verify_transactions={}, utxo_bootstrap={}.",
            config.state_type.as_str(),
            config.verify_transactions,
            config.utxo_bootstrap,
        )
        .into());
    }
    if config.state_type != StateType::Utxo && !is_canonical_mode_6 && !is_canonical_mode_5 {
        return Err(format!(
            "NodeConfig.state_type = {:?} is only supported in the canonical \
             Mode 5 (Digest Verifier: verify_transactions=true, blocks_to_keep=-1, \
             utxo_bootstrap=false) or Mode 6 (headers-only: verify_transactions=false, \
             blocks_to_keep=0, utxo_bootstrap=false) combos.",
            config.state_type.as_str(),
        )
        .into());
    }
    if !config.verify_transactions && !is_canonical_mode_6 {
        return Err(
            "NodeConfig.verify_transactions = false requires the canonical \
             Mode 6 combo (state_type=digest, blocks_to_keep=0, \
             utxo_bootstrap=false); other verify_transactions=false combos \
             are not yet supported."
                .into(),
        );
    }
    if config.utxo_bootstrap && config.state_type != StateType::Utxo {
        return Err(format!(
            "NodeConfig.utxo_bootstrap = true requires state_type = utxo \
             (snapshot bootstrap reconstructs the UTXO tree); got state_type = {:?}.",
            config.state_type.as_str(),
        )
        .into());
    }
    // Digest backend unsupported-subsystem gates — programmatic
    // backstop for the TOML-time rejections in `NodeConfig::load`.
    // The TOML loader rejects these combos, but a directly-built
    // `NodeConfig` (test harnesses, library embedders) bypasses
    // that path. Mirror the checks here so the runtime never
    // boots a digest-mode node with subsystems that need UTXO
    // box bytes.
    if config.state_type == StateType::Digest && config.mining_config.enabled {
        return Err(
            "NodeConfig.mining_config.enabled = true is incompatible with \
             state_type = digest — candidate generation requires UTXO box \
             state, which the digest backend does not retain."
                .into(),
        );
    }
    // Storage-rent self-claim enumerates eligible boxes only from the
    // extra-index, so it cannot function without the indexer enabled.
    // Programmatic-construction backstop for the TOML-time reject in
    // `NodeConfig::load`. (Reached only for utxo configs — a digest +
    // mining config already returned above.) Gates the source's presence,
    // not its catch-up: a backfilling index only under-collects, since each
    // claimed box is re-resolved from committed state first.
    if config.mining_config.enabled
        && config.mining_config.claim_storage_rent
        && !config.indexer_config.enabled
    {
        return Err("NodeConfig: [mining] claim_storage_rent = true requires \
             indexer_config.enabled = true — storage-rent-eligible boxes are \
             enumerated only from the extra-index, so the claim collects \
             nothing without it."
            .into());
    }
    if config.state_type == StateType::Digest && config.indexer_config.enabled {
        return Err(
            "NodeConfig.indexer_config.enabled = true is incompatible with \
             state_type = digest — extra-index requires the UTXO box store, \
             which the digest backend does not retain."
                .into(),
        );
    }
    if config.state_type == StateType::Digest && config.mempool_config.enabled {
        return Err(
            "NodeConfig.mempool_config.enabled = true is incompatible with \
             state_type = digest — tx admission requires UTXO box bytes, \
             which the digest backend does not retain. The TOML loader \
             force-disables the mempool via `mempool_force_off_for_mode`; \
             programmatic constructors must mirror that."
                .into(),
        );
    }
    // Mode 2 (utxo_bootstrap = true) is now accepted at runtime.
    // The consume-side pipeline is live; on a fresh data_dir the
    // node will discover snapshots, verify trust against
    // header.state_root, download chunks, reconstruct the UTXO
    // tree, and install it before normal block sync takes over.
    // Trust verification remains PROVISIONAL until a Scala oracle
    // pin lands; operators running Mode 2 against a fresh data_dir
    // should cross-check the installed root against a known-good
    // Scala mainnet snapshot.
    // NiPoPoW bootstrap is fully wired end-to-end. The PopowBootstrap
    // reducer is
    // constructed in NodeState when `config.nipopow_bootstrap`
    // is `true` AND `store.chain_state().best_header_height == 0`
    // (fresh data_dir); subsequent ticks drive request fan-out,
    // proof apply, and bounded forward catchup.
    Ok(())
}

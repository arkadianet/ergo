//! `NodeConfig::load` — resolves CLI + TOML + chain-spec defaults into
//! the [`super::NodeConfig`] runtime shape. Holds all the per-section
//! validation (R1, R2, R3, R5 from Scala's `consistentSettings`, the
//! Mode-3/5/6 activation gates, byte-length checks on API hash + miner
//! pubkey, anchor-scheduler gating, etc.).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ergo_chain_spec::ChainSpec;
use ergo_indexer::IndexerConfig;
use ergo_mempool::{weight, MempoolConfig};
use tracing_subscriber::EnvFilter;

use super::toml_sections::*;
use super::{
    validate_supported, Cli, LoggingConfig, LoggingFileConfig, LoggingFormat, Network, NodeConfig,
    StateType, MAX_DOWNLOAD_WINDOW,
};

impl NodeConfig {
    /// Load config from TOML file + CLI overrides.
    /// CLI args take priority over TOML values.
    pub fn load(cli: Cli) -> Result<Self, String> {
        // 1. Determine data dir (CLI > default)
        let data_dir = cli
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./ergo-data"));

        // 2. Load TOML config if it exists
        let config_path = cli
            .config
            .clone()
            .unwrap_or_else(|| data_dir.join("ergo-node.toml"));
        let toml_cfg = if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)
                .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
            toml::from_str::<TomlConfig>(&contents)
                .map_err(|e| format!("failed to parse {}: {e}", config_path.display()))?
        } else {
            TomlConfig::default()
        };

        // 3. Merge: CLI overrides TOML overrides defaults
        let network_str = cli
            .network
            .or(toml_cfg.network)
            .unwrap_or_else(|| "mainnet".into());
        let network = network_str.parse::<Network>()?;
        let chain_spec = Arc::new(ChainSpec::for_network(network));
        validate_supported(&chain_spec)?;

        let data_dir = cli
            .data_dir
            .or(toml_cfg.data_dir.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("./ergo-data"));

        // Peers: CLI overrides TOML entirely (not merged), then network
        // seeds are appended as additive bootstrap fallbacks. Dedupe
        // preserves user-supplied ordering — seeds only fill gaps.
        let user_peers: Vec<SocketAddr> = if !cli.peers.is_empty() {
            cli.peers
        } else {
            toml_cfg
                .peers
                .known
                .iter()
                .filter_map(|s| s.parse::<SocketAddr>().ok())
                .collect()
        };

        let mut known_peers = user_peers;
        for seed in &chain_spec.bootstrap.seed_peers {
            if !known_peers.contains(seed) {
                known_peers.push(*seed);
            }
        }

        if known_peers.is_empty() {
            return Err("no peers configured — use --peers or [peers] known in config file".into());
        }

        let max_connections = toml_cfg
            .peers
            .max_connections
            .unwrap_or(ergo_p2p::peer_manager::DEFAULT_MAX_CONNECTIONS);
        // When target_outbound is omitted, clamp the (raised) default down
        // to the operator's max_connections ceiling instead of hard-failing
        // the load below. Without this, a plain binary upgrade would brick a
        // config that pins a low max_connections (e.g. the old default 80)
        // and leaves target_outbound unset: the raised default (96) would
        // exceed that pin and trip the `target_outbound > max_connections`
        // error. An EXPLICIT target_outbound above max_connections stays a
        // hard error (a genuine operator contradiction).
        let target_outbound = match toml_cfg.peers.target_outbound {
            Some(explicit) => explicit,
            None => ergo_p2p::peer_manager::DEFAULT_TARGET_OUTBOUND.min(max_connections),
        };
        let peer_limits = ergo_p2p::peer_manager::PeerLimits {
            max_connections,
            target_outbound,
            max_inbound: toml_cfg
                .peers
                .max_inbound
                .unwrap_or(ergo_p2p::peer_manager::DEFAULT_MAX_INBOUND),
            per_ip_limit: toml_cfg
                .peers
                .per_ip_limit
                .unwrap_or(ergo_p2p::peer_manager::DEFAULT_PER_IP_LIMIT),
            per_subnet_limit: toml_cfg
                .peers
                .per_subnet_limit
                .unwrap_or(ergo_p2p::peer_manager::DEFAULT_PER_SUBNET_LIMIT),
        };
        if peer_limits.max_connections == 0 {
            return Err("[peers] max_connections must be >= 1".into());
        }
        if peer_limits.target_outbound == 0 {
            return Err("[peers] target_outbound must be >= 1".into());
        }
        if peer_limits.target_outbound > peer_limits.max_connections {
            return Err(format!(
                "[peers] target_outbound ({}) exceeds max_connections ({})",
                peer_limits.target_outbound, peer_limits.max_connections,
            ));
        }
        if peer_limits.per_ip_limit == 0 {
            return Err("[peers] per_ip_limit must be >= 1".into());
        }
        if peer_limits.per_subnet_limit == 0 {
            return Err("[peers] per_subnet_limit must be >= 1".into());
        }

        // Inbound listener bind address. Opt-in: empty string or absent
        // → outbound only. Validated as a `SocketAddr` at load time so
        // typos surface at startup rather than at first inbound dial.
        let bind_addr = match toml_cfg.peers.bind_addr.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(
                raw.parse::<SocketAddr>()
                    .map_err(|e| format!("[peers] bind_addr = {raw:?}: {e}"))?,
            ),
        };
        // Declared address: what we advertise to peers. Independent of
        // bind_addr (a NAT'd node binds privately, declares its public
        // IP). Empty / absent → handshake omits the field, peers won't
        // gossip us as reachable.
        let declared_addr = match toml_cfg.peers.declared_addr.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(
                raw.parse::<SocketAddr>()
                    .map_err(|e| format!("[peers] declared_addr = {raw:?}: {e}"))?,
            ),
        };

        let agent_name = toml_cfg
            .node
            .agent_name
            .unwrap_or_else(|| "ergo-rust".into());
        let node_name = toml_cfg
            .node
            .node_name
            .unwrap_or_else(|| "ergo-rust-node".into());
        // [node] blocks_to_keep — Mode 3 pruning. Default -1 (archive).
        // Wire sentinel -2 is reserved for the UTXO-bootstrap completed
        // state (Mode 2, deferred); operators cannot set it directly.
        // R2 enforcement against [indexer] enabled happens further down,
        // once both values are resolved.
        let blocks_to_keep = toml_cfg.node.blocks_to_keep.unwrap_or(-1);
        if blocks_to_keep < -1 {
            return Err(format!(
                "[node] blocks_to_keep = {blocks_to_keep} is invalid; \
                 use -1 (archive) or a non-negative N (pruned suffix length)",
            ));
        }
        // [node] keep_versions — undo-retention window / max serviceable
        // reorg depth (mirrors Scala `ergo.node.keepVersions`). Default 200.
        // 0 would mean "a store that can never roll back" (Scala allows it;
        // we refuse — every reorg would wedge the node). Prospective only:
        // raising it does not resurrect undo entries a previous run pruned.
        let keep_versions = toml_cfg
            .node
            .keep_versions
            .unwrap_or(ergo_state::store::ROLLBACK_WINDOW);
        if keep_versions == 0 {
            return Err("[node] keep_versions = 0 is invalid: the state store \
                 could never roll back, so ANY reorg would permanently wedge \
                 the node. Use >= 1 (default 200, matching the Scala \
                 reference node's keepVersions)."
                .to_string());
        }
        // [node] state_type — default utxo. Parsed before R1 + activation
        // gates so both can reference the resolved enum.
        let state_type = match toml_cfg.node.state_type.as_deref() {
            None => StateType::Utxo,
            Some(s) => s.parse::<StateType>().map_err(|e| format!("[node] {e}"))?,
        };
        let verify_transactions = toml_cfg.node.verify_transactions.unwrap_or(true);
        let utxo_bootstrap = toml_cfg.node.utxo.utxo_bootstrap.unwrap_or(false);
        let nipopow_bootstrap = toml_cfg.node.nipopow.nipopow_bootstrap.unwrap_or(false);
        let p2p_nipopows = toml_cfg.node.nipopow.p2p_nipopows.unwrap_or(2);
        if p2p_nipopows == 0 {
            return Err("[node.nipopow] p2p_nipopows must be >= 1 (quorum cannot be zero)".into());
        }
        // R1 (per Scala ErgoSettingsReader.consistentSettings:175-176):
        // `verify_transactions = false` requires `state_type = digest`.
        // Naming both keys helps operators see which to fix.
        if !verify_transactions && state_type == StateType::Utxo {
            return Err("[node] verify_transactions = false is incompatible with \
                 [node] state_type = \"utxo\"; headers-only mode requires \
                 the digest backend (set state_type = \"digest\")."
                .to_string());
        }
        // Mode 6 canonical-combo enforcement (per Scala application.conf:15):
        // "Download block transactions and verify them (requires
        // BlocksToKeep == 0 if disabled)". A headers-only node has
        // nothing to retain a window of, so `blocks_to_keep` must be
        // exactly 0. Other Digest+vT=false combos (e.g. -1, 1024)
        // aren't a Scala-supported mode — refuse before the activation
        // gates so the operator sees the precise conflict.
        if !verify_transactions && state_type == StateType::Digest && blocks_to_keep != 0 {
            return Err(format!(
                "[node] verify_transactions = false + state_type = \"digest\" \
                 requires [node] blocks_to_keep = 0 (canonical Mode 6 combo \
                 per Scala application.conf:15); got blocks_to_keep = {blocks_to_keep}. \
                 A headers-only node downloads no block sections — there is no \
                 suffix length to retain.",
            ));
        }
        // R1b: headers-only (digest + !verify_transactions +
        // blocks_to_keep=0) cannot be combined with utxo_bootstrap. A
        // Mode 6 node has no UTXO state to install a snapshot into;
        // the combo would let the boot path try to bootstrap a UTXO
        // tree the rest of the runtime cannot use.
        if state_type == StateType::Digest
            && !verify_transactions
            && blocks_to_keep == 0
            && utxo_bootstrap
        {
            return Err("[node] headers-only mode (state_type = \"digest\", \
                 verify_transactions = false, blocks_to_keep = 0) cannot be \
                 combined with [node.utxo] utxo_bootstrap = true — there is \
                 no UTXO state to bootstrap into. Set utxo_bootstrap = false."
                .to_string());
        }
        // R2 (per Scala ErgoSettingsReader.consistentSettings:189-190):
        // extra-index requires un-pruned blocks. Scala's
        // `isFullBlocksPruned = blocksToKeep >= 0 || utxoBootstrap`,
        // so either suffix-length pruning OR UTXO bootstrap counts
        // as "pruned" for R2's purposes. Both halves enforced here
        // before the activation gates so the real config conflict
        // surfaces rather than getting masked by "not yet supported".
        let indexer_enabled = toml_cfg.indexer.enabled.unwrap_or(false);
        if indexer_enabled && blocks_to_keep >= 0 {
            return Err(format!(
                "[indexer] enabled = true is incompatible with \
                 [node] blocks_to_keep = {blocks_to_keep} (pruned mode); \
                 extra-index requires the full archive."
            ));
        }
        if indexer_enabled && utxo_bootstrap {
            return Err("[indexer] enabled = true is incompatible with \
                 [node.utxo] utxo_bootstrap = true; extra-index requires \
                 the full archive (UTXO bootstrap means the chain below \
                 the snapshot height was never downloaded)."
                .to_string());
        }
        // R3 (per Scala ErgoSettingsReader.consistentSettings:191-194):
        // nipopow_bootstrap requires `utxo_bootstrap = true` OR
        // `blocks_to_keep >= 0`. Translation: a node bootstrapping
        // via PoPoW proof cannot also be a full archive — the proof
        // is the bootstrap mechanism that lets you skip the long
        // header sync, only useful when something downstream
        // (snapshot or pruning) lets you avoid the historic chain.
        // R3 fires before the activation gate so the real conflict
        // surfaces. R5 (genesisId requirement) is enforced at
        // config-load by the `nipopow_bootstrap && genesis_id.is_none()`
        // check after genesis_id resolution below, plus a runtime pin
        // through `NipopowVerifier::new(genesis_id_opt, ...)` in the
        // bootstrap orchestrator. R4 (mainnet mining ⇒
        // `checkReemissionRules = true`) has no analogue here — we
        // don't expose a `check_reemission_rules` opt-out at the
        // config layer, so the rule is vacuous in our config space.
        if nipopow_bootstrap && !(utxo_bootstrap || blocks_to_keep >= 0) {
            return Err(format!(
                "[node.nipopow] nipopow_bootstrap = true requires either \
                 [node.utxo] utxo_bootstrap = true or \
                 [node] blocks_to_keep >= 0 (currently {blocks_to_keep}); \
                 full archive nodes cannot also PoPoW-bootstrap."
            ));
        }
        // Mode 5 unsupported-subsystem gates. Mode 5
        // (`state_type = digest` + `verify_transactions = true`) does
        // not retain a UTXO box store, so subsystems whose
        // contracts depend on UTXO box bytes are incompatible. Each
        // gate fires here BEFORE the Mode 5 activation gate so the
        // operator sees the precise conflict ("indexer + digest")
        // rather than the generic "Mode 5 deferred" reject — and so
        // the gates remain operative when the activation gate
        // eventually lifts.
        //
        // Mining: Scala `failWithError(stateType == Digest &&
        // mining)`. Candidate generation needs UTXO access to pull
        // confirmed inputs.
        let mining_enabled_intent = toml_cfg.mining.enabled || cli.mining_enabled;
        if state_type == StateType::Digest && mining_enabled_intent {
            return Err("[mining] enabled = true is incompatible with \
                 [node] state_type = \"digest\" — candidate generation \
                 requires UTXO box state, which the digest backend does \
                 not retain. Disable mining or switch to state_type = \"utxo\"."
                .to_string());
        }
        // Storage-rent self-claim requires the indexer: eligible boxes are
        // enumerated only from the extra-index `unspent_by_creation_height`
        // table (`mining_engine::resolve_eligible_rent_boxes`). With the
        // indexer off the claim silently collects nothing, so reject the
        // combo rather than let it no-op. Enabling the indexer in turn needs
        // a full archive (the R2 gates above), so this transitively pins
        // `claim_storage_rent` to Mode 1. This gates the SOURCE's presence,
        // not its catch-up state: while the index backfills, enumeration may
        // be partial, but each row is re-resolved against committed state
        // (spent/missing boxes skipped) before being claimed — so a lagging
        // index only under-collects, never claims an invalid box.
        if mining_enabled_intent && toml_cfg.mining.claim_storage_rent && !indexer_enabled {
            return Err("[mining] claim_storage_rent = true requires [indexer] \
                 enabled = true — storage-rent-eligible boxes are enumerated \
                 only from the extra-index, so the claim collects nothing \
                 without it. Enable the indexer or set claim_storage_rent = false."
                .to_string());
        }
        // Indexer: extra-index needs box bytes AND a full archive,
        // both unavailable under the digest backend. R2 above
        // already rejects `indexer + pruned` and `indexer +
        // utxo_bootstrap`; this completes the matrix.
        if state_type == StateType::Digest && indexer_enabled {
            return Err("[indexer] enabled = true is incompatible with \
                 [node] state_type = \"digest\" — extra-index requires \
                 the UTXO box store, which the digest backend does not \
                 retain. Disable the indexer or switch to state_type = \"utxo\"."
                .to_string());
        }
        // Identify the canonical Mode 6 (headers-only) combo so it can
        // pass through the activation gates below. Mode 6 ships in this
        // commit (part 2b) — the sync coordinator skips block-section
        // requests when `verify_transactions = false`, the StateStore
        // accepts the `"digest"` sentinel, and the mempool disables
        // itself. Other Digest combos (Mode 5) and other pruning
        // combos (Mode 3) stay gated until their own part 2 lands.
        let is_canonical_mode_6 = super::is_canonical_mode_6_combo(
            state_type,
            verify_transactions,
            blocks_to_keep,
            utxo_bootstrap,
        );
        // Canonical Mode 5 (Digest Verifier): full tx validation against
        // an authenticated digest, archive retention, no bootstrap. The
        // backend ships (boot opens `DigestStateStore`), so the digest
        // activation gate below admits this combo; the subsystem
        // force-offs (mempool) and unsupported-subsystem rejections
        // (mining / indexer) still fire on `state_type == digest`.
        let is_canonical_mode_5 = super::is_canonical_mode_5_combo(
            state_type,
            verify_transactions,
            blocks_to_keep,
            utxo_bootstrap,
        );

        // Mode 3 activation gate — lifted in Phase 4 now that
        // eviction (Phase 2a+2b), receive/serve gating (Phase 3a+3b),
        // and rollback guard (Phase 4) all ship in the same envelope.
        // Replaced with the rollback-window floor: pruning must keep
        // enough blocks to cover the reorg resolver's worst-case
        // rollback depth. Rolling back into a pruned region would
        // need section bytes that have been evicted; the wallet
        // replay path would fail with `RollbackBelowPruningSentinel`.
        // Mode 6 (`blocks_to_keep = 0`) is exempt — it's headers-only
        // and never applies full blocks.
        if blocks_to_keep > 0 {
            // i64 math: `keep_versions` is unbounded operator input, so a
            // u32 add can overflow and an `as i32` cast can wrap negative —
            // silently disabling this floor for huge windows.
            let floor = i64::from(keep_versions) + i64::from(ergo_state::store::SAFETY_MARGIN);
            if i64::from(blocks_to_keep) < floor {
                return Err(format!(
                    "[node] blocks_to_keep = {blocks_to_keep} is below the rollback-window \
                     floor ({floor} = keep_versions {keep_versions} + SAFETY_MARGIN {}). \
                     Pruning must retain at least the reorg-resolver's worst-case rollback \
                     depth so a reorg never needs evicted section bytes; the wallet replay \
                     path would otherwise fail with RollbackBelowPruningSentinel.",
                    ergo_state::store::SAFETY_MARGIN,
                ));
            }
        }
        // `blocks_to_keep = 0` is meaningful ONLY in the canonical Mode 6
        // combo (state_type=digest + verify_transactions=false +
        // utxo_bootstrap=false). With the default UTXO + verify combo,
        // a 0 value would load successfully here but die downstream in
        // `build_api_identity` (which rejects (Utxo, verify=true, 0)).
        // Reject at the config seam so the failure is operator-actionable.
        if blocks_to_keep == 0 && !is_canonical_mode_6 {
            return Err(format!(
                "[node] blocks_to_keep = 0 is reserved for the canonical Mode 6 combo \
                 (state_type=digest, verify_transactions=false, utxo_bootstrap=false). \
                 Got state_type={:?}, verify_transactions={verify_transactions}, \
                 utxo_bootstrap={utxo_bootstrap}. Either set the full Mode 6 combo or \
                 use blocks_to_keep = -1 (archive).",
                state_type.as_str(),
            ));
        }
        // Digest backend activation gate. The digest backend now ships
        // in two canonical combos: Mode 5 (Digest Verifier — full
        // AD-proof tx validation, archive) and Mode 6 (headers-only).
        // Any other digest combo (pruned digest, utxo_bootstrap on
        // digest, etc.) stays rejected.
        if state_type != StateType::Utxo && !is_canonical_mode_6 && !is_canonical_mode_5 {
            return Err(format!(
                "[node] state_type = {:?} is only supported in the canonical \
                 Mode 5 (Digest Verifier: verify_transactions=true, \
                 blocks_to_keep=-1, utxo_bootstrap=false) or Mode 6 \
                 (headers-only: verify_transactions=false, blocks_to_keep=0, \
                 utxo_bootstrap=false) combos.",
                state_type.as_str(),
            ));
        }
        // `verify_transactions = false` activation: now allowed but
        // only for the canonical Mode 6 combo. R1 above already
        // ensures state_type=digest when this is false, and the
        // canonical-combo check ensures blocks_to_keep=0.
        if !verify_transactions && !is_canonical_mode_6 {
            return Err("[node] verify_transactions = false requires the canonical \
                 Mode 6 combo (state_type=digest, blocks_to_keep=0); other \
                 verify_transactions=false combos are not yet supported."
                .to_string());
        }
        // Mode 2 activation gate. Schema, R2 second half, and
        // `/api/v1/identity` reflection landed in Mode 2 part 1; the
        // Mode 2 activation gate lifted: snapshot codec (2b-2c),
        // snapshot-message p2p surface (2e), consume-side state
        // machine (2f-2i) all ship. Operators on a fresh data_dir
        // can set utxo_bootstrap = true to opt into the bootstrap
        // path. Trust verification against header.state_root is
        // PROVISIONAL until a Scala oracle pin lands — production
        // operators should cross-check the installed root against
        // a known-good Scala mainnet snapshot before treating the
        // UTXO state as authoritative.
        // Nipopow activation gate LIFTED in Part 2 §14.6
        // (orchestration end-to-end commit). PoPoW proof verification,
        // the p2p messages (codes 90/91), apply_popow_proof, and the
        // drive_popow_bootstrap orchestration are all on master. R5
        // genesis-id enforcement (Part 2 §14.7) is wired through
        // NipopowVerifier::new(genesis_id_opt, ...), defaulting to the
        // network's hardcoded genesis when the operator hasn't set
        // `[chain] genesis_id`.

        // [sync] — tunable pipeline sizing with bounds validation.
        let download_window = toml_cfg
            .sync
            .download_window
            .unwrap_or(ergo_p2p::sync::DOWNLOAD_WINDOW);
        if download_window == 0 {
            return Err("[sync] download_window = 0 stalls downloads; use >= 1".into());
        }
        if download_window > MAX_DOWNLOAD_WINDOW {
            return Err(format!(
                "[sync] download_window = {download_window} exceeds MAX_DOWNLOAD_WINDOW ({MAX_DOWNLOAD_WINDOW})"
            ));
        }

        let cache_bytes = cli.cache_bytes.or(toml_cfg.store.cache_bytes);

        // Checkpoint resolution priority: CLI > TOML > network default.
        // Either source may override only the height (in which case
        // block_id falls back to the network default to keep the safety
        // assertion intact). Setting height = 0 explicitly disables the
        // checkpoint (full validation everywhere).
        let cli_h = cli.checkpoint_height;
        let toml_h = toml_cfg.chain.script_validation_checkpoint_height;
        let cli_id = cli.checkpoint_block_id.as_deref();
        let toml_id = toml_cfg
            .chain
            .script_validation_checkpoint_block_id
            .as_deref();
        let default_cp = chain_spec.bootstrap.checkpoint;
        let script_validation_checkpoint = match cli_h.or(toml_h) {
            Some(0) => None,
            Some(h) => {
                let id_hex = cli_id.or(toml_id);
                let id = match (id_hex, default_cp) {
                    (Some(hex_str), _) => {
                        let bytes = hex::decode(hex_str)
                            .map_err(|e| format!("checkpoint_block_id hex decode: {e}"))?;
                        if bytes.len() != 32 {
                            return Err(format!(
                                "checkpoint_block_id must be 32 bytes (got {})",
                                bytes.len(),
                            ));
                        }
                        let mut id = [0u8; 32];
                        id.copy_from_slice(&bytes);
                        id
                    }
                    (None, Some((_, def_id))) => def_id,
                    (None, None) => {
                        return Err("checkpoint_height set but no checkpoint_block_id provided \
                         and the active network has no hardcoded default"
                            .into())
                    }
                };
                Some((h, id))
            }
            None => default_cp,
        };

        // Genesis-id resolution for NiPoPoW R5 (Part 2 §11). TOML
        // override > network default. An explicit empty string in
        // TOML (`genesis_id = ""`) disables the check entirely —
        // intended for development against synthetic chains only;
        // mainnet runs MUST leave this at the default.
        let genesis_id = match toml_cfg.chain.genesis_id.as_deref() {
            Some("") => None,
            Some(hex_str) => {
                let bytes = hex::decode(hex_str.trim_start_matches("0x"))
                    .map_err(|e| format!("[chain] genesis_id hex decode: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "[chain] genesis_id must be 32 bytes (got {})",
                        bytes.len(),
                    ));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Some(id)
            }
            None => chain_spec.genesis.header_id,
        };

        // R5 (per Scala ErgoSettingsReader.consistentSettings:195-196):
        // `nipopow_bootstrap = true` requires a configured genesis id.
        // Our `genesis_id = ""` opt-out exists for dev against synthetic
        // chains; combining it with `nipopow_bootstrap = true` would
        // leave `NipopowVerifier` open to any genesis, defeating the
        // bootstrap pin Scala mandates.
        if nipopow_bootstrap && genesis_id.is_none() {
            return Err("[node.nipopow] nipopow_bootstrap = true requires \
                 a configured genesis id; the explicit `[chain] genesis_id = \"\"` \
                 opt-out is incompatible with PoPoW bootstrap (matches Scala \
                 ErgoSettingsReader.consistentSettings:195-196). \
                 Remove the genesis_id override or leave it at the network default."
                .to_string());
        }

        let api_bind = if toml_cfg.api.disabled.unwrap_or(false) {
            None
        } else {
            let raw = toml_cfg.api.bind.as_deref().unwrap_or("127.0.0.1:9099");
            let addr = raw
                .parse::<SocketAddr>()
                .map_err(|e| format!("[api] bind = {raw:?}: {e}"))?;
            let public_bind = toml_cfg.api.public_bind.unwrap_or(false);
            if !addr.ip().is_loopback() && !public_bind {
                return Err(format!(
                    "[api] bind = {raw:?} is not a loopback address. \
                     api_key_hash gates /wallet/* and /node/shutdown only; \
                     /transactions, /blocks, and /api/v1/mempool/{{submit,check}} \
                     remain unauthenticated (matches Scala node behavior). \
                     For remote operator access, bind 127.0.0.1 / ::1 and put a \
                     reverse proxy in front, OR set [api] public_bind = true \
                     and accept that submission routes are publicly callable."
                ));
            }
            Some(addr)
        };

        // [api.security] — always required when the API server is enabled,
        // matching Scala `ErgoApp.scala:40-43` `require(apiKeyHash.isDefined,
        // "API key hash must be set")`. Generate with
        // `echo -n "<secret>" | b2sum -l 256 | cut -d' ' -f1`. Validated
        // here so a malformed value exits the node with a clear shell
        // message rather than silently disabling the gate downstream.
        let api_key_hash = if api_bind.is_some() {
            let raw = toml_cfg
                .api
                .security
                .as_ref()
                .and_then(|s| s.api_key_hash.as_deref())
                .ok_or_else(|| {
                    "[api.security] api_key_hash is required when the API is enabled. \
                     Set it to the lowercase Base16 of Blake2b256(<your-secret>), e.g. \
                     `echo -n \"hello\" | b2sum -l 256 | cut -d' ' -f1`. \
                     Disable the API server entirely with [api] disabled = true if you \
                     have no operator surface to expose."
                        .to_string()
                })?;
            if raw.len() != 64 {
                return Err(format!(
                    "[api.security] api_key_hash must be 64 lowercase hex chars (got {})",
                    raw.len(),
                ));
            }
            if !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(
                    "[api.security] api_key_hash must be lowercase hex (0-9, a-f only); \
                     uppercase or mixed-case rejected for canonical-form parity with Scala \
                     ScorexEncoder.encode (Base16 lowercase)."
                        .to_string(),
                );
            }
            Some(raw.to_string())
        } else {
            None
        };

        // [mempool] — TOML overrides defaults; CLI flags override TOML.
        let def = MempoolConfig::default();
        let tm = &toml_cfg.mempool;
        let mempool_sort_policy = cli
            .mempool_sort
            .or(tm.sort_policy.clone())
            .unwrap_or_else(|| "cost".into());
        // Validate sort policy early so the error surfaces at startup.
        weight::from_config(&mempool_sort_policy)
            .map_err(|e| format!("[mempool] sort_policy: {e}"))?;
        // Mempool is force-disabled whenever the node lacks UTXO
        // box state. See `mempool_force_off_for_mode` for the full
        // policy (Mode 6 via `!verify_transactions`, Mode 5 via
        // `state_type == Digest`, plus operator overrides).
        let mempool_force_off = super::mempool_force_off_for_mode(
            state_type,
            verify_transactions,
            tm.disabled.unwrap_or(false),
            cli.mempool_disabled,
        );
        let mempool_config = MempoolConfig {
            enabled: !mempool_force_off,
            max_pool_size: tm.max_pool_size.unwrap_or(def.max_pool_size),
            max_pool_bytes: tm.max_pool_bytes.unwrap_or(def.max_pool_bytes),
            min_relay_fee_nano_erg: tm
                .min_relay_fee_nano_erg
                .unwrap_or(def.min_relay_fee_nano_erg),
            max_tx_size_bytes: tm.max_tx_size_bytes.unwrap_or(def.max_tx_size_bytes),
            max_tx_cost: tm.max_tx_cost.unwrap_or(def.max_tx_cost),
            ibd_gate_block_lag: tm.ibd_gate_block_lag.unwrap_or(def.ibd_gate_block_lag),
            // Internal tuning — not operator-configurable via TOML/CLI.
            invalidation_cache_size: def.invalidation_cache_size,
            invalidation_ttl_seconds: def.invalidation_ttl_seconds,
            notifier_poll_ms: def.notifier_poll_ms,
            revalidation_per_tick: def.revalidation_per_tick,
            revalidation_max_depth: def.revalidation_max_depth,
            max_family_depth: def.max_family_depth,
            max_family_ops: def.max_family_ops,
            max_family_update_ms: def.max_family_update_ms,
            mempool_cleanup_cost_mult: def.mempool_cleanup_cost_mult,
            rebroadcast_count: tm.rebroadcast_count.unwrap_or(def.rebroadcast_count),
            global_cost_budget: def.global_cost_budget,
            per_peer_cost_budget: def.per_peer_cost_budget,
            unresolved_cache_size: def.unresolved_cache_size,
            unresolved_cache_ttl_seconds: def.unresolved_cache_ttl_seconds,
        };
        if mempool_config.max_pool_size == 0 {
            return Err("[mempool] max_pool_size must be >= 1".into());
        }
        if mempool_config.max_pool_bytes == 0 {
            return Err("[mempool] max_pool_bytes must be >= 1".into());
        }
        if mempool_config.max_tx_size_bytes == 0 {
            return Err("[mempool] max_tx_size_bytes must be >= 1".into());
        }
        if mempool_config.max_tx_cost == 0 {
            return Err("[mempool] max_tx_cost must be >= 1".into());
        }

        // [indexer] — opt-in extra-index parity. Defaults disabled.
        let idx_def = IndexerConfig::default();
        let ti = &toml_cfg.indexer;
        let indexer_config = IndexerConfig {
            enabled: ti.enabled.unwrap_or(idx_def.enabled),
            poll_idle_ms: ti.poll_idle_ms.unwrap_or(idx_def.poll_idle_ms),
            db_filename: ti.db_filename.clone().unwrap_or(idx_def.db_filename),
            // Mirrors `[node] keep_versions`: the indexer must be able to
            // follow any reorg the state store performs, so the two undo
            // windows stay equal by construction (no separate knob).
            rollback_window: keep_versions as u64,
        };
        if indexer_config.poll_idle_ms == 0 {
            return Err("[indexer] poll_idle_ms must be >= 1".into());
        }
        if indexer_config.db_filename.trim().is_empty() {
            return Err("[indexer] db_filename must be non-empty".into());
        }
        // R2 (extra-index forbidden under pruning) is enforced earlier,
        // right after blocks_to_keep is parsed — see the check up top.

        let enable_anchor_scheduler = toml_cfg.sync.enable_anchor_scheduler.unwrap_or(false);

        // [shadow] — shadow validation vs a Scala reference node. Defaults
        // off; validated only when enabled so a dormant section can't brick
        // boot.
        let sh_def = crate::node::ShadowConfig::default();
        let ts = &toml_cfg.shadow;
        let shadow_config = crate::node::ShadowConfig {
            enabled: ts.enabled.unwrap_or(sh_def.enabled),
            reference_url: ts
                .reference_url
                .clone()
                .unwrap_or_else(|| sh_def.reference_url.clone()),
            interval_secs: ts.interval_secs.unwrap_or(sh_def.interval_secs),
            lag_tolerance: ts.lag_tolerance.unwrap_or(sh_def.lag_tolerance),
            stall_gap_threshold: ts.stall_gap_threshold.unwrap_or(sh_def.stall_gap_threshold),
            request_timeout_secs: ts
                .request_timeout_secs
                .unwrap_or(sh_def.request_timeout_secs),
        };
        if shadow_config.enabled {
            let url = shadow_config.reference_url.trim();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err("[shadow] reference_url must be an http(s):// base URL".into());
            }
            if shadow_config.interval_secs == 0 {
                return Err("[shadow] interval_secs must be >= 1".into());
            }
            if shadow_config.request_timeout_secs == 0 {
                return Err("[shadow] request_timeout_secs must be >= 1".into());
            }
            if shadow_config.stall_gap_threshold == 0 {
                return Err("[shadow] stall_gap_threshold must be >= 1".into());
            }
        }

        // [mining] — external-miner subsystem. Defaults disabled. CLI
        // overrides applied below.
        let mut mining_config = toml_cfg.mining.clone();
        if cli.mining_enabled {
            mining_config.enabled = true;
        }
        if let Some(pk_hex) = cli.mining_public_key.as_ref() {
            mining_config.miner_public_key_hex = Some(pk_hex.clone());
        }
        if let Err(e) = mining_config.validate() {
            return Err(format!("[mining]: {e}"));
        }

        // [voting] — operator on-chain voting policy. Resolve each
        // `[voting.targets]` parameter NAME to its votable id; an unknown or
        // non-votable name (blockVersion, soft-fork, typo) is a startup error.
        // Targets only ever cast a vote while mining, so non-empty targets with
        // mining disabled is refused (mirrors the claim_storage_rent gate).
        let mut voting_targets: std::collections::BTreeMap<u8, i64> =
            std::collections::BTreeMap::new();
        for (name, target) in &toml_cfg.voting.targets {
            let id = ergo_validation::voting::votable_param_id(name).ok_or_else(|| {
                format!(
                    "[voting] target {name:?} is not an operator-votable parameter \
                     (votable: storageFeeFactor, minValuePerByte, maxBlockSize, \
                     maxBlockCost, tokenAccessCost, inputCost, dataInputCost, \
                     outputCost, subblocksPerBlock; blockVersion is soft-fork driven)"
                )
            })?;
            // Reject an out-of-range target at startup (same `[min, max]` the
            // runtime `POST /api/v1/votes` write enforces) — otherwise a
            // fat-fingered config value silently pins the parameter at its bound
            // forever with no warning. Bounds are constant per id.
            if let Some((min, max)) = ergo_validation::voting::votable_param_bounds(id) {
                if *target < min as i64 || *target > max as i64 {
                    return Err(format!(
                        "[voting] target {target} for {name:?} is outside its allowable \
                         voting range [{min}, {max}]"
                    ));
                }
            }
            voting_targets.insert(id, *target);
        }
        if !voting_targets.is_empty() && !mining_config.enabled {
            return Err("[voting] targets are set but [mining] enabled = false — \
                        votes are only cast while mining. Enable mining or remove \
                        the [voting.targets]."
                .into());
        }

        // [logging] — TOML drives subscriber wiring. Defaults preserve
        // pre-config behavior: stderr only at warn level. File output
        // is opt-in; when enabled the directory is resolved against
        // data_dir for relative paths so a single `data_dir = "/var/lib/ergo"`
        // is enough to keep state and logs together.
        let logging = {
            let tl = &toml_cfg.logging;
            let default_level = tl
                .default_level
                .clone()
                .unwrap_or_else(|| "info".to_string());
            EnvFilter::try_new(&default_level).map_err(|e| {
                format!("[logging] default_level {default_level:?} is not a valid filter: {e}")
            })?;
            let format = match tl.format.as_deref().unwrap_or("text") {
                "text" => LoggingFormat::Text,
                "json" => LoggingFormat::Json,
                other => {
                    return Err(format!(
                        "[logging] format {other:?} must be one of \"text\" | \"json\""
                    ))
                }
            };
            let file = if let Some(tf) = &tl.file {
                let dir = match tf.dir.as_deref() {
                    // A current-directory-only dir ("", ".", "./", and the
                    // Windows ".\") resolves to the data dir itself, which
                    // would scatter rotating log files in amongst the redb
                    // state files and reads as "no file logging" if you look
                    // in a `logs/` subdir. Treat any dot-only path as "unset"
                    // → the same `<data_dir>/logs` default the `None` arm uses.
                    // Component-based, so the native path separator is handled
                    // on each platform (empty `components()` → vacuously true).
                    Some(d)
                        if std::path::Path::new(d)
                            .components()
                            .all(|c| c == std::path::Component::CurDir) =>
                    {
                        data_dir.join("logs")
                    }
                    Some(d) => {
                        let p = PathBuf::from(d);
                        if p.is_absolute() {
                            p
                        } else {
                            data_dir.join(p)
                        }
                    }
                    None => data_dir.join("logs"),
                };
                let prefix = tf.prefix.clone().unwrap_or_else(|| "ergo-node".to_string());
                if prefix.contains('/') || prefix.contains('\\') {
                    return Err(format!(
                        "[logging.file] prefix {prefix:?} must not contain path separators"
                    ));
                }
                let rotation = tf.rotation.clone().unwrap_or_else(|| "daily".to_string());
                match rotation.as_str() {
                    "minutely" | "hourly" | "daily" | "never" => {}
                    other => {
                        return Err(format!(
                            "[logging.file] rotation {other:?} must be one of \
                             minutely | hourly | daily | never"
                        ))
                    }
                }
                let max_files = tf.max_files.unwrap_or(14);
                if max_files == 0 {
                    return Err("[logging.file] max_files must be >= 1".into());
                }
                Some(LoggingFileConfig {
                    dir,
                    prefix,
                    rotation,
                    max_files,
                })
            } else {
                None
            };
            LoggingConfig {
                default_level,
                format,
                file,
            }
        };

        Ok(Self {
            network,
            chain_spec,
            data_dir,
            known_peers,
            peer_limits,
            bind_addr,
            declared_addr,
            agent_name,
            node_name,
            blocks_to_keep,
            keep_versions,
            state_type,
            verify_transactions,
            utxo_bootstrap,
            nipopow_bootstrap,
            p2p_nipopows,
            ibd_flush_interval: cli.ibd_flush_interval,
            download_window,
            cache_bytes,
            script_validation_checkpoint,
            genesis_id,
            api_bind,
            api_key_hash,
            mempool_config,
            mempool_sort_policy,
            indexer_config,
            shadow_config,
            enable_anchor_scheduler,
            logging,
            mining_config,
            voting_targets,
            wallet_expose_private_keys: toml_cfg.wallet.expose_private_keys.unwrap_or(false),
        })
    }
}

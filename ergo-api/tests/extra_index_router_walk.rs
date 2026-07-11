//! Router-walk regression for the extra-index `/blockchain/*` surface.
//!
//! Pins the canonical 25-route table (mirroring Scala's
//! `BlockchainApiRoute.scala:69-97`) against `ergo-api/web/openapi.yaml`
//! and the actual axum router.
//!
//! Cross-spec invariants enforced:
//!
//! 1. The route table enumerates exactly 25 rows.
//! 2. Every `(method, path)` row has a matching `paths.<path>.<method>`
//!    entry in `openapi.yaml`. The reverse holds for routes belonging
//!    to the active phase: `openapi.yaml` may not declare a route the
//!    active phase does not mount.
//! 3. When `cfg.indexer.enabled = false` (or the indexer is not yet
//!    plumbed at all — current pre-P1 state), no `/blockchain/*` route
//!    is mounted; the axum default 404 handles every path.
//!
//! As later phases ship, the [`CURRENT_PHASE`] constant advances and the
//! router-walk asserts begin to require that an `IndexerQuery` handle is
//! plumbed and the per-phase route subset is reachable.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ergo_api::compat::traits::NodeChainQuery;
use ergo_api::compat::types::{Parameters, ScalaFullBlock, ScalaInfo};
use ergo_api::server::router;
use ergo_api::traits::NodeReadState;
use ergo_api::types::{
    ApiFullBlockRef, ApiHeaderRef, ApiHealth, ApiInfo, ApiMempoolSummary, ApiMempoolTransaction,
    ApiMempoolTransactions, ApiPeer, ApiStatus, ApiSyncStatus, ApiTip, ApiWeightFunction,
    HealthStatus, SyncStateLabel,
};
use ergo_indexer_types::{
    BalanceDto, BoxId, IndexedBoxDto, IndexedTokenDto, IndexedTxDto, IndexerQuery, IndexerStatus,
    Page, SortDir, TemplateHash, TokenId, TreeHash, TxId,
};
use tower::ServiceExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    /// Pre-P1 — `IndexerQuery` not yet plumbed, every `/blockchain/*`
    /// path returns 404.
    None,
    P1,
    P2,
    P3,
    P4,
    P5,
}

/// Active phase. Advance this constant as each P_n landing PR ships.
/// Pre-P1 the value is `Phase::None` and the router-walk only verifies
/// the `/blockchain/*` paths are not mounted. From P1 onwards, a stub
/// `IndexerQuery` is plumbed and the walk asserts that:
/// - paths whose `phase ≤ CURRENT_PHASE` dispatch (non-404 status)
/// - paths whose `phase > CURRENT_PHASE` still 404, *unless* listed in
///   `EARLY_SHIPPED` below
///
/// All routes in the spec table are now mounted; the per-phase
/// EARLY_SHIPPED carve-out collapsed once templates / tokens / blocks /
/// box-range all shipped.
const CURRENT_PHASE: Phase = Phase::P4;

/// Routes from a higher phase that have already been mounted ahead of
/// their phase landing. Empty whenever `CURRENT_PHASE` matches the
/// last-shipped phase; populate when a slice mounts a route that
/// formally belongs to a phase greater than `CURRENT_PHASE`.
///
/// Each entry is a `(method, normalized_path)` pair after `{X}`-canonicalisation.
const EARLY_SHIPPED: &[(&str, &str)] = &[];

fn is_early_shipped(method: &str, path: &str) -> bool {
    EARLY_SHIPPED
        .iter()
        .any(|(m, p)| *m == method && *p == path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteRow {
    /// One or more HTTP verbs. Scala routes mounted without a method
    /// directive accept both `GET` and `POST`; those are expanded to a
    /// two-element list here so the consistency check is verb-explicit.
    methods: Vec<String>,
    path: String,
    phase: Phase,
}

/// Authoritative per-phase route table. Single source of truth for the
/// router-walk and openapi-consistency tests. Mirrors Scala's
/// `BlockchainApiRoute.scala:69-97`. Paths are pre-canonicalised to the
/// `{X}` placeholder produced by [`normalize_path`].
///
/// When a route's mount phase changes — or a new route lands in
/// `BlockchainApiRoute.scala` — update this table and the per-phase
/// counts in `routes_spec_phase_distribution_matches_design`.
const ROUTES: &[RouteRowStatic] = &[
    // P1 (Indexer skeleton + boxes/txs + rollback)
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/indexedHeight",
        phase: Phase::P1,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/transaction/byId/{X}",
        phase: Phase::P1,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/transaction/byIndex/{X}",
        phase: Phase::P1,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/byId/{X}",
        phase: Phase::P1,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/byIndex/{X}",
        phase: Phase::P1,
    },
    // P2 (Addresses + balance)
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/transaction/byAddress",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/transaction/byAddress/{X}",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET", "POST"],
        path: "/blockchain/transaction/range",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/box/byAddress",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/byAddress/{X}",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/box/unspent/byAddress",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/unspent/byAddress/{X}",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/balance",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/balanceForAddress/{X}",
        phase: Phase::P2,
    },
    // P3 (Templates + tokens + blocks)
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/byTemplateHash/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/unspent/byTemplateHash/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/token/byId/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/tokens",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/byTokenId/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/box/unspent/byTokenId/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/block/byHeaderId/{X}",
        phase: Phase::P3,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/block/byHeaderIds",
        phase: Phase::P3,
    },
    // P4 (Range)
    RouteRowStatic {
        methods: &["GET", "POST"],
        path: "/blockchain/box/range",
        phase: Phase::P4,
    },
    // ErgoTree-keyed (mount at P2)
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/box/byErgoTree",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["POST"],
        path: "/blockchain/box/unspent/byErgoTree",
        phase: Phase::P2,
    },
];

/// Rust-node-exclusive routes that mount under `/blockchain/*` but
/// have no Scala-reference counterpart. Kept in a separate table so
/// the Scala-parity assertions (25-row count, per-phase distribution)
/// stay accurate to the upstream spec.
///
/// The openapi parity test pools both `ROUTES` and `RUST_EXCLUSIVE_ROUTES`
/// — operators consume one OpenAPI document covering everything mounted,
/// regardless of provenance.
const RUST_EXCLUSIVE_ROUTES: &[RouteRowStatic] = &[
    // Storage-rent surface. Mounts whenever the indexer is plumbed
    // AND the bridge supplies a `ChainParamsView`.
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/storageRent/eligibleAt/{X}",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/storageRent/maturesAt/{X}",
        phase: Phase::P2,
    },
    RouteRowStatic {
        methods: &["GET"],
        path: "/blockchain/storageRent/maturesInRange",
        phase: Phase::P2,
    },
];

/// `const`-friendly twin of [`RouteRow`]. Uses borrowed slices instead
/// of `Vec<String>` so the table can live in static memory.
struct RouteRowStatic {
    methods: &'static [&'static str],
    path: &'static str,
    phase: Phase,
}

fn route_rows() -> Vec<RouteRow> {
    ROUTES
        .iter()
        .map(|r| RouteRow {
            methods: r.methods.iter().map(|m| (*m).to_string()).collect(),
            path: r.path.to_string(),
            phase: r.phase,
        })
        .collect()
}

/// Normalise path-template parameter names so the spec markdown
/// (`/blockchain/transaction/byId/{id}`) and openapi.yaml
/// (`/blockchain/transaction/byId/{txId}`) compare equal. Replaces every
/// `{...}` segment with a single canonical placeholder.
fn normalize_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut in_param = false;
    for c in path.chars() {
        match c {
            '{' if !in_param => {
                in_param = true;
                out.push_str("{X}");
            }
            '}' if in_param => {
                in_param = false;
            }
            _ if in_param => {
                // Drop the parameter-name characters between { and }.
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parse the `/blockchain/*` path declarations in `openapi.yaml`.
///
/// Returns a map of `path -> [methods]`. The parser is intentionally
/// minimal: openapi.yaml is hand-authored and we own its formatting, so
/// no full YAML parser is needed. The recogniser keys on indentation:
/// path lines are at column 2 (`  /blockchain/...:`) and method lines
/// are at column 4 (`    get:`, `    post:`).
fn parse_openapi_paths() -> BTreeMap<String, BTreeSet<String>> {
    const YAML: &str = include_str!("../web/openapi.yaml");
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut current_path: Option<String> = None;
    for line in YAML.lines() {
        if let Some(rest) = line.strip_prefix("  /blockchain/") {
            if let Some(colon) = rest.rfind(':') {
                let suffix = &rest[..colon];
                let path = normalize_path(&format!("/blockchain/{suffix}"));
                current_path = Some(path);
            }
            continue;
        }
        // Top-level keys (`paths:`, `components:`) reset path tracking.
        if line.starts_with(|c: char| !c.is_whitespace()) && !line.is_empty() {
            current_path = None;
            continue;
        }
        if line.starts_with("  /") {
            // Different (non-/blockchain) top-level path — disable
            // method capture until we see another /blockchain/ key.
            current_path = None;
            continue;
        }
        if let Some(ref path) = current_path {
            for verb in ["get", "post", "put", "patch", "delete", "head", "options"] {
                let prefix = format!("    {verb}:");
                if line.trim_end() == prefix {
                    result
                        .entry(path.clone())
                        .or_default()
                        .insert(verb.to_uppercase());
                }
            }
        }
    }
    result
}

// ----- happy path -----

#[test]
fn routes_spec_enumerates_25_rows() {
    let rows = route_rows();
    assert_eq!(
        rows.len(),
        25,
        "routes spec table must enumerate exactly 25 rows (Scala BlockchainApiRoute.scala:69-97); got {}",
        rows.len(),
    );
}

#[test]
fn routes_spec_phase_distribution_matches_design() {
    let rows = route_rows();
    let mut counts: BTreeMap<Phase, usize> = BTreeMap::new();
    for r in &rows {
        *counts.entry(r.phase).or_insert(0) += 1;
    }
    assert_eq!(
        counts.get(&Phase::P1).copied().unwrap_or(0),
        5,
        "P1 row count"
    );
    assert_eq!(
        counts.get(&Phase::P2).copied().unwrap_or(0),
        11,
        "P2 row count (9 in §P2 + 2 ErgoTree-keyed)",
    );
    assert_eq!(
        counts.get(&Phase::P3).copied().unwrap_or(0),
        8,
        "P3 row count"
    );
    assert_eq!(
        counts.get(&Phase::P4).copied().unwrap_or(0),
        1,
        "P4 row count"
    );
    // P5 mounts no new (method, path) tuples — overlay-only change.
    assert_eq!(
        counts.get(&Phase::P5).copied().unwrap_or(0),
        0,
        "P5 row count"
    );
}

#[test]
fn openapi_yaml_declares_every_route_in_spec() {
    let rows = route_rows();
    let openapi = parse_openapi_paths();
    let mut missing = Vec::new();
    for row in &rows {
        let methods = match openapi.get(&row.path) {
            Some(m) => m,
            None => {
                missing.push(format!("{} (no path declared)", row.path));
                continue;
            }
        };
        for m in &row.methods {
            if !methods.contains(m) {
                missing.push(format!(
                    "{} {} (path declared, method missing)",
                    m, row.path
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "openapi.yaml is missing {} (method, path) entries declared in the routes spec:\n{}",
        missing.len(),
        missing.join("\n"),
    );
}

#[test]
fn openapi_yaml_does_not_declare_extra_blockchain_routes() {
    let rows = route_rows();
    let openapi = parse_openapi_paths();
    // For each (path, method) in openapi, verify EITHER the Scala-mirror
    // routes spec OR the Rust-exclusive table lists the same tuple.
    // Extras would mean the spec drifted out of sync.
    let mut spec_tuples: BTreeSet<(String, String)> = BTreeSet::new();
    for row in &rows {
        for m in &row.methods {
            spec_tuples.insert((m.clone(), row.path.clone()));
        }
    }
    for r in RUST_EXCLUSIVE_ROUTES {
        for m in r.methods {
            spec_tuples.insert(((*m).to_string(), r.path.to_string()));
        }
    }
    let mut extras = Vec::new();
    for (path, methods) in &openapi {
        for m in methods {
            if !spec_tuples.contains(&(m.clone(), path.clone())) {
                extras.push(format!("{m} {path}"));
            }
        }
    }
    assert!(
        extras.is_empty(),
        "openapi.yaml declares {} (method, path) entries that no spec table lists:\n{}",
        extras.len(),
        extras.join("\n"),
    );
}

#[test]
fn pre_p1_router_does_not_mount_blockchain_routes() {
    if CURRENT_PHASE != Phase::None {
        // Once any indexer phase is active, this test no longer makes
        // sense — replaced with phase-specific 200/503 walks. We keep
        // the body intact so a regression to Phase::None is loud.
        return;
    }
    let rows = route_rows();
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    let app = router(
        read,
        Some(compat),
        None,
        None,
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    for row in &rows {
        // Substitute the canonical `{X}` placeholder with a concrete
        // 64-hex token / dummy address so axum's path matcher actually
        // dispatches. Pre-P1 there's no router for `/blockchain/*` so
        // any value is fine — axum's default-404 fallback fires
        // regardless.
        let concrete = row.path.replace("{X}", &"aa".repeat(32));
        for verb in &row.methods {
            let req = Request::builder()
                .method(verb.as_str())
                .uri(&concrete)
                .body(Body::empty())
                .unwrap();
            let resp = futures_lite_block_on(app.clone().oneshot(req)).expect("router future");
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "{verb} {} must 404 pre-P1 (indexer not plumbed); got {}",
                concrete,
                resp.status(),
            );
        }
    }
}

/// Phase-aware mount partition: with `IndexerQuery` plumbed and status
/// pinned to `Syncing`, every route whose `phase ≤ CURRENT_PHASE` must
/// dispatch (the status gate fires → `503`, except
/// `/blockchain/indexedHeight` which always returns `200`). Routes whose
/// `phase > CURRENT_PHASE` must still 404 — they are not mounted yet.
///
/// The `IndexerStatus::Syncing` choice is deliberate: it lets the test
/// distinguish "route mounted, gate fired" (503) from "route not
/// mounted" (404) without having to feed each handler a domain-correct
/// stub response. Only the `(method, path)` partition is under test
/// here; per-route success-path bodies live in their dedicated test
/// files.
#[test]
fn phase_walk_asserts_per_phase_mount_partition() {
    if CURRENT_PHASE == Phase::None {
        return;
    }
    let rows = route_rows();
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let compat: Arc<dyn NodeChainQuery> = Arc::new(StubCompat);
    let indexer: Arc<dyn IndexerQuery> = Arc::new(StubIndexer {
        status: IndexerStatus::Syncing,
    });
    let app = router(
        read,
        Some(compat),
        None,
        Some(indexer),
        ergo_ser::address::NetworkPrefix::Mainnet,
    );
    for row in &rows {
        let concrete = row.path.replace("{X}", &"aa".repeat(32));
        for verb in &row.methods {
            let req = Request::builder()
                .method(verb.as_str())
                .uri(&concrete)
                .body(Body::empty())
                .unwrap();
            let resp = futures_lite_block_on(app.clone().oneshot(req)).expect("router future");
            let status = resp.status();
            let mounted_for_phase = row.phase <= CURRENT_PHASE || is_early_shipped(verb, &row.path);
            if mounted_for_phase {
                assert_ne!(
                    status,
                    StatusCode::NOT_FOUND,
                    "{verb} {} (phase {:?}) must be mounted at CURRENT_PHASE={:?}; got 404",
                    concrete,
                    row.phase,
                    CURRENT_PHASE,
                );
                if concrete == "/blockchain/indexedHeight" {
                    assert_eq!(
                        status,
                        StatusCode::OK,
                        "{verb} {} bypasses the status gate; expected 200",
                        concrete,
                    );
                } else {
                    assert_eq!(
                        status,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "{verb} {} must hit the status gate (Syncing → 503); got {}",
                        concrete,
                        status,
                    );
                }
            } else {
                assert_eq!(
                    status,
                    StatusCode::NOT_FOUND,
                    "{verb} {} (phase {:?}) must NOT be mounted at CURRENT_PHASE={:?}; got {}",
                    concrete,
                    row.phase,
                    CURRENT_PHASE,
                    status,
                );
            }
        }
    }
}

// ---- Stubs --------------------------------------------------------

struct StubReadState;

impl NodeReadState for StubReadState {
    fn info(&self) -> ApiInfo {
        ApiInfo {
            agent_name: "ergo-rust".into(),
            node_name: "stub".into(),
            network: "mainnet".into(),
            version: "0.1.0".into(),
            started_at_unix_ms: 0,
            uptime_seconds: 0,
            target_block_interval_ms: 120_000,
        }
    }
    fn status(&self) -> ApiStatus {
        ApiStatus {
            sync_state: SyncStateLabel::AtTip,
            peer_count: 0,
            best_header_height: 0,
            best_full_block_height: 0,
            headers_ahead_of_full_blocks: 0,
            mempool_size: 0,
            snapshot_age_ms: 0,
            bootstrap: None,
            last_block_apply_error: None,
            block_apply_errors_total: 0,
            mempool_tx_requested_total: 0,
            mempool_peer_tx_admitted_total: 0,
            mempool_peer_tx_rejected_total: 0,
            reorgs_total: 0,
            last_reorg_depth: None,
            last_reorg_unix_ms: None,
        }
    }
    fn tip(&self) -> ApiTip {
        ApiTip {
            best_header: ApiHeaderRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                n_bits: 0,
                difficulty: String::new(),
            },
            best_full_block: ApiFullBlockRef {
                height: 0,
                header_id: String::new(),
                parent_id: String::new(),
                timestamp_unix_ms: 0,
                state_root_avl: String::new(),
                n_bits: 0,
                difficulty: String::new(),
            },
            headers_ahead_of_full_blocks: 0,
        }
    }
    fn sync(&self) -> ApiSyncStatus {
        ApiSyncStatus {
            headers_chain_synced: true,
            best_header_height: 0,
            best_full_block_height: 0,
            gap: 0,
            download_window: 0,
            pending_blocks: 0,
            recovery_done: true,
        }
    }
    fn peers(&self) -> Vec<ApiPeer> {
        Vec::new()
    }
    fn mempool_summary(&self) -> ApiMempoolSummary {
        ApiMempoolSummary {
            size: 0,
            total_bytes: 0,
            capacity_count: 0,
            capacity_bytes: 0,
            revalidation_pending: 0,
        }
    }
    fn mempool_transactions(&self) -> ApiMempoolTransactions {
        ApiMempoolTransactions {
            transactions: Vec::new(),
            weight_function: ApiWeightFunction::Cost,
        }
    }
    fn mempool_transaction(&self, _tx_id_hex: &str) -> Option<ApiMempoolTransaction> {
        None
    }
    fn health(&self) -> ApiHealth {
        ApiHealth {
            status: HealthStatus::Ok,
            behind: 0,
            last_progress_age_ms: 0,
            peer_count: 0,
        }
    }
}

/// Minimal compat stub — only the three trait methods that have no
/// default impl are overridden. Every other method falls through to the
/// trait default (empty collection / `None`), which is exactly what this
/// test wants: the `/blockchain/*` surface must 404 regardless of how
/// the compat surface answers.
struct StubCompat;

impl NodeChainQuery for StubCompat {
    fn header_ids_at_height(&self, _height: u32) -> Vec<String> {
        Vec::new()
    }
    fn full_block_by_id(&self, _id: &str) -> Option<ScalaFullBlock> {
        None
    }
    fn info(&self) -> ScalaInfo {
        ScalaInfo {
            last_mempool_update_time: 0,
            current_time: 0,
            network: "mainnet".into(),
            name: "stub".into(),
            state_type: "utxo".into(),
            difficulty: 0,
            best_full_header_id: String::new(),
            best_header_id: String::new(),
            peers_count: 0,
            unconfirmed_count: 0,
            app_version: "0.1.0".into(),
            eip37_supported: true,
            state_root: String::new(),
            genesis_block_id: String::new(),
            rest_api_url: None,
            previous_full_header_id: String::new(),
            full_height: 0,
            headers_height: 0,
            state_version: String::new(),
            full_blocks_score: 0,
            max_peer_height: 0,
            launch_time: 0,
            is_explorer: false,
            last_seen_message_time: 0,
            eip27_supported: true,
            headers_score: 0,
            parameters: Parameters {
                output_cost: 0,
                token_access_cost: 0,
                max_block_cost: 0,
                height: 0,
                max_block_size: 0,
                data_input_cost: 0,
                block_version: 0,
                input_cost: 0,
                storage_fee_factor: 0,
                subblocks_per_block: 0,
                min_value_per_byte: 0,
            },
            is_mining: false,
        }
    }
}

/// Minimal `IndexerQuery` stub. Every method returns the empty/`None`
/// default; the router-walk only asserts mount partitioning, so handler
/// behaviour beyond "trait method exists" is irrelevant. The status
/// drives the status-gate middleware response (Syncing → 503) which is the
/// signal the walk pins on.
struct StubIndexer {
    status: IndexerStatus,
}

impl IndexerQuery for StubIndexer {
    fn indexed_height(&self) -> u64 {
        0
    }
    fn status(&self) -> IndexerStatus {
        self.status.clone()
    }

    fn box_by_id(&self, _: &BoxId) -> Option<IndexedBoxDto> {
        None
    }
    fn box_by_global_index(&self, _: u64) -> Option<IndexedBoxDto> {
        None
    }
    fn boxes_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedBoxDto> {
        Vec::new()
    }

    fn tx_by_id(&self, _: &TxId) -> Option<IndexedTxDto> {
        None
    }
    fn tx_by_global_index(&self, _: u64) -> Option<IndexedTxDto> {
        None
    }
    fn txs_by_global_range(&self, _: u64, _: u64) -> Vec<IndexedTxDto> {
        Vec::new()
    }

    fn address_balance(&self, _: &TreeHash) -> Option<BalanceDto> {
        None
    }
    fn address_txs_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedTxDto> {
        Vec::new()
    }
    fn address_boxes_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_unspent_paged(&self, _: &TreeHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn address_total_txs(&self, _: &TreeHash) -> u64 {
        0
    }
    fn address_total_boxes(&self, _: &TreeHash) -> u64 {
        0
    }

    fn template_boxes_paged(&self, _: &TemplateHash, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_unspent_paged(&self, _: &TemplateHash, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn template_total_boxes(&self, _: &TemplateHash) -> u64 {
        0
    }

    fn token_by_id(&self, _: &TokenId) -> Option<IndexedTokenDto> {
        None
    }
    fn tokens_by_ids(&self, _: &[TokenId]) -> Vec<IndexedTokenDto> {
        Vec::new()
    }
    fn token_boxes_paged(&self, _: &TokenId, _: Page) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_unspent_paged(&self, _: &TokenId, _: Page, _: SortDir) -> Vec<IndexedBoxDto> {
        Vec::new()
    }
    fn token_total_boxes(&self, _: &TokenId) -> u64 {
        0
    }
}

// Minimal local block_on so we don't need to pull in `futures` just to
// drive the oneshot futures synchronously inside a `#[test]` body.
fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread runtime");
    rt.block_on(fut)
}

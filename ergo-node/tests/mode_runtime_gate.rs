//! Runtime activation gate — boot-path coverage for every mode under
//! development.
//!
//! `NodeConfig::load` rejects unsupported field values during TOML
//! parsing — those tests live in `ergo-node/src/config.rs`. This file
//! pins the *runtime* equivalent: a hand-built `NodeConfig` cannot
//! bypass the gate, even if a test fixture or library embedder skips
//! the load path.
//!
//! Tests drive `run_inner` directly (not just the helper function) so
//! a future refactor that disconnects the validator from the boot
//! sequence will fail this test rather than silently regress
//! wire-truthfulness.
//!
//! Currently covers:
//! - Mode 3 (Pruning): `blocks_to_keep != -1` rejected until eviction lands.
//! - Modes 5/6 (Digest backend): the canonical Mode 5 (verify) and Mode 6
//!   (headers-only) combos boot; every other digest combo (partial, plus
//!   the mining / indexer / mempool subsystem combos) is rejected.
//!
//! When each mode's part 2 ships, the matching tests should be
//! removed (or inverted to assert successful boot under the new
//! configuration).

// `spawn_node` is unused by these tests (we want the *failure* path,
// not a live node) but is shared with other integration tests. Silence
// dead-code on the unused helpers in this compilation unit only.
#[allow(dead_code)]
mod common;

use ergo_node::run_inner;

// Phase 4 lifted the Mode 3 activation gate. `blocks_to_keep > 0`
// is now a LIVE runtime path provided `blocks_to_keep >= ROLLBACK_WINDOW
// + SAFETY_MARGIN` (TOML-time check); direct NodeConfig construction
// from tests / embedders bypasses the TOML check, so we test the
// runtime boot path directly. The runtime no longer rejects
// `blocks_to_keep != -1`; the runtime gate that remains is the
// programmatic-construction Mode 5/6 backstop. The corresponding
// "reject pruned" tests below would need a Mode 3 happy-path
// equivalent — covered by `prune_eviction_sync_oracle` /
// `prune_eviction_pipeline_oracle` integration tests in ergo-state.

#[tokio::test]
async fn run_inner_rejects_snapshot_sentinel_at_runtime_gate() {
    // `-2` (UTXOSetBootstrapped) is the wire-only post-snapshot
    // sentinel, never a valid config. The TOML loader rejects it
    // before NodeConfig is built; direct NodeConfig construction
    // bypasses TOML, so the runtime gate must catch it explicitly
    // (Phase 4 backstop). Reject reason must reference the
    // invalid sentinel value, not just "some boot error" — that
    // would mask drift if the gate moved or changed.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode3-utxoboot-rejected"));
    cfg.blocks_to_keep = -2;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("must reject -2"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("-2") && msg.contains("invalid"),
        "rejection must name the invalid sentinel: {msg}",
    );
}

#[tokio::test]
async fn run_inner_rejects_below_archive_sentinel_at_runtime_gate() {
    // `< -1` must reject at the runtime gate (same backstop
    // path as `-2`).
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode3-minus-three-rejected"));
    cfg.blocks_to_keep = -3;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("must reject -3"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("-3") && msg.contains("invalid"),
        "rejection must name the invalid sentinel: {msg}",
    );
}

#[tokio::test]
async fn run_inner_rejects_sub_floor_pruning_at_runtime_gate() {
    // Sub-floor `blocks_to_keep > 0 && < ROLLBACK_WINDOW +
    // SAFETY_MARGIN` must reject at the runtime gate. TOML
    // loader catches this, but the runtime backstop covers
    // direct-construction callers.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode3-sub-floor-rejected"));
    cfg.blocks_to_keep = 5;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("must reject sub-floor"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("rollback-window floor"),
        "rejection must reference the rollback floor: {msg}",
    );
}

// ----- Modes 5/6 (Digest backend + headers-only) -----

#[tokio::test]
async fn run_inner_accepts_canonical_mode_5() {
    // Canonical Mode 5 (Digest Verifier): state_type=Digest +
    // verify_transactions=true + blocks_to_keep=-1 + utxo_bootstrap=false.
    // The digest backend now ships — `run_inner` opens a genesis-seeded
    // `DigestStateStore` and boots the node — so the activation gate
    // admits this combo. Mirrors `run_inner_accepts_canonical_headers_only`.
    let mut cfg = common::make_test_config(std::env::temp_dir().join("ergo-mode5-digest-accepted"));
    cfg.state_type = ergo_node::config::StateType::Digest;
    // verify_transactions=true and blocks_to_keep=-1 are the make_test_config
    // defaults — that IS the canonical Mode 5 row.
    // The loader force-disables the mempool whenever the backend is
    // digest (no box store to validate inputs). Programmatic
    // constructors must mirror that — the runtime backstop rejects
    // digest + enabled mempool.
    cfg.mempool_config.enabled = false;
    let handle = run_inner(cfg)
        .await
        .expect("canonical Mode 5 combo must boot the digest-verifier backend");
    drop(handle);
}

#[tokio::test]
async fn mode_5_survives_a_sync_tick() {
    // Regression for the digest-backend tick-1 panic. `emit_heartbeat`,
    // `publish_snapshot`, and `maybe_rebuild_serve_snapshot` used to call
    // `store.as_utxo_mut().expect("...gated off in digest mode").root_digest()`,
    // which aborts the action loop on the FIRST `sync_tick` of a Mode-5
    // (Digest backend) node — `as_utxo_mut()` is `None` for a digest store.
    // `run_inner_accepts_canonical_mode_5` only boots and drops the handle, so
    // it never drives a tick and never caught this.
    //
    // Here we let the node run past at least one `sync_tick` (1 s cadence;
    // `publish_snapshot` is not behind the heartbeat throttle, so it runs every
    // tick) and assert the action loop is still alive: `shutdown()` awaits the
    // loop's `JoinHandle` and surfaces a panic as `Err`. The same ticks also
    // drive `maybe_rebuild_serve_snapshot`, whose backend-kind early-return now
    // sits ahead of the `tip == 0` check, so a fresh digest node exercises it.
    //
    // Scope: this is a no-panic robustness guard for the digest backend. It does
    // NOT assert Mode 5 is consensus- or Scala-parity-complete — only that the
    // action loop must never abort on a UTXO-only assumption.
    let mut cfg = common::make_test_config(std::env::temp_dir().join("ergo-mode5-sync-tick"));
    cfg.state_type = ergo_node::config::StateType::Digest;
    // Digest backend has no box store, so the loader/runtime disable the mempool.
    cfg.mempool_config.enabled = false;
    let handle = run_inner(cfg).await.expect("canonical Mode 5 must boot");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    handle
        .shutdown()
        .await
        .expect("Mode-5 action loop must survive a sync_tick (no UTXO-only panic)");
}

#[tokio::test]
async fn mode_6_survives_a_sync_tick() {
    // Companion to `mode_5_survives_a_sync_tick`. Canonical Mode 6
    // (headers-only) is accepted by the runtime gate, but — unlike Mode 5 — it
    // boots on the UTXO backend: `boot.rs` routes ONLY canonical Mode 5 to
    // `StateBackendKind::Digest`; Mode 6 falls through to `StateStore` and just
    // sets `headers_only` in the coordinator. So Mode 6 never reaches the
    // UTXO-only `as_utxo_mut()` path that crashed Mode 5 (a common point of
    // confusion — it is NOT a digest-backend mode today). This test pins that
    // the canonical headers-only config boots and survives steady-state ticks;
    // backend routing itself is enforced by the accept/reject gate tests above.
    let mut cfg = common::make_test_config(std::env::temp_dir().join("ergo-mode6-sync-tick"));
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    cfg.mempool_config.enabled = false;
    let handle = run_inner(cfg).await.expect("canonical Mode 6 must boot");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    handle
        .shutdown()
        .await
        .expect("Mode-6 (headers-only) action loop must survive a sync_tick");
}

#[tokio::test]
async fn run_inner_rejects_partial_headers_only_combo() {
    // Partial digest combo: state_type=Digest and
    // verify_transactions=false, but `blocks_to_keep` stays at the
    // make_test_config default (-1) instead of the canonical Mode 6
    // value 0. It is neither canonical Mode 5 (verify must be true) nor
    // canonical Mode 6 (blocks_to_keep must be 0), so the digest
    // activation arm in `validate_runtime_mode_support` rejects it.
    //
    // Both canonical combos are LIVE runtime paths — pinned by
    // `run_inner_accepts_canonical_headers_only` (Mode 6) and
    // `run_inner_accepts_canonical_mode_5` (Mode 5).
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode6-headers-partial-rejected"));
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    // blocks_to_keep stays at -1 — that's what makes this partial.
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("partial digest combo (neither Mode 5 nor Mode 6) must be rejected"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Mode 5") && msg.contains("Mode 6"),
        "rejection must point at the two supported canonical combos: {msg}",
    );
}

#[tokio::test]
async fn run_inner_accepts_canonical_headers_only() {
    // Canonical Mode 6 combo: state_type=Digest + verify_transactions=false
    // + blocks_to_keep=0 + utxo_bootstrap=false. The
    // `is_canonical_mode_6_combo` short-circuit in
    // `validate_runtime_mode_support` lets this through, making Mode 6
    // a live runtime path. `ApiIdentity.history_mode` emits
    // `{"kind":"headers_only"}` for this config (see Phase 4 unit test
    // `build_api_identity_canonical_mode_6_emits_headers_only`).
    //
    // Drop the handle to shut the node down cleanly.
    let mut cfg = common::make_test_config(
        std::env::temp_dir().join("ergo-mode6-headers-canonical-accepted"),
    );
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    // The loader force-disables the mempool whenever the backend
    // is digest (see `mempool_force_off_for_mode`). Programmatic
    // constructors must mirror that — the runtime backstop now
    // rejects digest + enabled mempool.
    cfg.mempool_config.enabled = false;
    let handle = run_inner(cfg)
        .await
        .expect("canonical Mode 6 combo passes is_canonical_mode_6 short-circuit");
    drop(handle);
}

// ----- Mode 5 digest-backend programmatic backstops -----

#[tokio::test]
async fn run_inner_rejects_digest_plus_mining_via_programmatic_backstop() {
    // The TOML loader rejects this combo via `NodeConfig::load`,
    // but a directly-built `NodeConfig` bypasses that path. The
    // runtime backstop in `validate_runtime_mode_support` must
    // catch it before the action loop spawns the mining
    // subsystem, which would try to read UTXO box bytes the
    // digest backend does not retain.
    //
    // Use canonical Mode 6 (Digest + vT=false + btk=0) as the
    // base config so the runtime gate is not short-circuited by
    // the broader Mode 5 rejection arm; the test specifically
    // exercises the mining + Digest sub-arm.
    let mut cfg = common::make_test_config(
        std::env::temp_dir().join("ergo-mode-digest-plus-mining-rejected"),
    );
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    cfg.mining_config.enabled = true;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("digest + mining must be rejected at runtime gate"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("mining"), "must name mining: {msg}");
    assert!(msg.contains("digest"), "must name digest: {msg}");
}

#[tokio::test]
async fn run_inner_rejects_claim_storage_rent_without_indexer() {
    // The storage-rent self-claim enumerates eligible boxes only from the
    // extra-index; mining + claim_storage_rent + indexer disabled is a
    // silent no-op, so the runtime gate rejects it. The TOML loader catches
    // this too, but a directly-built NodeConfig bypasses that path. Base
    // config is utxo Mode 1 (make_test_config defaults), so the digest +
    // mining arm does not short-circuit it first.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-claim-rent-no-indexer-rejected"));
    cfg.mining_config.enabled = true;
    cfg.mining_config.claim_storage_rent = true;
    cfg.indexer_config.enabled = false;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("claim_storage_rent without indexer must be rejected at the runtime gate"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("claim_storage_rent"),
        "must name the field: {msg}"
    );
    assert!(msg.contains("indexer"), "must name indexer: {msg}");
}

#[tokio::test]
async fn run_inner_rejects_digest_plus_indexer_via_programmatic_backstop() {
    let mut cfg = common::make_test_config(
        std::env::temp_dir().join("ergo-mode-digest-plus-indexer-rejected"),
    );
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    cfg.indexer_config.enabled = true;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("digest + indexer must be rejected at runtime gate"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("indexer"), "must name indexer: {msg}");
    assert!(msg.contains("digest"), "must name digest: {msg}");
}

#[tokio::test]
async fn run_inner_rejects_digest_plus_enabled_mempool_via_programmatic_backstop() {
    // The TOML loader force-disables the mempool whenever the
    // backend is digest, but a programmatic constructor that
    // leaves `mempool_config.enabled = true` would otherwise
    // spawn the admission task against the missing box store.
    let mut cfg = common::make_test_config(
        std::env::temp_dir().join("ergo-mode-digest-plus-mempool-rejected"),
    );
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    cfg.mempool_config.enabled = true;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("digest + mempool.enabled must be rejected at runtime gate"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("mempool"), "must name mempool: {msg}");
    assert!(msg.contains("digest"), "must name digest: {msg}");
}

#[tokio::test]
async fn run_inner_rejects_mode_6_plus_utxo_bootstrap() {
    // Codex M2-followup pin: the contradictory combo (headers-only
    // digest + utxo_bootstrap=true) must be rejected at the runtime
    // gate. A NodeConfig built directly (bypassing
    // `NodeConfig::load`'s TOML R1b reject) hits the
    // `validate_runtime_mode_support` backstop. The unit-level test
    // for the gate lives in `ergo-node/src/node/tests.rs` — this is
    // the integration-level pin that the rejection also fires through
    // `run_inner`'s real entry point, so a future refactor that
    // disconnects the validator from boot cannot silently regress.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode6-plus-utxoboot-rejected"));
    cfg.state_type = ergo_node::config::StateType::Digest;
    cfg.verify_transactions = false;
    cfg.blocks_to_keep = 0;
    cfg.utxo_bootstrap = true;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!(
            "Mode 6 + utxo_bootstrap=true must be rejected — no UTXO state to bootstrap into"
        ),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("headers-only") && msg.contains("utxo_bootstrap"),
        "rejection must reference both headers-only and utxo_bootstrap: {msg}",
    );
}

// ----- Mode 2 (UTXO snapshot bootstrap) -----

// ----- Nipopow bootstrap -----

// `run_inner_rejects_nipopow_with_pruning` — removed in Phase 4.
// Mode 3 + NiPoPoW bootstrap is now the standard Mode 4 combo
// (Phase 1b sentinel composition contract). The TOML-time
// rollback-floor check guards misconfiguration; runtime accepts
// the valid combo. The Phase 1b sentinel composition + Phase 2a/2b
// eviction integration tests pin the happy-path behavior.

#[tokio::test]
async fn run_inner_accepts_nipopow_with_utxo_bootstrap_after_part2_14_6_lift() {
    // NiPoPoW Part 2 §14.6 lifted the runtime activation gate. R3
    // (Scala `ErgoSettingsReader.consistentSettings:191-194`) is
    // satisfied by `utxo_bootstrap = true`, the Mode 2 gate was
    // lifted in part 2j, and `validate_runtime_mode_support` in
    // `ergo-node/src/node/mod.rs:794-799` no longer rejects
    // `nipopow_bootstrap = true`. The `PopowBootstrap` reducer is
    // constructed in `NodeState::new` and driven by
    // `drive_popow_bootstrap` in `sync_tick.rs:298` — request
    // fan-out, quorum check, and `apply_popow_proof` are all wired.
    //
    // This test only asserts the gates are lifted; the actual
    // bootstrap pipeline needs live peers and is covered by
    // integration testing.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-nipopow-utxoboot-accepted"));
    cfg.utxo_bootstrap = true;
    cfg.nipopow_bootstrap = true;
    let handle = run_inner(cfg)
        .await
        .expect("nipopow_bootstrap + utxo_bootstrap now passes both gates");
    // Drop the handle to shut the node down.
    drop(handle);
}

// `nipopow_bootstrap = true` standalone (archive + no utxo_bootstrap)
// is rejected by R3 in `NodeConfig::load` at `config.rs:850-857` — a
// Scala-parity compatibility rule that stays forever. R3 fires at
// config-load time, NOT at runtime, so the integration test path
// through `make_test_config` (which hand-builds NodeConfig and
// bypasses `load`) cannot cover it. R3 coverage lives in the unit
// test `nipopow_bootstrap_true_with_archive_rejected_by_r3` at
// `ergo-node/src/config.rs:2261-2283`, which exercises the real
// `NodeConfig::load` path with a TOML fixture.
//
// No runtime gate exists today on the canonical NiPoPoW + Mode 2
// combo, so there is nothing for an integration test to exercise on
// the runtime side. Acceptance of `nipopow_bootstrap + utxo_bootstrap`
// is pinned above.

#[tokio::test]
async fn run_inner_accepts_utxo_bootstrap_after_2j_gate_lift() {
    // Mode 2 part 2j lifted the runtime activation gate.
    // `utxo_bootstrap = true` on a fresh data_dir is accepted; the
    // consume-side pipeline (2f-2i) takes over and discovers,
    // trust-verifies, downloads, reconstructs, and installs a
    // peer-supplied UTXO snapshot. Trust verification remains
    // PROVISIONAL until a Scala oracle pin lands.
    //
    // This test only asserts the gate is lifted; the actual
    // bootstrap pipeline needs live peers and is covered by
    // integration testing.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-mode2-bootstrap-accepted"));
    cfg.utxo_bootstrap = true;
    let handle = run_inner(cfg)
        .await
        .expect("Mode 2 utxo_bootstrap = true now passes the runtime gate");
    // Drop the handle to shut the node down.
    drop(handle);
}

#[tokio::test]
async fn run_inner_rejects_verify_transactions_false_alone() {
    // Even if a caller hand-builds an R1-violating config
    // (vT=false + state_type=Utxo), the runtime gate refuses it.
    // The state_type check fires first only if it's non-default; with
    // Utxo, the gate falls through to the verify_transactions check.
    let mut cfg =
        common::make_test_config(std::env::temp_dir().join("ergo-vt-false-utxo-rejected"));
    cfg.verify_transactions = false;
    let err = match run_inner(cfg).await {
        Ok(_) => panic!("vT=false must be rejected"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("verify_transactions"), "error: {msg}");
    assert!(msg.contains("not yet supported"), "error: {msg}");
}

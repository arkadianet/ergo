//! Config-load tests: precedence, `consistentSettings` R1-R5 gates,
//! TOML section round-trips, `StateType` parse/wire-byte parity, and
//! CLI/TOML override matrix. Sibling to [`super::load`]; uses
//! `super::*` plus the private `toml_sections::TomlConfig` for shared
//! parse fixtures.

use super::toml_sections::TomlConfig;
use super::*;
use ergo_mempool::MempoolConfig;

fn parse(toml_str: &str) -> TomlConfig {
    toml::from_str::<TomlConfig>(toml_str).expect("parse TOML")
}

/// Blake2b256("hello") — same `(secret, hash)` pair used by the
/// Scala node at `reference/ergo/src/main/resources/*.conf` and
/// by the Scala IT client at `NodeApi.scala:52`. Lets `load()`
/// pass the mandatory-hash gate without making every test fixture
/// restate it. Tests that exercise the validation paths write
/// their own TOMLs and assert the rejection.
///
/// Duplicated in `ergo-api/src/auth.rs::tests`,
/// `ergo-api/tests/auth.rs::SCALA_HELLO_HASH`, and
/// `ergo-node/tests/common/mod.rs`. All four MUST stay in sync.
const TEST_DEFAULT_API_KEY_HASH: &str =
    "324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf";

/// Writes `body` to a freshly created, uniquely named temp file and
/// returns its guard. `tempfile` creates the file with `O_EXCL`, so
/// parallel test threads never collide on a name regardless of the
/// platform clock resolution, and the file is removed when the guard
/// drops — including when a failing assertion unwinds the test.
fn temp_toml(body: &str) -> tempfile::NamedTempFile {
    let file = tempfile::Builder::new()
        .prefix("ergo-cfg-test-")
        .suffix(".toml")
        .tempfile()
        .expect("create temp toml");
    std::fs::write(file.path(), body).expect("write temp toml");
    file
}

/// Default per-test TOML carrying only the mandatory api_key_hash, so
/// tests that don't care about TOML structure still satisfy `load()`'s
/// hash gate. Bind the returned guard for the test's lifetime.
fn default_toml() -> tempfile::NamedTempFile {
    temp_toml(&format!(
        "[api.security]\napi_key_hash = \"{TEST_DEFAULT_API_KEY_HASH}\"\n"
    ))
}

fn minimal_cli<P: AsRef<std::path::Path>>(tmp_toml: Option<P>) -> Cli {
    Cli {
        config: tmp_toml.map(|p| p.as_ref().to_path_buf()),
        network: Some("mainnet".into()),
        peers: vec!["127.0.0.1:9030".parse().unwrap()],
        data_dir: Some(
            std::env::temp_dir().join(format!("ergo-config-test-{}", std::process::id())),
        ),
        ibd_flush_interval: 100,
        cache_bytes: None,
        checkpoint_height: None,
        checkpoint_block_id: None,
        mempool_disabled: false,
        mempool_sort: None,
        mining_enabled: false,
        mining_public_key: None,
    }
}

/// Auto-appends the mandatory api_key_hash unless the caller's TOML
/// already pins one (tests that assert on hash-validation errors set
/// their own). Returns the temp-file guard; bind it for the test's
/// lifetime — the file is removed on drop.
fn write_toml(contents: &str) -> tempfile::NamedTempFile {
    let body = if contents.contains("api_key_hash") {
        contents.to_string()
    } else {
        format!("{contents}\n[api.security]\napi_key_hash = \"{TEST_DEFAULT_API_KEY_HASH}\"\n")
    };
    temp_toml(&body)
}

#[test]
fn sync_section_missing_uses_defaults() {
    let cfg = parse("[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    assert!(cfg.sync.download_window.is_none());
}

#[test]
fn sync_section_parses_explicit_values() {
    let cfg = parse("[sync]\ndownload_window = 64\n");
    assert_eq!(cfg.sync.download_window, Some(64));
}

#[test]
fn peers_section_parses_connection_limits() {
    let cfg = parse(
        "[peers]\n\
         max_connections = 90\n\
         target_outbound = 60\n\
         max_inbound = 128\n\
         per_ip_limit = 2\n\
         per_subnet_limit = 4\n",
    );
    assert_eq!(cfg.peers.max_connections, Some(90));
    assert_eq!(cfg.peers.target_outbound, Some(60));
    assert_eq!(cfg.peers.max_inbound, Some(128));
    assert_eq!(cfg.peers.per_ip_limit, Some(2));
    assert_eq!(cfg.peers.per_subnet_limit, Some(4));
}

#[test]
fn default_download_window_matches_p2p_constant() {
    // Regression guard: NodeConfig default must track the p2p crate's
    // canonical DOWNLOAD_WINDOW so raising the p2p default propagates.
    assert_eq!(ergo_p2p::sync::DOWNLOAD_WINDOW, 384);
}

#[test]
fn load_default_download_window_is_p2p_default() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.download_window, ergo_p2p::sync::DOWNLOAD_WINDOW);
}

#[test]
fn load_default_peer_limits_are_decoupled() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(
        cfg.peer_limits,
        ergo_p2p::peer_manager::PeerLimits::default(),
    );
    assert_eq!(cfg.peer_limits.max_connections, 384);
    assert_eq!(cfg.peer_limits.target_outbound, 96);
    assert_eq!(cfg.peer_limits.max_inbound(), 256);
}

#[test]
fn load_toml_peer_limit_override() {
    let path = write_toml(
        "[peers]\n\
         known = [\"127.0.0.1:9030\"]\n\
         max_connections = 100\n\
         target_outbound = 70\n\
         max_inbound = 40\n\
         per_ip_limit = 2\n\
         per_subnet_limit = 5\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(
        cfg.peer_limits,
        ergo_p2p::peer_manager::PeerLimits {
            max_connections: 100,
            target_outbound: 70,
            max_inbound: 40,
            per_ip_limit: 2,
            per_subnet_limit: 5,
        },
    );
}

#[test]
fn load_without_max_inbound_uses_default() {
    // A config predating the max_inbound key must still load, defaulting
    // inbound to DEFAULT_MAX_INBOUND (256) — not the old leftover value.
    let path = write_toml(
        "[peers]\n\
         known = [\"127.0.0.1:9030\"]\n\
         max_connections = 100\n\
         target_outbound = 70\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.peer_limits.max_inbound(), 256);
}

#[test]
fn load_rejects_outbound_target_above_max_connections() {
    let path = write_toml(
        "[peers]\n\
         known = [\"127.0.0.1:9030\"]\n\
         max_connections = 10\n\
         target_outbound = 11\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject invalid peer limits");
    assert!(err.contains("target_outbound"));
}

#[test]
fn load_defaulted_target_clamps_to_low_max_connections() {
    // Back-compat: a config that pins a low max_connections (the old
    // default 80) without setting target_outbound must still boot after
    // the default rose to 96 — the omitted target clamps to the ceiling
    // rather than hard-failing the load. An EXPLICIT target above max is
    // still rejected (see load_rejects_outbound_target_above_max_connections).
    let path = write_toml(
        "[peers]\n\
         known = [\"127.0.0.1:9030\"]\n\
         max_connections = 80\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli)
        .expect("config pinning max_connections=80 with target unset must still load");
    assert_eq!(cfg.peer_limits.max_connections, 80);
    // Clamped to min(DEFAULT_TARGET_OUTBOUND, max_connections) = min(96, 80).
    assert_eq!(cfg.peer_limits.target_outbound, 80);
}

#[test]
fn load_default_node_identity_uses_ergo_rust() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.agent_name, "ergo-rust");
    assert_eq!(cfg.node_name, "ergo-rust-node");
}

#[test]
fn load_toml_download_window_override() {
    let path =
        write_toml("[sync]\ndownload_window = 128\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.download_window, 128);
}

#[test]
fn load_rejects_zero_download_window() {
    let path = write_toml("[sync]\ndownload_window = 0\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject 0");
    assert!(err.contains("download_window = 0"));
}

#[test]
fn load_rejects_oversize_download_window() {
    let path =
        write_toml("[sync]\ndownload_window = 200000\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject huge");
    assert!(err.contains("MAX_DOWNLOAD_WINDOW"));
}

#[test]
fn mainnet_seeds_all_parse() {
    // Mainnet bootstrap peers come from `BootstrapParams::mainnet()`
    // in ergo-chain-spec, which parses 13 entries from mainnet.conf:129-143
    // (filter_map drops anything that won't parse, so a short list
    // would catch a regression).
    let seeds = &ChainSpec::mainnet().bootstrap.seed_peers;
    assert_eq!(seeds.len(), 13);
    // Sanity: the v4 Hetzner seed and the IPv6 entry must both be present.
    assert!(seeds
        .iter()
        .any(|a| a.to_string() == "213.239.193.208:9030"));
    assert!(seeds.iter().any(|a| a.is_ipv6()));
}

#[test]
fn load_merges_user_peer_with_mainnet_seeds() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    // User-supplied 127.0.0.1 is preserved and ordered first.
    assert_eq!(cfg.known_peers[0].to_string(), "127.0.0.1:9030");
    // Plus all 13 mainnet seeds.
    assert_eq!(cfg.known_peers.len(), 1 + 13);
}

#[test]
fn load_dedupes_user_peer_matching_seed() {
    // If the user supplies an address that also appears in seeds,
    // we must not list it twice.
    let toml = default_toml();
    let mut cli = minimal_cli(Some(&toml));
    cli.peers = vec!["213.239.193.208:9030".parse().unwrap()];
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.known_peers.len(), 13);
}

#[test]
fn default_api_bind_is_loopback() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    let addr = cfg.api_bind.expect("default bind set");
    assert!(
        addr.ip().is_loopback(),
        "default api bind must be loopback, got {addr}"
    );
    assert_eq!(addr.port(), 9099);
}

#[test]
fn api_disabled_yields_none() {
    let path = write_toml("[api]\ndisabled = true\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.api_bind.is_none());
}

#[test]
fn api_non_loopback_bind_rejected_without_public_bind() {
    let path =
        write_toml("[api]\nbind = \"0.0.0.0:9090\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should refuse non-loopback");
    assert!(
        err.contains("loopback"),
        "error should mention loopback: {err}"
    );
}

#[test]
fn wallet_expose_private_keys_defaults_false() {
    let path = write_toml("[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("default config must load");
    assert!(
        !cfg.wallet_expose_private_keys,
        "absent [wallet] expose_private_keys must default to false"
    );
}

#[test]
fn wallet_expose_private_keys_explicit_true_threaded() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [wallet]\nexpose_private_keys = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("explicit true must load");
    assert!(
        cfg.wallet_expose_private_keys,
        "explicit [wallet] expose_private_keys = true must thread to NodeConfig"
    );
}

#[test]
fn wallet_section_unknown_field_rejected() {
    // TomlWallet uses deny_unknown_fields so typos surface as a
    // parse error rather than silently defaulting to false.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [wallet]\nexpose_privite_keys = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("typo must reject");
    assert!(
        err.contains("expose_privite_keys") || err.contains("unknown field"),
        "error must cite the unknown field: {err}"
    );
}

#[test]
fn api_enabled_requires_api_key_hash() {
    // Scala-parity boot rule (ErgoApp.scala:40-43). Without the
    // hash, `load()` must refuse to return Ok rather than silently
    // mounting `/wallet/*` ungated. Note: minimal_cli's default
    // TOML provides the hash, so this test writes its own TOML
    // *without* the hash to exercise the rejection path.
    let path = temp_toml("[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("must refuse missing hash");
    assert!(
        err.contains("api_key_hash is required"),
        "error must cite the missing hash: {err}"
    );
}

#[test]
fn api_key_hash_wrong_length_rejected() {
    let path = write_toml(
        "[api.security]\napi_key_hash = \"deadbeef\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("8-char hash must reject");
    assert!(
        err.contains("64 lowercase hex chars"),
        "error must cite length: {err}"
    );
}

#[test]
fn api_key_hash_uppercase_rejected() {
    // Canonical-form invariant: Scala's `ScorexEncoder.encode` is
    // lowercase Base16. Accepting mixed case here would let a
    // misconfigured operator silently never authenticate (header
    // hash is always lowercase, would never match an uppercase
    // stored value). Reject at load instead.
    let upper = "324DCF027DD4A30A932C441F365A25E86B173DEFA4B8E58948253471B81B72CF";
    let path = write_toml(&format!(
        "[api.security]\napi_key_hash = \"{upper}\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n"
    ));
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("uppercase hash must reject");
    assert!(err.contains("lowercase"), "error must cite case: {err}");
}

#[test]
fn api_key_hash_non_hex_rejected() {
    let mixed = format!("z{}", &TEST_DEFAULT_API_KEY_HASH[1..]); // 'z' at start
    let path = write_toml(&format!(
        "[api.security]\napi_key_hash = \"{mixed}\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n"
    ));
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("non-hex must reject");
    assert!(err.contains("hex"), "error must cite hex: {err}");
}

#[test]
fn api_disabled_does_not_require_api_key_hash() {
    // Counterpart to `api_enabled_requires_api_key_hash`: when the
    // operator turns off the API server entirely, there's no
    // surface to gate so the hash isn't required.
    let path = temp_toml("[api]\ndisabled = true\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("api disabled should load without hash");
    assert!(cfg.api_bind.is_none());
    assert!(cfg.api_key_hash.is_none());
}

#[test]
fn api_non_loopback_bind_allowed_with_public_bind() {
    let path = write_toml(
        "[api]\nbind = \"0.0.0.0:9090\"\npublic_bind = true\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    let addr = cfg.api_bind.expect("bind set");
    assert!(!addr.ip().is_loopback());
}

#[test]
fn api_ipv6_loopback_accepted_without_public_bind() {
    let path =
        write_toml("[api]\nbind = \"[::1]:9090\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    let addr = cfg.api_bind.expect("bind set");
    assert!(addr.ip().is_loopback());
}

#[test]
fn load_with_no_user_peers_still_succeeds_on_mainnet() {
    // Seeds alone are enough to bootstrap mainnet — no CLI/TOML
    // peers required. Regresses the earlier "no peers configured"
    // error path for the seed-only case.
    let toml = default_toml();
    let mut cli = minimal_cli(Some(&toml));
    cli.peers = Vec::new();
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.known_peers.len(), 13);
}

#[test]
fn mempool_section_missing_uses_defaults() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    let def = MempoolConfig::default();
    assert!(cfg.mempool_config.enabled);
    assert_eq!(cfg.mempool_config.max_pool_size, def.max_pool_size);
    assert_eq!(
        cfg.mempool_config.min_relay_fee_nano_erg,
        def.min_relay_fee_nano_erg
    );
    assert_eq!(cfg.mempool_sort_policy, "cost");
}

#[test]
fn mempool_disabled_via_toml() {
    let path = write_toml("[mempool]\ndisabled = true\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.mempool_config.enabled);
}

#[test]
fn mempool_disabled_via_cli_flag() {
    let toml = default_toml();
    let mut cli = minimal_cli(Some(&toml));
    cli.mempool_disabled = true;
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.mempool_config.enabled);
}

#[test]
fn mempool_sort_policy_override() {
    let path =
        write_toml("[mempool]\nsort_policy = \"size\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.mempool_sort_policy, "size");
}

#[test]
fn mempool_cli_sort_overrides_toml() {
    let path =
        write_toml("[mempool]\nsort_policy = \"size\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let mut cli = minimal_cli(Some(&path));
    cli.mempool_sort = Some("min".into());
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.mempool_sort_policy, "min");
}

#[test]
fn invalid_sort_policy_rejected() {
    let path =
        write_toml("[mempool]\nsort_policy = \"bogus\"\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject unknown sort policy");
    assert!(
        err.contains("sort_policy"),
        "error should mention sort_policy: {err}"
    );
}

#[test]
fn mempool_knobs_from_toml() {
    let path = write_toml(
        "[mempool]\n\
         max_pool_size = 500\n\
         min_relay_fee_nano_erg = 2000000\n\
         ibd_gate_block_lag = 20\n\
         rebroadcast_count = 7\n\
         \n[peers]\nknown = [\"127.0.0.1:9030\"]\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.mempool_config.max_pool_size, 500);
    assert_eq!(cfg.mempool_config.min_relay_fee_nano_erg, 2_000_000);
    assert_eq!(cfg.mempool_config.ibd_gate_block_lag, 20);
    assert_eq!(cfg.mempool_config.rebroadcast_count, 7);
    // unset fields still default
    assert_eq!(
        cfg.mempool_config.max_pool_bytes,
        MempoolConfig::default().max_pool_bytes
    );
}

#[test]
fn rebroadcast_count_defaults_to_scala_value() {
    // Unset [mempool].rebroadcast_count -> Scala application.conf default of 3.
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.mempool_config.rebroadcast_count, 3);
    assert_eq!(MempoolConfig::default().rebroadcast_count, 3);
}

#[test]
fn mempool_unknown_field_rejected() {
    // `enabled = false` is a common typo for `disabled = true`.
    // deny_unknown_fields must surface this as a parse error, not
    // silently ignore it.
    let path = write_toml("[mempool]\nenabled = false\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject unknown field");
    assert!(
        err.contains("enabled") || err.contains("unknown"),
        "error should identify the unknown field: {err}"
    );
}

#[test]
fn mempool_internal_knob_rejected() {
    // Internal tunables must not be silently ignored via TOML.
    let path =
        write_toml("[mempool]\nnotifier_poll_ms = 500\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject internal field");
    assert!(
        err.contains("notifier_poll_ms") || err.contains("unknown"),
        "error should identify the unknown field: {err}"
    );
}

#[test]
fn mempool_zero_pool_bytes_rejected() {
    let path =
        write_toml("[mempool]\nmax_pool_bytes = 0\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject zero pool bytes");
    assert!(err.contains("max_pool_bytes"), "error: {err}");
}

#[test]
fn mempool_zero_pool_size_rejected() {
    let path =
        write_toml("[mempool]\nmax_pool_size = 0\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject zero pool size");
    assert!(err.contains("max_pool_size"), "error: {err}");
}

#[test]
fn mempool_zero_tx_cost_rejected() {
    let path = write_toml("[mempool]\nmax_tx_cost = 0\n\n[peers]\nknown = [\"127.0.0.1:9030\"]\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject zero tx cost");
    assert!(err.contains("max_tx_cost"), "error: {err}");
}

#[test]
fn peers_bind_addr_default_outbound_only() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(
        cfg.bind_addr.is_none(),
        "absent bind_addr must mean outbound-only",
    );
    assert!(cfg.declared_addr.is_none());
}

#[test]
fn peers_bind_addr_empty_string_treated_as_unset() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\nbind_addr = \"\"\ndeclared_addr = \"\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.bind_addr.is_none());
    assert!(cfg.declared_addr.is_none());
}

#[test]
fn peers_bind_addr_parses_ipv4() {
    let path = write_toml("[peers]\nknown = [\"127.0.0.1:9030\"]\nbind_addr = \"0.0.0.0:9030\"\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.bind_addr.unwrap().to_string(), "0.0.0.0:9030");
}

#[test]
fn peers_declared_addr_parses_ipv4() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\ndeclared_addr = \"203.0.113.10:9030\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.declared_addr.unwrap().to_string(), "203.0.113.10:9030",);
}

#[test]
fn peers_bind_addr_invalid_rejected() {
    let path =
        write_toml("[peers]\nknown = [\"127.0.0.1:9030\"]\nbind_addr = \"not-an-address\"\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject malformed bind_addr");
    assert!(err.contains("bind_addr"), "error: {err}");
}

#[test]
fn peers_declared_addr_invalid_rejected() {
    let path =
        write_toml("[peers]\nknown = [\"127.0.0.1:9030\"]\ndeclared_addr = \"hostname:9030\"\n");
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("should reject hostname declared_addr");
    assert!(err.contains("declared_addr"), "error: {err}");
}

// ----- logging -----

#[test]
fn logging_section_missing_uses_defaults() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.logging.default_level, "info");
    assert_eq!(cfg.logging.format, LoggingFormat::Text);
    assert!(cfg.logging.file.is_none());
}

#[test]
fn logging_format_json_parses() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging]\nformat = \"json\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.logging.format, LoggingFormat::Json);
}

#[test]
fn logging_format_unknown_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging]\nformat = \"yaml\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown format should reject");
    assert!(err.contains("format"), "error: {err}");
}

#[test]
fn logging_default_level_override() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging]\ndefault_level = \"info\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.logging.default_level, "info");
}

#[test]
fn logging_invalid_default_level_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging]\ndefault_level = \"!!!not-a-filter\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("invalid filter should reject");
    assert!(err.contains("default_level"), "error: {err}");
}

#[test]
fn logging_file_defaults_resolve_under_data_dir() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\n",
    );
    let mut cli = minimal_cli(Some(&path));
    let data_dir = std::env::temp_dir().join("ergo-cfg-logfile-default");
    cli.data_dir = Some(data_dir.clone());
    let cfg = NodeConfig::load(cli).expect("load");
    let file = cfg.logging.file.expect("file enabled");
    assert_eq!(file.dir, data_dir.join("logs"));
    assert_eq!(file.prefix, "ergo-node");
    assert_eq!(file.rotation, "daily");
    assert_eq!(file.max_files, 14);
}

#[test]
fn logging_file_relative_dir_resolves_against_data_dir() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\ndir = \"my-logs\"\n",
    );
    let mut cli = minimal_cli(Some(&path));
    let data_dir = std::env::temp_dir().join("ergo-cfg-logfile-rel");
    cli.data_dir = Some(data_dir.clone());
    let cfg = NodeConfig::load(cli).expect("load");
    let file = cfg.logging.file.expect("file enabled");
    assert_eq!(file.dir, data_dir.join("my-logs"));
}

#[test]
fn logging_file_dot_dir_resolves_to_logs_subdir() {
    // `dir = "."` (and ""/"./") would otherwise resolve to the data dir
    // itself, scattering rotating log files among the redb state files and
    // reading as "no file logging". They must normalize to the same
    // <data_dir>/logs default an unset dir uses.
    let mut cases: Vec<&str> = vec![".", "./", ""];
    if cfg!(windows) {
        // ".\" is a current-directory spelling only where `\` is a path
        // separator; on Unix it is an ordinary one-char filename, so this
        // case is Windows-only.
        cases.push(".\\");
    }
    for dot in cases {
        let path = write_toml(&format!(
            "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
             [logging.file]\ndir = {dot:?}\n"
        ));
        let mut cli = minimal_cli(Some(&path));
        let data_dir = std::env::temp_dir().join("ergo-cfg-logfile-dot");
        cli.data_dir = Some(data_dir.clone());
        let cfg = NodeConfig::load(cli).expect("load");
        let file = cfg.logging.file.expect("file enabled");
        assert_eq!(
            file.dir,
            data_dir.join("logs"),
            "dir={dot:?} must normalize to <data_dir>/logs"
        );
    }
}

#[test]
fn logging_file_absolute_dir_preserved() {
    let abs = if cfg!(windows) {
        "C:/var/log/ergo-test"
    } else {
        "/var/log/ergo-test"
    };
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\ndir = {abs:?}\n"
    ));
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    let file = cfg.logging.file.expect("file enabled");
    assert_eq!(file.dir, std::path::PathBuf::from(abs));
}

#[test]
fn logging_file_unknown_rotation_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\nrotation = \"weekly\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown rotation should reject");
    assert!(err.contains("rotation"), "error: {err}");
}

#[test]
fn logging_file_zero_max_files_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\nmax_files = 0\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("zero retention should reject");
    assert!(err.contains("max_files"), "error: {err}");
}

#[test]
fn logging_file_prefix_with_path_separator_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging.file]\nprefix = \"sub/dir/ergo\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("prefix with separator should reject");
    assert!(err.contains("prefix"), "error: {err}");
}

#[test]
fn logging_unknown_field_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [logging]\ntypo_field = \"x\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown field should reject");
    assert!(err.contains("typo_field"), "error: {err}");
}

// ----- Mode 3 (pruning) -----

#[test]
fn blocks_to_keep_default_is_archive() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(
        cfg.blocks_to_keep, -1,
        "default must be -1 (full archive) for Mode 1 parity",
    );
}

#[test]
fn blocks_to_keep_archive_minus_one_accepted() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = -1\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.blocks_to_keep, -1);
}

#[test]
fn blocks_to_keep_zero_requires_canonical_mode_6() {
    // `blocks_to_keep = 0` is reserved for the canonical Mode 6
    // combo (state_type=digest + verify_transactions=false +
    // utxo_bootstrap=false). With the default UTXO + verify
    // combo, the config seam rejects with a Mode 6 alignment
    // message — without this rejection, the load would succeed
    // but boot would die in build_api_identity (which rejects
    // the (Utxo, verify=true, 0) tuple).
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 0\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("non-canonical Mode 6 must reject");
    assert!(
        err.contains("blocks_to_keep = 0") && err.contains("canonical Mode 6"),
        "error: {err}",
    );
}

#[test]
fn blocks_to_keep_below_rollback_floor_rejected() {
    // Phase 4 replaced the "not yet supported" activation gate
    // with the rollback-window floor: pruning must retain at least
    // `ROLLBACK_WINDOW + SAFETY_MARGIN` blocks so a reorg never
    // needs evicted section bytes. blocks_to_keep = 5 (below the
    // floor) must reject.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 5\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("below-floor pruning");
    assert!(err.contains("rollback-window floor"), "error: {err}",);
}

#[test]
fn blocks_to_keep_above_rollback_floor_accepted() {
    // Phase 4: blocks_to_keep above the floor loads successfully.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 3 with adequate window must load");
    assert_eq!(cfg.blocks_to_keep, 1024);
}

// ----- keep_versions (rollback window, Scala keepVersions parity) -----

#[test]
fn keep_versions_defaults_to_rollback_window() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.keep_versions, ergo_state::store::ROLLBACK_WINDOW);
    assert_eq!(
        cfg.indexer_config.rollback_window,
        ergo_state::store::ROLLBACK_WINDOW as u64,
        "indexer window mirrors keep_versions by construction",
    );
}

#[test]
fn keep_versions_custom_value_threads_to_both_windows() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nkeep_versions = 2000\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.keep_versions, 2000);
    assert_eq!(cfg.indexer_config.rollback_window, 2000);
}

#[test]
fn keep_versions_zero_rejected() {
    // Scala allows keepVersions = 0 (a store that can never roll back);
    // we refuse — any reorg would permanently wedge the node.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nkeep_versions = 0\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("keep_versions = 0 must reject");
    assert!(err.contains("keep_versions = 0"), "error: {err}");
}

#[test]
fn keep_versions_raised_raises_blocks_to_keep_floor() {
    // The pruning floor is keyed to the CONFIGURED window, not the
    // compile-time default: blocks_to_keep = 1024 passes the default
    // floor (200 + margin) but must reject under keep_versions = 2000.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\nkeep_versions = 2000\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("floor must track raised window");
    assert!(err.contains("rollback-window floor"), "error: {err}");
}

#[test]
fn keep_versions_huge_value_floor_does_not_overflow() {
    // u32::MAX + SAFETY_MARGIN overflows u32, and an `as i32` cast of the
    // sum would wrap NEGATIVE — silently disabling the floor (or panicking
    // in debug builds). The i64 floor math must instead reject any
    // blocks_to_keep as below the (astronomical) floor.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\nkeep_versions = 4294967295\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("huge window must raise the floor, not wrap it");
    assert!(err.contains("rollback-window floor"), "error: {err}");
}

#[test]
fn keep_versions_lowered_lowers_blocks_to_keep_floor() {
    // Symmetric guard against a boot-brick: a LOWERED window lowers the
    // floor, so a blocks_to_keep below the default floor loads (and the
    // downstream identity re-check must agree — it reads the same
    // configured value, not the const).
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 100\nkeep_versions = 50\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("lowered window must lower the floor");
    assert_eq!(cfg.keep_versions, 50);
    assert_eq!(cfg.blocks_to_keep, 100);
}

#[test]
fn blocks_to_keep_minus_two_rejected() {
    // The wire sentinel `-2` (UTXOSetBootstrapped) is reserved for
    // the post-snapshot runtime state — operators must not set it
    // directly via config.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = -2\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("must reject -2");
    assert!(
        err.contains("blocks_to_keep"),
        "error should mention key: {err}"
    );
}

#[test]
fn blocks_to_keep_minus_three_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = -3\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("must reject < -1");
    assert!(err.contains("blocks_to_keep"), "error: {err}");
}

#[test]
fn pruned_with_extra_index_rejected() {
    // R2 enforcement: extra-index requires un-pruned blocks. Mirrors
    // ErgoSettingsReader.consistentSettings line 189 in Scala.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\n\
         [indexer]\nenabled = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("R2 should reject the combo");
    // Error must point at the conflict — operators need to know which
    // setting to unwind, not a generic "config invalid".
    assert!(err.contains("blocks_to_keep"), "error: {err}");
    assert!(
        err.contains("indexer") || err.contains("extra-index"),
        "error: {err}"
    );
}

#[test]
fn archive_with_extra_index_accepted() {
    // The archive + extra-index combo is the supported Mode 1 setup
    // for explorer-style nodes; R2 only rejects when pruning is on.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = -1\n\
         [indexer]\nenabled = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 1 + extraIndex must work");
    assert_eq!(cfg.blocks_to_keep, -1);
    assert!(cfg.indexer_config.enabled);
}

#[test]
fn pruned_without_extra_index_loads_after_phase4() {
    // Phase 4 lifted the activation gate. blocks_to_keep = 1024
    // (above the rollback floor) without extra-index loads
    // successfully — that's the standard Mode 3 setup.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 3 standard setup must load");
    assert_eq!(cfg.blocks_to_keep, 1024);
}

// ----- Mode 6 (Headers-only) part 1: schema + R1 + activation gate -----

#[test]
fn state_type_default_is_utxo() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.state_type, StateType::Utxo);
    assert!(cfg.verify_transactions, "default vT must be true");
}

#[test]
fn state_type_explicit_utxo_accepted() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nstate_type = \"utxo\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.state_type, StateType::Utxo);
}

#[test]
fn state_type_digest_loads_as_canonical_mode_5() {
    // A bare `state_type = "digest"` resolves to the canonical Mode 5
    // row (verify_transactions defaults true, blocks_to_keep defaults
    // -1, utxo_bootstrap false). The digest backend now ships, so the
    // activation gate admits it. The mempool is force-disabled because
    // the digest backend retains no box bytes to validate tx inputs
    // against.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nstate_type = \"digest\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("canonical Mode 5 must load");
    assert_eq!(cfg.state_type, StateType::Digest);
    assert!(cfg.verify_transactions, "Mode 5 verifies transactions");
    assert_eq!(cfg.blocks_to_keep, -1, "Mode 5 is archive");
    assert!(!cfg.utxo_bootstrap);
    assert!(
        !cfg.mempool_config.enabled,
        "Mode 5 force-disables the mempool (no box store to validate inputs)",
    );
}

#[test]
fn state_type_unknown_value_rejected() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nstate_type = \"flux-capacitor\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("must reject unknown");
    // The error must identify both the bad value and the valid set
    // so operators don't have to guess.
    assert!(err.contains("flux-capacitor"), "error: {err}");
    assert!(err.contains("utxo"), "error: {err}");
    assert!(err.contains("digest"), "error: {err}");
}

#[test]
fn verify_transactions_default_is_true() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.verify_transactions);
}

#[test]
fn verify_transactions_false_with_utxo_rejected_by_r1() {
    // R1 (Scala ErgoSettingsReader.consistentSettings:175-176):
    // verify_transactions=false requires state_type=digest. The
    // error must name both keys.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"utxo\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("R1 must reject");
    assert!(err.contains("verify_transactions"), "error: {err}");
    assert!(err.contains("state_type"), "error: {err}");
}

#[test]
fn non_canonical_mode_6_combo_rejected_before_activation_gate() {
    // Per Scala application.conf:15, the canonical Mode 6 combo is
    // (state_type=digest, verify_transactions=false, blocks_to_keep=0).
    // Any other Digest+vT=false combo is rejected here, BEFORE the
    // activation gate so the operator sees the precise conflict.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"digest\"\n\
         blocks_to_keep = 1024\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("non-canonical must reject");
    assert!(err.contains("blocks_to_keep"), "error: {err}");
    assert!(err.contains("canonical"), "error: {err}");
    assert!(
        !err.contains("not yet supported"),
        "canonical-combo check must fire before activation gate; got: {err}",
    );
}

#[test]
fn non_canonical_mode_6_combo_archive_btk_rejected() {
    // (Digest, vT=false, blocks_to_keep=-1) is also non-canonical;
    // blocks_to_keep must be exactly 0 for headers-only.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"digest\"\n\
         blocks_to_keep = -1\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("must reject");
    assert!(err.contains("blocks_to_keep"), "error: {err}");
    assert!(err.contains("canonical"), "error: {err}");
}

#[test]
fn canonical_mode_6_combo_accepted() {
    // The canonical Mode 6 combo (state_type=digest, vT=false,
    // blocks_to_keep=0) ships in part 2b — it passes all gates
    // and produces a NodeConfig with the expected values. The
    // mempool is force-disabled since headers-only has no UTXO
    // state to validate transactions against.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"digest\"\n\
         blocks_to_keep = 0\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 6 canonical must load");
    assert_eq!(cfg.state_type, StateType::Digest);
    assert!(!cfg.verify_transactions);
    assert_eq!(cfg.blocks_to_keep, 0);
    assert!(
        !cfg.mempool_config.enabled,
        "mempool must be force-disabled in Mode 6 (no UTXO for tx validation)",
    );
}

#[test]
fn mode_6_combined_with_utxo_bootstrap_rejected() {
    // Headers-only + utxo_bootstrap=true is contradictory — the
    // headers-only backend has no UTXO state to install a snapshot
    // into. R1b refuses the combo at TOML load time so the operator
    // sees the precise conflict before any runtime gate fires.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"digest\"\n\
         blocks_to_keep = 0\n\
         [node.utxo]\nutxo_bootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("Mode 6 + utxo_bootstrap must reject");
    assert!(
        err.contains("utxo_bootstrap") && err.contains("headers-only"),
        "rejection must reference both utxo_bootstrap and headers-only: {err}",
    );
}

// ----- Mode 5 (digest verifier) unsupported-subsystem gates -----

#[test]
fn mode_5_mining_enabled_rejected_by_digest_combo_gate() {
    // Mining + state_type=digest is rejected at config load
    // (Scala parity: `failWithError(stateType == Digest &&
    // mining)`). The digest backend retains no box arena to drive
    // candidate generation, so this combo is refused even though the
    // bare Mode 5 row (digest + verify) now loads — the
    // unsupported-subsystem gate fires independently of the activation
    // gate, naming the precise conflict.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nstate_type = \"digest\"\n\
         [mining]\nenabled = true\n\
         miner_public_key_hex = \"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("mining + digest must reject");
    assert!(err.contains("[mining]"), "must name mining: {err}");
    assert!(err.contains("digest"), "must name digest: {err}");
}

#[test]
fn mode_5_indexer_enabled_rejected_by_digest_combo_gate() {
    // Extra-index + state_type=digest is rejected at config load
    // — the indexer needs UTXO box bytes, which the digest backend
    // does not retain. R2 covers `indexer + pruned` and `indexer +
    // utxo_bootstrap`; this Mode 5 gate completes the matrix.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nstate_type = \"digest\"\n\
         [indexer]\nenabled = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("indexer + digest must reject");
    assert!(err.contains("[indexer]"), "must name indexer: {err}");
    assert!(err.contains("digest"), "must name digest: {err}");
}

#[test]
fn claim_storage_rent_without_indexer_rejected() {
    // The storage-rent self-claim enumerates eligible boxes only from the
    // extra-index, so `claim_storage_rent = true` with the indexer off
    // silently collects nothing — config-load rejects it. Utxo Mode 1 (the
    // defaults) so the digest gates do not fire first.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [mining]\nenabled = true\nclaim_storage_rent = true\n\
         miner_public_key_hex = \"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("claim_storage_rent without indexer must reject");
    assert!(
        err.contains("claim_storage_rent"),
        "must name the field: {err}"
    );
    assert!(
        err.contains("[indexer]"),
        "must point at the indexer: {err}"
    );
}

#[test]
fn claim_storage_rent_with_indexer_loads() {
    // Positive path: full archival (Mode 1, the defaults) + mining +
    // claim_storage_rent + indexer enabled is a valid combo — the new gate
    // must NOT reject it (guards against an over-eager gate).
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [indexer]\nenabled = true\n\
         [mining]\nenabled = true\nclaim_storage_rent = true\n\
         miner_public_key_hex = \"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg =
        NodeConfig::load(cli).expect("mining + claim_storage_rent + indexer (Mode 1) must load");
    assert!(cfg.mining_config.claim_storage_rent);
    assert!(cfg.indexer_config.enabled);
}

#[test]
fn mempool_force_off_helper_covers_mode_5_truth_row() {
    // Direct truth-row test of `mempool_force_off_for_mode` for
    // Mode 5 (state_type=Digest, verify_transactions=true). The
    // Mode 5 activation gate blocks the TOML path, so a load-
    // based test could only exercise Mode 6 (vT=false). Calling
    // the helper directly pins the Mode 5 branch even while the
    // activation gate is in place.
    use crate::config::mempool_force_off_for_mode;
    use crate::config::StateType;

    // Mode 5 canonical: state_type=Digest + verify_transactions=true.
    // Must force off via the `state_type == Digest` branch, NOT
    // through `!verify_transactions` (vT is true here).
    assert!(
        mempool_force_off_for_mode(StateType::Digest, true, false, false),
        "Mode 5 (Digest + vT=true) must force-off mempool: no UTXO state for tx admission",
    );

    // Mode 6 canonical: state_type=Digest + verify_transactions=false.
    // Force off via `!verify_transactions` (the older path).
    assert!(
        mempool_force_off_for_mode(StateType::Digest, false, false, false),
        "Mode 6 (Digest + vT=false) must force-off mempool",
    );

    // Mode 1 canonical: state_type=Utxo + verify_transactions=true,
    // no operator overrides. Mempool must remain ON.
    assert!(
        !mempool_force_off_for_mode(StateType::Utxo, true, false, false),
        "Mode 1 (Utxo + vT=true) mempool stays enabled",
    );

    // Operator override via TOML wins regardless of mode.
    assert!(
        mempool_force_off_for_mode(StateType::Utxo, true, true, false),
        "TOML disabled=true forces off even in Mode 1",
    );

    // Operator override via CLI wins regardless of mode.
    assert!(
        mempool_force_off_for_mode(StateType::Utxo, true, false, true),
        "CLI --mempool-disabled forces off even in Mode 1",
    );
}

#[test]
fn mode_6_mempool_force_disabled_in_full_node_config_load() {
    // End-to-end test through `NodeConfig::load` confirming
    // `mempool_force_off_for_mode` is actually called and its
    // result wired into `MempoolConfig::enabled`. Uses the
    // canonical Mode 6 combo because the activation gate still
    // blocks Mode 5 here; the Mode 5 truth row is pinned
    // directly by `mempool_force_off_helper_covers_mode_5_truth_row`.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nverify_transactions = false\nstate_type = \"digest\"\n\
         blocks_to_keep = 0\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 6 canonical loads");
    assert_eq!(cfg.state_type, StateType::Digest);
    assert!(
        !cfg.mempool_config.enabled,
        "Mode 6 mempool must be force-disabled through the load path",
    );
}

// ----- mining -----

#[test]
fn load_mining_enabled_via_cli_without_toml_section_uses_serde_defaults() {
    // `--mining-enabled` with no `[mining]` TOML section: the load path
    // flips `enabled` on a config that starts from `MiningConfig::default`
    // (the minimal test TOML has no `[mining]` table). Before the
    // Default/serde-split fix this path produced `use_external_miner =
    // false` and failed `validate()` at load — this is the regression
    // guard for that.
    let toml = default_toml();
    let cli = Cli {
        mining_enabled: true,
        ..minimal_cli(Some(&toml))
    };
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.mining_config.enabled);
    assert!(cfg.mining_config.use_external_miner);
    assert_eq!(
        cfg.mining_config.block_candidate_generation_interval_ms,
        1000
    );
}

#[test]
fn load_mining_enabled_via_toml_without_pubkey_succeeds() {
    // `[mining] enabled = true` with no pubkey: the reward key is
    // wallet-resolved at candidate time, so load must succeed with
    // `miner_public_key_hex == None` and the serde field defaults filled
    // in (notably `use_external_miner = true`).
    let path = write_toml("[mining]\nenabled = true\n");
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.mining_config.enabled);
    assert!(cfg.mining_config.miner_public_key_hex.is_none());
    assert!(cfg.mining_config.use_external_miner);
}

// ----- Mode 2 (UTXO snapshot bootstrap) part 1 -----

#[test]
fn utxo_bootstrap_default_is_false() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(
        !cfg.utxo_bootstrap,
        "default must be false (no snapshot bootstrap)",
    );
}

#[test]
fn utxo_bootstrap_explicit_false_accepted() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = false\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.utxo_bootstrap);
}

#[test]
fn utxo_bootstrap_true_accepted_after_part_2j_gate_lift() {
    // Mode 2 part 2j lifted the activation gate. A TOML
    // setting `utxo_bootstrap = true` (without conflicting
    // flags like extra-index) now loads successfully. R-rule
    // conflicts (R2 etc.) still fire as configured.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 2 config now loads");
    assert!(cfg.utxo_bootstrap, "utxo_bootstrap = true threaded through");
}

#[test]
fn utxo_bootstrap_with_extra_index_rejected_by_r2() {
    // R2 second half (per Scala
    // ErgoSettingsReader.consistentSettings:189): extra-index
    // requires un-pruned blocks, which means NEITHER pruned
    // suffix length NOR UTXO bootstrap. R2 must fire before the
    // activation gate so the operator sees the real conflict.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = true\n\
         [indexer]\nenabled = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("R2 must reject");
    assert!(err.contains("utxo_bootstrap"), "error: {err}");
    assert!(
        err.contains("indexer") || err.contains("extra-index"),
        "error: {err}",
    );
    // Specifically: must NOT see the activation-gate message —
    // the R2 conflict should win.
    assert!(
        !err.contains("not yet supported"),
        "R2 must fire BEFORE activation gate; got: {err}",
    );
}

#[test]
fn utxo_section_unknown_field_rejected() {
    // deny_unknown_fields on TomlNodeUtxo catches typos like
    // `utxoBootstrap` (Scala camelCase) — without it the key
    // would silently fall back to default.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxoBootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown field");
    assert!(
        err.contains("utxoBootstrap") || err.contains("unknown"),
        "error: {err}",
    );
}

// ----- Nipopow bootstrap part 1 -----

#[test]
fn nipopow_bootstrap_default_is_false() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.nipopow_bootstrap);
}

#[test]
fn nipopow_bootstrap_explicit_false_accepted() {
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.nipopow]\nnipopow_bootstrap = false\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.nipopow_bootstrap);
}

#[test]
fn nipopow_bootstrap_true_with_archive_rejected_by_r3() {
    // R3 (Scala ErgoSettingsReader.consistentSettings:191-194):
    // nipopow_bootstrap requires utxo_bootstrap=true OR
    // blocks_to_keep>=0. A full archive (default: -1, false)
    // cannot PoPoW-bootstrap. R3 must fire before the
    // activation gate so the error names all three keys.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.nipopow]\nnipopow_bootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("R3 must reject");
    assert!(err.contains("nipopow_bootstrap"), "error: {err}");
    assert!(err.contains("utxo_bootstrap"), "error: {err}");
    assert!(err.contains("blocks_to_keep"), "error: {err}");
    // R3 must fire before activation gate — error should NOT
    // be the "not yet supported" one.
    assert!(
        !err.contains("not yet supported"),
        "R3 must fire BEFORE activation gate; got: {err}",
    );
}

#[test]
fn nipopow_bootstrap_with_disabled_genesis_id_rejected_by_r5() {
    // R5 (Scala ErgoSettingsReader.consistentSettings:195-196):
    // nipopow_bootstrap requires a configured genesis id. The
    // `[chain] genesis_id = ""` opt-out is incompatible with
    // PoPoW bootstrap — without a pinned genesis the verifier
    // would accept any chain. Combine `utxo_bootstrap = true`
    // to clear R3 so the R5 check is the one that fires.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = true\n\
         [node.nipopow]\nnipopow_bootstrap = true\n\
         [chain]\ngenesis_id = \"\"\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("R5 must reject");
    assert!(err.contains("nipopow_bootstrap"), "error: {err}");
    assert!(
        err.contains("genesis id") || err.contains("genesis_id"),
        "error: {err}"
    );
}

#[test]
fn nipopow_bootstrap_with_default_genesis_id_accepted() {
    // R5 passes when `[chain] genesis_id` is absent (network
    // default pins the verifier). Combined with utxo_bootstrap
    // to clear R3. The activation gate downstream of R5 is
    // permissive for this combo since both bootstrap paths are
    // canonically supported.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = true\n\
         [node.nipopow]\nnipopow_bootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("R5 must not reject default genesis");
    assert!(cfg.nipopow_bootstrap);
}

#[test]
fn nipopow_bootstrap_with_explicit_genesis_id_accepted_and_preserved() {
    // R5 passes when `[chain] genesis_id` is explicitly set to a
    // 32-byte hex. The bytes must round-trip into `cfg.genesis_id`
    // so the NipopowVerifier downstream pins to exactly the
    // operator's choice.
    let hex_id = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let mut expected = [0u8; 32];
    for (i, slot) in expected.iter_mut().enumerate() {
        *slot = (i + 1) as u8;
    }
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.utxo]\nutxo_bootstrap = true\n\
         [node.nipopow]\nnipopow_bootstrap = true\n\
         [chain]\ngenesis_id = \"{hex_id}\"\n",
    ));
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("R5 must accept explicit genesis_id");
    assert!(cfg.nipopow_bootstrap);
    assert_eq!(cfg.genesis_id, Some(expected));
}

#[test]
fn nipopow_bootstrap_true_with_pruning_accepted_post_phase4() {
    // Phase 4 lifted the Mode 3 activation gate. Pruning +
    // nipopow_bootstrap = true is now the standard Mode 3 +
    // NiPoPoW combo (the Phase 1b sentinel composition contract
    // covers this — both bootstrap writers play nice). The
    // rollback floor still applies: blocks_to_keep = 1024 is
    // safely above ROLLBACK_WINDOW + SAFETY_MARGIN.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblocks_to_keep = 1024\n\
         [node.nipopow]\nnipopow_bootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("Mode 3 + NiPoPoW combo must load post-Phase 4");
    assert_eq!(cfg.blocks_to_keep, 1024);
    assert!(cfg.nipopow_bootstrap);
}

#[test]
fn nipopow_section_unknown_field_rejected() {
    // deny_unknown_fields on TomlNodeNipopow catches typos like
    // `nipopowBootstrap` (Scala camelCase) or `popowBootstrap`
    // (an obsolete Scala alias).
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node.nipopow]\nnipopowBootstrap = true\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown field");
    assert!(
        err.contains("nipopowBootstrap") || err.contains("unknown"),
        "error: {err}",
    );
}

#[test]
fn state_type_byte_codec_round_trip() {
    // Wire byte 0 = UTXO, 1 = Digest. Roundtrip via FromStr/as_str
    // and wire_byte to pin Scala parity.
    assert_eq!(StateType::Utxo.wire_byte(), 0);
    assert_eq!(StateType::Digest.wire_byte(), 1);
    assert_eq!(StateType::Utxo.as_str(), "utxo");
    assert_eq!(StateType::Digest.as_str(), "digest");
    assert_eq!("utxo".parse::<StateType>().unwrap(), StateType::Utxo);
    assert_eq!("UTXO".parse::<StateType>().unwrap(), StateType::Utxo);
    assert_eq!("digest".parse::<StateType>().unwrap(), StateType::Digest);
    assert!("garbage".parse::<StateType>().is_err());
}

#[test]
fn node_section_unknown_field_rejected() {
    // deny_unknown_fields on TomlNode catches typos like
    // `block_to_keep` (singular) — without it a misspelled key
    // would silently fall back to archive mode.
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [node]\nblock_to_keep = 1024\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown [node] field should reject");
    assert!(
        err.contains("block_to_keep") || err.contains("unknown"),
        "error: {err}"
    );
}

// ----- [voting] -----

/// A valid 33-byte compressed secp256k1 point — the same generator-point hex
/// the mining tests use to satisfy `MiningConfig::validate`.
const TEST_MINER_PK_HEX: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn voting_defaults_to_no_targets() {
    // No `[voting]` section ⇒ empty target map; the node mines neutral.
    let path = default_toml();
    let cli = minimal_cli(Some(path.path()));
    let cfg = NodeConfig::load(cli).expect("default config must load");
    assert!(
        cfg.voting_targets.is_empty(),
        "absent [voting] ⇒ no configured targets"
    );
}

#[test]
fn voting_targets_resolve_names_to_ids() {
    // `[voting.targets]` maps canonical camelCase parameter names to numeric
    // targets; load resolves each name to its signed-i8 id (stored as u8).
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [mining]\nenabled = true\nminer_public_key_hex = \"{TEST_MINER_PK_HEX}\"\n\
         [voting.targets]\nstorageFeeFactor = 1300000\nmaxBlockSize = 600000\n",
    ));
    let cli = minimal_cli(Some(&path));
    let cfg = NodeConfig::load(cli).expect("valid voting targets must load");
    assert_eq!(cfg.voting_targets.get(&1), Some(&1_300_000i64), "id 1");
    assert_eq!(cfg.voting_targets.get(&3), Some(&600_000i64), "id 3");
    assert_eq!(cfg.voting_targets.len(), 2);
}

#[test]
fn voting_unknown_param_name_rejected() {
    // blockVersion (123) is NOT operator-votable; a target for it (or a typo)
    // is a startup config error naming the section + the bad name.
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [mining]\nenabled = true\nminer_public_key_hex = \"{TEST_MINER_PK_HEX}\"\n\
         [voting.targets]\nblockVersion = 4\n",
    ));
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("non-votable param must reject");
    assert!(err.contains("[voting]"), "must name the section: {err}");
    assert!(err.contains("blockVersion"), "must name the param: {err}");
}

#[test]
fn voting_target_out_of_range_rejected() {
    // storageFeeFactor (id 1) allowable range is [0, 2_500_000]. A target above
    // the max can never be a settling value (the recompute won't step past the
    // bound), so it is a startup config error rather than a silent bound-pin.
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [mining]\nenabled = true\nminer_public_key_hex = \"{TEST_MINER_PK_HEX}\"\n\
         [voting.targets]\nstorageFeeFactor = 9000000\n",
    ));
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("out-of-range target must reject");
    assert!(err.contains("[voting]"), "must name the section: {err}");
    assert!(
        err.contains("allowable") && err.contains("2500000"),
        "must report the allowable range: {err}"
    );
}

#[test]
fn voting_targets_without_mining_rejected() {
    // Configured targets with mining disabled never cast a vote — refuse to
    // start so the misconfiguration surfaces (mirrors the claim_storage_rent
    // requires-indexer gate).
    let path = write_toml(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [voting.targets]\nstorageFeeFactor = 1300000\n",
    );
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("voting without mining must reject");
    assert!(err.contains("[voting]"), "must name the section: {err}");
    assert!(err.contains("[mining]"), "must point at mining: {err}");
}

#[test]
fn voting_section_unknown_field_rejected() {
    // deny_unknown_fields on the [voting] section catches typos like a
    // mis-keyed `target` (singular) instead of the `targets` map.
    let path = write_toml(&format!(
        "[peers]\nknown = [\"127.0.0.1:9030\"]\n\
         [mining]\nenabled = true\nminer_public_key_hex = \"{TEST_MINER_PK_HEX}\"\n\
         [voting]\ntarget = 1\n",
    ));
    let cli = minimal_cli(Some(&path));
    let err = NodeConfig::load(cli).expect_err("unknown [voting] field should reject");
    assert!(
        err.contains("target") || err.contains("unknown"),
        "error: {err}"
    );
}

// ----- [shadow] section (workstream D) -------------------------------------

#[test]
fn shadow_section_absent_resolves_disabled_defaults() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(!cfg.shadow_config.enabled);
    assert_eq!(cfg.shadow_config.reference_url, "http://127.0.0.1:9053");
    assert_eq!(cfg.shadow_config.interval_secs, 30);
    assert_eq!(cfg.shadow_config.lag_tolerance, 3);
    assert_eq!(cfg.shadow_config.stall_gap_threshold, 10);
    assert_eq!(cfg.shadow_config.request_timeout_secs, 5);
}

#[test]
fn shadow_enabled_resolves_and_trims_reference_url() {
    let toml = write_toml(
        "[shadow]\n\
         enabled = true\n\
         reference_url = \"  http://10.0.0.5:9053  \"\n\
         interval_secs = 12\n\
         lag_tolerance = 5\n",
    );
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert!(cfg.shadow_config.enabled);
    assert_eq!(cfg.shadow_config.reference_url, "http://10.0.0.5:9053");
    assert_eq!(cfg.shadow_config.interval_secs, 12);
    assert_eq!(cfg.shadow_config.lag_tolerance, 5);
    // Unset knobs keep defaults.
    assert_eq!(cfg.shadow_config.stall_gap_threshold, 10);
}

#[test]
fn shadow_unknown_field_is_a_parse_error() {
    let toml = write_toml("[shadow]\nenabld = true\n");
    let cli = minimal_cli(Some(&toml));
    assert!(NodeConfig::load(cli).is_err(), "deny_unknown_fields");
}

#[test]
fn shadow_enabled_rejects_bad_scheme_and_zero_knobs() {
    for body in [
        "[shadow]\nenabled = true\nreference_url = \"ws://x:1\"\n",
        "[shadow]\nenabled = true\ninterval_secs = 0\n",
        "[shadow]\nenabled = true\nrequest_timeout_secs = 0\n",
        "[shadow]\nenabled = true\nstall_gap_threshold = 0\n",
    ] {
        let toml = write_toml(body);
        let cli = minimal_cli(Some(&toml));
        assert!(NodeConfig::load(cli).is_err(), "should reject: {body}");
    }
}

#[test]
fn shadow_disabled_skips_validation() {
    // A dormant (disabled) section must never brick boot, even when junk.
    let toml = write_toml("[shadow]\nreference_url = \"ws://junk\"\ninterval_secs = 0\n");
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("dormant section loads");
    assert!(!cfg.shadow_config.enabled);
}

# Miner Attribution + Mining Section Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show who mined every block across the operator UI (pool label → address link → "you" badge), and add a dedicated Mining section covering the node's own mining state plus the network mining landscape.

**Architecture:** Two small server additions (miner fields on `ApiRecentBlock`, new `GET /api/v1/mining/minerStats`) feed pure-additive UI enrichment. The block-detail view resolves pk→address through the existing `/utils/rawToAddress` with a session cache. Everything degrades to today's rendering when a fetch fails or a field is absent. Spec: `docs/superpowers/specs/2026-07-05-ui-miner-attribution-design.md`.

**Tech Stack:** Rust (axum 0.7, utoipa, serde) in `ergo-api`/`ergo-node`; zero-dependency ES-module SPA in `ergo-api/web/` (CSP `script-src 'self'`, no inline scripts, data via `textContent`/`createElement` only).

**Worktree:** already created — `/home/rkadias/coding/development/arkadianet/ergo/.claude/worktrees/ui-miner-attribution`, branch `feat/ui-miner-attribution` (off main dcc81af). Run everything from there. Do NOT `cd` to the parent repo (see the subagent-worktree-cwd-trap memory: always `git -C <worktree>` or verify `pwd` before git commands, and verify the branch before/after each commit).

**Conventions that will bite you if ignored:**
- `cargo fmt --all` before every Rust commit; CI runs `cargo fmt --all -- --check`.
- The gate is WHOLE-workspace: `cargo clippy --all-targets --all-features -- -D warnings` and `cargo test --all` — never `-p` subsets for the final gate ( `-p` is fine for the tight TDD loop).
- Any change to utoipa-annotated handlers or DTOs requires regenerating `ergo-api/tests/fixtures/openapi_native.yaml`:
  `cargo test -p ergo-api openapi_native_snapshot -- --ignored --nocapture regenerate`
- JS files: `node --check <file>` after editing (no other JS toolchain exists).
- New JS files must be registered in `ergo-api/src/web.rs` (include_str!) AND routed in `ergo-api/src/server.rs`, or the SPA 404s on import and the whole section silently fails to load.

**Verified reference vector (live mainnet, 2026-07-05):** pk `0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f` → mainnet P2PK address `9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx` (2Miners). Use it in unit tests.

---

### Task 1: Server — miner fields on `ApiRecentBlock` (+ `NodeState.network`)

**Files:**
- Modify: `ergo-api/src/types.rs` (~line 682, end of ApiRecentBlock; also the stale doc comment ~line 59)
- Modify: `ergo-api/tests/recent_blocks_route.rs` (block() helper ~line 127 + new test)
- Modify: `ergo-node/src/node/state.rs` (~line 311, near `recent_blocks_cache`)
- Modify: `ergo-node/src/node/boot.rs` (~line 1492, the `NodeState { … recent_blocks_cache: None, … }` literal at line 1398)
- Modify: `ergo-node/src/node/tests.rs` (`make_state` line 41, `make_digest_state` line 59)
- Modify: `ergo-node/src/node/snapshot_emit.rs` (thread network; construct fields; stub helper ~line 1527)

- [ ] **Step 1: Write the failing route test**

In `ergo-api/tests/recent_blocks_route.rs`, extend the `block()` helper (lines ~127-135) with the two new fields and add a serialization test. The helper currently ends with `delivered_by: None,`; change it to:

```rust
fn block(height: u32) -> ApiRecentBlock {
    ApiRecentBlock {
        height,
        header_id: format!("{height:064x}"),
        ts_unix_ms: 1_700_000_000_000 + height as u64,
        txs: height,
        size_bytes: 1000 + height as u64,
        delivered_by: None,
        miner_pk: Some(format!("02{height:064x}")),
        miner_address: Some(format!("9addr{height}")),
    }
}
```

Add at the end of the file:

```rust
#[tokio::test]
async fn recent_blocks_serializes_miner_fields_and_omits_when_absent() {
    // Present: both keys appear with the stub's values.
    let (status, v) = get("/api/v1/blocks/recent?n=1", vec![block(7)]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v[0]["miner_pk"], format!("02{:064x}", 7));
    assert_eq!(v[0]["miner_address"], "9addr7");

    // Absent: a block built without miner facts must OMIT the keys entirely
    // (old-node / faulted-read compatibility), not serialize null.
    let mut b = block(9);
    b.miner_pk = None;
    b.miner_address = None;
    let (status, v) = get("/api/v1/blocks/recent?n=1", vec![b]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(v[0].get("miner_pk").is_none(), "miner_pk must be omitted when None");
    assert!(v[0].get("miner_address").is_none(), "miner_address must be omitted when None");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ergo-api --test recent_blocks_route 2>&1 | tail -20`
Expected: COMPILE FAILURE — `struct ApiRecentBlock has no field named miner_pk`.

- [ ] **Step 3: Add the fields to `ApiRecentBlock`**

In `ergo-api/src/types.rs`, after the `delivered_by` field (line ~682):

```rust
    /// Miner public key from the header's Autolykos solution (33-byte
    /// compressed secp256k1 point, hex) — present on both v1 and v2
    /// solutions. Identifies who mined the block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_pk: Option<String>,
    /// P2PK base58 address derived from `miner_pk` with this node's
    /// network prefix — the conventional "miner" identity explorers
    /// show. `None` only if address encoding failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub miner_address: Option<String>,
```

While in this file: fix the stale doc comment at ~line 59. It currently reads "`mining` is reserved for the future mining crate — always `false`", but live nodes return `true`. Replace that sentence with:

```rust
/// `mining` mirrors the node's mining configuration (whether the
/// `/mining/*` work-serving routes are wired).
```

Now fix the two other construction sites that stopped compiling:
- `ergo-node/src/node/snapshot_emit.rs` `try_recent_block` constructor (~line 692): add `miner_pk: None, miner_address: None,` temporarily (Step 5 fills them in).
- `ergo-node/src/node/snapshot_emit.rs` `recent_block_stub` test helper (~line 1527): add `miner_pk: None, miner_address: None,`.

(`merge_delivered_by` at snapshot_emit.rs:505 uses `ApiRecentBlock { delivered_by, ..b.clone() }` struct-update — propagates the new fields automatically, no edit.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p ergo-api --test recent_blocks_route 2>&1 | tail -5`
Expected: PASS (all tests in the file, including the new one).

- [ ] **Step 5: Write the failing derivation unit test (ergo-node)**

The derivation lives in a tiny pure helper so it's testable without a store. In `ergo-node/src/node/snapshot_emit.rs`, find the test module at the bottom (`#[cfg(test)] mod tests` — same module that holds `recent_block_stub`) and add:

```rust
    #[test]
    fn miner_fields_derives_pk_hex_and_mainnet_p2pk_address() {
        // Live-verified vector: 2Miners' mining pk → its P2PK address
        // (cross-checked against /utils/rawToAddress on mainnet 2026-07-05).
        let pk = hex::decode("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
            .unwrap();
        let (pk_hex, addr) =
            miner_fields(&pk, ergo_ser::address::NetworkPrefix::Mainnet);
        assert_eq!(
            pk_hex.as_deref(),
            Some("0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f")
        );
        assert_eq!(
            addr.as_deref(),
            Some("9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx")
        );
    }

    #[test]
    fn miner_fields_bad_pk_length_yields_pk_but_no_address() {
        let (pk_hex, addr) = miner_fields(&[0u8; 5], ergo_ser::address::NetworkPrefix::Mainnet);
        assert_eq!(pk_hex.as_deref(), Some("0000000000"));
        assert!(addr.is_none(), "address encoding must fail closed to None");
    }
```

Run: `cargo test -p ergo-node miner_fields 2>&1 | tail -5`
Expected: COMPILE FAILURE — `miner_fields` not found.

- [ ] **Step 6: Implement `miner_fields` + thread `NetworkPrefix` through**

1. `ergo-node/src/node/state.rs` — add a field next to `recent_blocks_cache` (~line 311):

```rust
    /// Address-prefix network byte (mainnet/testnet), used at
    /// snapshot-assembly time to derive `ApiRecentBlock.miner_address`
    /// from the header's Autolykos solution pk.
    pub(super) network: ergo_ser::address::NetworkPrefix,
```

2. `ergo-node/src/node/boot.rs` — in the `NodeState { … }` literal (starts line ~1398), next to `recent_blocks_cache: None,` (line ~1492) add:

```rust
        network: config.chain_spec.network_params.address_prefix,
```

(`config` is in scope — the same expression is already used at boot.rs:1058.)

3. `ergo-node/src/node/tests.rs` — in BOTH `make_state` (line 41) and `make_digest_state` (line 59) `NodeState` literals add:

```rust
        network: ergo_ser::address::NetworkPrefix::Mainnet,
```

4. `ergo-node/src/node/snapshot_emit.rs`:

Add to the imports at the top of the file:

```rust
use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};
```

Add the helper (near `try_recent_block`):

```rust
/// Miner attribution facts from a header's Autolykos solution pk bytes:
/// (hex pk, derived P2PK address). The address encodes with this node's
/// network prefix; an encode failure (wrong length) degrades to `None`
/// rather than omitting the block.
fn miner_fields(pk_bytes: &[u8], network: NetworkPrefix) -> (Option<String>, Option<String>) {
    (
        Some(hex::encode(pk_bytes)),
        encode_p2pk_from_pubkey(network, pk_bytes).ok(),
    )
}
```

Thread the prefix through the call chain:
- `publish_snapshot` (line ~142): the `recent_blocks_for_tip(&mut state.recent_blocks_cache, …)` call gains a final argument `state.network` (Copy — no borrow conflict with the `&mut` cache borrow).
- `recent_blocks_for_tip(cache, store, tip_id, tip_height)` → add param `network: NetworkPrefix`, pass into `build_recent_blocks(store, tip_id, tip_height, network)`.
- `build_recent_blocks(store, tip_id, tip_height)` → add param `network: NetworkPrefix`, pass into `try_recent_block(&sections, &id, height, &header, header_bytes.len(), network)`.
- `try_recent_block(…)` → add param `network: NetworkPrefix`; replace the temporary `miner_pk: None, miner_address: None,` from Step 3 with:

```rust
    let (miner_pk, miner_address) = miner_fields(header.solution.pk().as_bytes(), network);
    Some(ApiRecentBlock {
        height,
        header_id: hex::encode(id),
        ts_unix_ms: header.timestamp,
        txs: bt.transactions.len() as u32,
        size_bytes: (header_len + tx_bytes.len() + ext_len + adp_len) as u64,
        // `delivered_by` is merged in at snapshot-assembly time from the
        // first-deliverer ring (a transient P2P fact), NOT baked into the
        // tip-keyed recent-blocks cache (committed-state only). See
        // `merge_delivered_by` at the `publish_snapshot` call site.
        delivered_by: None,
        miner_pk,
        miner_address,
    })
```

(`header.solution.pk()` returns `&GroupElement`; `.as_bytes()` is the same accessor `encode_pow_solutions` in api_bridge/compat.rs:99-118 uses.)

- [ ] **Step 7: Run ergo-node tests to verify they pass**

Run: `cargo test -p ergo-node miner_fields 2>&1 | tail -5` — expected PASS (2 tests).
Run: `cargo test -p ergo-node snapshot 2>&1 | tail -5` — expected PASS (no regressions in snapshot_emit tests).
Run: `cargo test -p ergo-api 2>&1 | tail -5` — expected PASS.

- [ ] **Step 8: Regenerate the OpenAPI snapshot (ApiRecentBlock schema changed)**

Run: `cargo test -p ergo-api openapi_native_snapshot -- --ignored --nocapture regenerate`
Then: `cargo test -p ergo-api --test openapi_native_snapshot 2>&1 | tail -3`
Expected: PASS (fixture now includes miner_pk/miner_address in the ApiRecentBlock schema).

- [ ] **Step 9: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(api): miner pk + derived P2PK address on /api/v1/blocks/recent

Thread the address-prefix byte into snapshot assembly so every recent
block carries its miner identity (powSolutions pk, hex) and the
conventional explorer-style P2PK address derived from it. Fields are
optional-and-omitted for wire compatibility. Also corrects the stale
'mining is always false' doc comment on ApiIdentity.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Server — `GET /api/v1/mining/minerStats`

**Files:**
- Modify: `ergo-api/src/types.rs` (new DTOs, after `ApiDifficultySeries`)
- Modify: `ergo-api/src/server.rs` (handler + mount in the compat arm + NativeOpenApi lists + import)
- Create: `ergo-api/tests/miner_stats_route.rs`
- Regenerate: `ergo-api/tests/fixtures/openapi_native.yaml`

- [ ] **Step 1: Write the failing route test**

Create `ergo-api/tests/miner_stats_route.rs`. Model it on `ergo-api/tests/difficulty_history_route.rs` (same stub pattern): copy that file's `StubReadState` (lines 36-129), `StubChain` (lines 133-161), `header(…)` + `empty_info()` helpers (lines 163-234), `build_app` (236-239) and `get` (241-255) VERBATIM, with two changes: (a) the `header` helper gains a `pk: &str` parameter that lands in `pow_solutions.pk` (replace `pk: String::new()` with `pk: pk.to_string()`), and (b) import `ApiMinerStats` instead of `ApiDifficultySeries` from `ergo_api::types`. Then add these tests:

```rust
const PK_2MINERS: &str = "0274e729bb6615cbda94d9d176a2f1525068f12b330e38bbbf387232797dfd891f";
const ADDR_2MINERS: &str = "9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx";

async fn request(headers: Vec<ScalaHeader>, query: &str) -> (ApiMinerStats, u32) {
    let stub = Arc::new(StubChain::new(headers));
    let app = build_app(stub.clone());
    let (status, bytes) = get(app, &format!("/api/v1/mining/minerStats{query}")).await;
    assert_eq!(status, StatusCode::OK, "minerStats must answer 200");
    let stats: ApiMinerStats =
        serde_json::from_slice(&bytes).expect("body deserialises as ApiMinerStats");
    (stats, stub.last_requested.load(Ordering::SeqCst))
}

#[tokio::test]
async fn miner_stats_folds_by_pk_sorts_by_count_and_derives_addresses() {
    // Heights 100..=104: pkA mines 3 (last 104), pkB mines 2 (last 103).
    let pk_b = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let headers = vec![
        header(100, 1_000, "1", PK_2MINERS),
        header(101, 2_000, "1", pk_b),
        header(102, 3_000, "1", PK_2MINERS),
        header(103, 4_000, "1", pk_b),
        header(104, 5_000, "1", PK_2MINERS),
    ];
    let (stats, _) = request(headers, "").await;
    assert_eq!(stats.tip_height, 104);
    assert_eq!(stats.blocks, 5);
    assert_eq!(stats.miners.len(), 2);
    // Sorted by count desc.
    assert_eq!(stats.miners[0].pk, PK_2MINERS);
    assert_eq!(stats.miners[0].count, 3);
    assert_eq!(stats.miners[0].last_height, 104);
    // Live-verified derivation vector.
    assert_eq!(stats.miners[0].address.as_deref(), Some(ADDR_2MINERS));
    assert_eq!(stats.miners[1].count, 2);
    assert_eq!(stats.miners[1].last_height, 103);
}

#[tokio::test]
async fn miner_stats_bad_pk_hex_degrades_to_absent_address() {
    let (stats, _) = request(vec![header(10, 1_000, "1", "zz-not-hex")], "").await;
    assert_eq!(stats.miners.len(), 1);
    assert!(stats.miners[0].address.is_none(), "bad pk folds but gets no address");
}

#[tokio::test]
async fn miner_stats_window_defaults_and_clamps() {
    assert_eq!(request(Vec::new(), "").await.1, 720, "default window is 720");
    assert_eq!(request(Vec::new(), "?window=128").await.1, 128);
    assert_eq!(request(Vec::new(), "?window=0").await.1, 1, "clamps up to 1");
    assert_eq!(request(Vec::new(), "?window=99999").await.1, 16_384, "clamps to ceiling");
    assert_eq!(request(Vec::new(), "?window=junk").await.1, 720, "non-numeric falls back");
}

#[tokio::test]
async fn miner_stats_empty_chain_yields_empty_stats() {
    let (stats, _) = request(Vec::new(), "").await;
    assert_eq!(stats.tip_height, 0);
    assert_eq!(stats.blocks, 0);
    assert!(stats.miners.is_empty());
}

#[tokio::test]
async fn miner_stats_absent_without_chain_reader_404s() {
    let read: Arc<dyn NodeReadState> = Arc::new(StubReadState);
    let app = router(read, None, None, None, NetworkPrefix::Mainnet);
    let (status, _) = get(app, "/api/v1/mining/minerStats").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "route rides the chain reader");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p ergo-api --test miner_stats_route 2>&1 | tail -10`
Expected: COMPILE FAILURE — `ApiMinerStats` not found.

- [ ] **Step 3: Add the DTOs**

In `ergo-api/src/types.rs`, immediately after `ApiDifficultySeries`:

```rust
/// One miner's aggregate over the `minerStats` window.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStat {
    /// Miner public key (33-byte compressed point, hex) from the folded
    /// headers' Autolykos solutions.
    pub pk: String,
    /// P2PK address derived from `pk` with this node's network prefix.
    /// Absent only when the stored pk bytes fail address encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Blocks this miner produced within the window.
    pub count: u32,
    /// Height of this miner's most recent block in the window.
    pub last_height: u32,
}

/// Response of `GET /api/v1/mining/minerStats` — the network mining
/// landscape over the last `window` headers of the canonical chain.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiMinerStats {
    /// Best-header height at fold time (0 on an empty chain).
    pub tip_height: u32,
    /// Requested window after clamping to `[1, 16384]`.
    pub window: u32,
    /// Headers actually scanned — shorter than `window` near genesis.
    pub blocks: u32,
    /// Miners sorted by `count` descending, ties by `last_height`
    /// descending.
    pub miners: Vec<ApiMinerStat>,
}
```

- [ ] **Step 4: Add the handler and mount it**

In `ergo-api/src/server.rs`:

1. Extend the line-98 import: `use ergo_ser::address::{encode_p2pk_from_pubkey, NetworkPrefix};`
2. Add `ApiMinerStat, ApiMinerStats,` to the `use crate::types::{…}` list (line ~82).
3. Add the handler next to `difficulty_history_handler` (~line 1571):

```rust
#[utoipa::path(
    get,
    path = "/api/v1/mining/minerStats",
    tag = "chain",
    params(
        ("window" = Option<u32>, Query,
         description = "Most-recent headers to fold, by miner pk. \
Defaults to 720 (~one day at 120s blocks); clamped to [1, 16384]."),
    ),
    responses(
        (status = 200,
         description = "Blocks-per-miner over the recent chain, sorted by \
count descending, each with the P2PK address derived from the miner pk. \
Conditional: mounted only when the node is wired with a chain reader.",
         body = ApiMinerStats, content_type = "application/json"),
    ),
)]
async fn miner_stats_handler(
    State((chain, network)): State<(Arc<dyn NodeChainQuery>, NetworkPrefix)>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let window = params
        .get("window")
        .and_then(|raw| raw.parse::<u32>().ok())
        .unwrap_or(720)
        .clamp(1, 16_384);
    let headers = chain.last_headers(window);
    let blocks = headers.len() as u32;
    let tip_height = headers.last().map(|h| h.height).unwrap_or(0);
    // Fold by pk hex: (count, last_height). Headers arrive ascending, so
    // a plain max keeps the latest height per miner.
    let mut agg: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();
    for h in &headers {
        let e = agg.entry(h.pow_solutions.pk.clone()).or_insert((0, 0));
        e.0 += 1;
        if h.height > e.1 {
            e.1 = h.height;
        }
    }
    let mut miners: Vec<ApiMinerStat> = agg
        .into_iter()
        .map(|(pk, (count, last_height))| {
            let address = hex::decode(&pk)
                .ok()
                .and_then(|b| encode_p2pk_from_pubkey(network, &b).ok());
            ApiMinerStat {
                pk,
                address,
                count,
                last_height,
            }
        })
        .collect();
    miners.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last_height.cmp(&a.last_height))
    });
    Json(ApiMinerStats {
        tip_height,
        window,
        blocks,
        miners,
    })
    .into_response()
}
```

4. Mount it in the compat arm. At the TOP of the `Some(c) =>` arm (line ~946, before the `let scala: Router = …` that later consumes `c` via `.with_state(c)` at line ~1094), insert:

```rust
            // Native miner-stats rides the same chain-reader handle as the
            // Scala-compat routes but also needs the address-prefix byte,
            // so it mounts as its own mini router with a tuple state.
            let miner_stats_routes: Router = Router::new()
                .route("/api/v1/mining/minerStats", get(miner_stats_handler))
                .with_state((c.clone(), network));
```

Then change the merge line (~line 1095) from:

```rust
            let with_compat = operator.merge(scala);
```

to:

```rust
            let with_compat = operator.merge(scala).merge(miner_stats_routes);
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p ergo-api --test miner_stats_route 2>&1 | tail -5`
Expected: PASS (6 tests).

- [ ] **Step 6: Register with OpenAPI + regenerate the snapshot**

In the `NativeOpenApi` derive (server.rs:1377-1535):
- `paths(…)`: add `miner_stats_handler,` after `difficulty_history_handler,`.
- `components(schemas(…))`: add `ApiMinerStat, ApiMinerStats,` after `ApiDifficultySeries,`.
- In the `info(description = …)` text, the conditional-routes list mentions `/api/v1/difficulty/history` — add `` `/api/v1/mining/minerStats` `` to that same list.

Run: `cargo test -p ergo-api openapi_native_snapshot -- --ignored --nocapture regenerate`
Then: `cargo test -p ergo-api 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(api): GET /api/v1/mining/minerStats — network mining landscape

Folds the last N canonical headers (default 720, clamp [1,16384]) by
Autolykos solution pk, deriving each miner's P2PK address server-side.
Rides the chain-reader handle like difficulty/history; tuple state adds
the network prefix.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: UI — `miners.js` module + api-client methods + static registration

**Files:**
- Create: `ergo-api/web/js/miners.js`
- Modify: `ergo-api/web/js/api-client.js` (3 new methods in the `api` object)
- Modify: `ergo-api/src/web.rs` (one const)
- Modify: `ergo-api/src/server.rs` (one route + import)

- [ ] **Step 1: Create `ergo-api/web/js/miners.js`**

```js
// Miner attribution helpers shared by explorer / overview / mining views:
// pk → P2PK address resolution (server-side /utils/rawToAddress, session-
// cached), curated pool labels, own-node pk detection ("you" badge), and
// the standard miner DOM cell.
//
// POOL_LABELS is keyed by the P2PK address DERIVED FROM powSolutions.pk —
// the exact string the server emits as `miner_address` and that
// /utils/rawToAddress returns. It is NOT the pool's long P2S payout
// address ("88dhg…"): each pool's mining pk was extracted from its
// reward-script payout address in the public explorer address book
// (marker 0x08cd + 33 bytes) and re-encoded as P2PK. Seeded 2026-07-05,
// verified against the last 720 mainnet blocks (~93% labeled). Curated
// by hand — refresh when pools rotate keys.
import { getJson } from './api-client.js';
import { truncMiddle } from './format.js';

const POOL_LABELS = new Map([
  ['9fQYeMEXvSfmL2iUfsDDJ88SVtuPuvTZiB5aR19nKeCKSACVmgx', '2Miners'],
  ['9gLHUWsNSjEi957E23ChviPKGnD76DoMuNg5ykjrvrvTBZTo5qv', 'HeroMiners'],
  ['9giun3ba4ZnPvxYdXpk89XvwWkmWqJNQpGxgTRz932PajDPjE2z', 'HeroMiners'],
  ['9eZ8u92tKiXZrojwjsHcdkPgQEDhpRSfcUZ2LnGrBe7qtyeUNJ8', 'WoolyPooly'],
  ['9ff7YXNuQtZ5v9PSgkfft6J1vpnqTvsWZ9J81W6To5EdBxqmVNF', 'Nanopool'],
  ['9gsbKAia1ARpA2zyotMzrWnJvmfuqcPemue5pfbm87Mnt5h1Tmm', 'Kryptex'],
  ['9gqURqNpyUdNXBDH6t9p8cYrhQvzz8UEPsyoPyZNhTi8J2QB4Le', 'K1 Pool'],
  ['9h6oo1SLQKs38niWiXDwL9D9gbdQ3P9rmL7x9uGwbJqLrCvqe4S', '666 Pool'],
  ['9hFPAU1x1NRsuCjUZmCCyptvosTxYbe5uDvPV7t2BjwbzbS1dH3', 'DX Pool'],
  ['9fu1mLunnUUYEdJSXRUu1KZDJyJZV4gajd1uEFMEBsCWLEAJENo', 'DX Pool'],
  ['9fr915vPsMmf8UxLEvkLJfbq1Tf9BGGVvZYVm2h27MCCnp3xdZT', 'JJ Pool'],
  ['9grr1mjq8jqczDTD9PgDFmApQ9ifcV5zmBUdsgs6ynRBiC1x4im', 'Magic Pool'],
  ['9fTtqcMuSfURB658n68UhKwDVwW3FkepR3pJQ2eNde6uxM66G97', 'Solo Pool'],
  ['9eg5XhXFJNKSe1un72XB1G2ZQzYeqTAvcG8Q4MekV9J2xXh9SWj', 'Sigmanauts'],
  ['9ennYNGuHYz2C6JagPuFFMY17UHT6WMfzkKhDj3swDim7UE65VN', 'Sigmanauts'],
  ['9gbzYdhsZSv8SgsGRNu8apNgFeNRBjYgfqjBTiDKPbm4WchmZN2', 'Sigmanauts'],
]);

export function poolLabel(address) {
  return (address && POOL_LABELS.get(address)) || null;
}

// pk (hex) → P2PK address via GET /utils/rawToAddress. Only successes are
// cached, so a transient failure retries on the next view (the tokenMeta
// discipline from explorer.js).
const pkAddr = new Map();
export async function pkToAddress(pk) {
  if (!pk) return null;
  if (pkAddr.has(pk)) return pkAddr.get(pk);
  const got = await getJson(`/utils/rawToAddress/${pk}`);
  if (got?.address) {
    pkAddr.set(pk, got.address);
    return got.address;
  }
  return null;
}

// Own-node mining pk (what external miners mine to). /mining/* routes 404
// on non-mining nodes — probed once per session, null when absent.
let ownPk; // undefined = not probed yet; null = probed, none
let ownPkInflight = null;
export function ownPkHex() {
  return ownPk || null;
}
export function isOwnPk(pk) {
  return !!pk && !!ownPk && pk === ownPk;
}
export async function fetchOwnPk() {
  if (ownPk !== undefined) return ownPkHex();
  if (!ownPkInflight) {
    ownPkInflight = getJson('/mining/rewardPublicKey').then((r) => {
      ownPk = r?.rewardPubkey || null;
      return ownPk;
    });
  }
  await ownPkInflight;
  return ownPkHex();
}

// Standard miner cell: pool label (title = full address) or truncated
// address, linked into the explorer address view, plus the "you" pill
// when the pk is this node's own. `—` when the address is unknown.
export function minerNode(address, pk, opts = {}) {
  const w = document.createElement('span');
  w.className = 'mn-cell';
  if (!address) {
    w.textContent = '—';
    return w;
  }
  const a = document.createElement('a');
  a.className = 'ex-link';
  a.href = `#explorer/address/${address}`;
  const lbl = poolLabel(address);
  a.textContent = lbl || truncMiddle(address, opts.head ?? 8, opts.tail ?? 6);
  if (lbl) a.title = address;
  w.append(a);
  if (isOwnPk(pk)) {
    const you = document.createElement('span');
    you.className = 'pill pill--ok';
    you.textContent = 'you';
    w.append(document.createTextNode(' '), you);
  }
  return w;
}
```

- [ ] **Step 2: Add the api-client methods**

In `ergo-api/web/js/api-client.js`, right after the `miningRewardAddress` line (line ~100):

```js
  miningRewardPublicKey: () => getJson('/mining/rewardPublicKey'),
  // Network mining landscape: last-`window` headers folded by miner pk,
  // addresses derived server-side. Rides the chain reader (404 = old node).
  minerStats: (window = 720) => getJson(`/api/v1/mining/minerStats?window=${window}`),
  // Emission schedule facts at a height ({minerReward, reemitted, …} nanoERG).
  emissionAt: (height) => getJson(`/emission/at/${height}`),
```

- [ ] **Step 3: Register the file server-side**

`ergo-api/src/web.rs` — after the `JS_WALLET` const:

```rust
pub const JS_MINERS: &str = include_str!("../web/js/miners.js");
```

`ergo-api/src/server.rs` — add `JS_MINERS` to the `use crate::web::{…}` import (line ~91) and add after the `/js/wallet.js` route (line ~569):

```rust
        .route("/js/miners.js", get(|| async { js(JS_MINERS) }))
```

- [ ] **Step 4: Verify**

Run: `node --check ergo-api/web/js/miners.js && node --check ergo-api/web/js/api-client.js`
Expected: no output (both parse).
Run: `cargo check -p ergo-api 2>&1 | tail -3`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ui): miners.js — pool labels, pk→address cache, own-pk badge helpers

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: UI — explorer block detail miner row + home table miner column

**Files:**
- Modify: `ergo-api/web/js/explorer.js` (imports ~line 23, renderHome ~line 439, renderBlock ~line 527)

- [ ] **Step 1: Import the helpers**

After the format.js import (line ~23):

```js
import { minerNode, pkToAddress, fetchOwnPk } from './miners.js';
```

- [ ] **Step 2: Block detail — add the resolved "miner" row**

In `renderBlock`, the kv grid currently has (line ~527):

```js
  kvRow(grid, 'miner pk', h.powSolutions?.pk ? hashNode(h.powSolutions.pk) : '—');
```

Insert ABOVE that line:

```js
  // Resolved miner identity: pk → P2PK address via the server (cached),
  // pool label when known, "you" pill on own blocks. Renders the raw pk
  // as a placeholder and upgrades in place when the lookup lands; a
  // failed lookup just leaves the pk — same info as before this row.
  const minerVal = el('span');
  const minerPk = h.powSolutions?.pk;
  if (minerPk) {
    minerVal.textContent = truncMiddle(minerPk, 10, 8);
    fetchOwnPk().then(() =>
      pkToAddress(minerPk).then((addr) => {
        if (mySeq !== seq || !addr) return;
        minerVal.replaceChildren(minerNode(addr, minerPk, { head: 12, tail: 10 }));
      }),
    );
  } else {
    minerVal.textContent = '—';
  }
  kvRow(grid, 'miner', minerVal);
```

- [ ] **Step 3: Home table — add the Miner column**

In `renderHome`, change the recent-blocks await (line ~446) to also warm the own-pk probe so first paint can badge:

```js
  const [recent] = await Promise.all([api.recentBlocks(32), fetchOwnPk()]);
```

In the `makeTable` column array, insert between the `size` and `id` columns:

```js
      {
        key: 'miner',
        label: 'Miner',
        width: 130,
        render: (b) => minerNode(b.miner_address, b.miner_pk),
        sort: (b) => poolLabel(b.miner_address) || b.miner_address || '',
      },
```

and extend the miners.js import with `poolLabel`:

```js
import { minerNode, pkToAddress, fetchOwnPk, poolLabel } from './miners.js';
```

(Blocks served by an old node have no `miner_address` → the cell renders `—`; no fetch fan-out on list surfaces by design.)

- [ ] **Step 4: Verify + commit**

Run: `node --check ergo-api/web/js/explorer.js` — expected: clean.

```bash
git add -A && git commit -m "feat(ui): explorer miner attribution — resolved miner row + home Miner column

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: UI — overview: mini-list miner, mining panel enrichment, disabled stub

**Files:**
- Modify: `ergo-api/web/js/overview.js` (imports; onSlow ~line 220; chain-tip list ~line 500; mining panel ~line 520)

- [ ] **Step 1: Imports + own-pk warm**

Add to overview.js imports:

```js
import { minerNode, fetchOwnPk, ownPkHex } from './miners.js';
```

In `mount()` (wherever the section builds its DOM — find `export function mount`), add one line at the end: `fetchOwnPk();` (probed once; 404 on non-mining nodes caches null).

- [ ] **Step 2: onSlow — tip-keyed minerStats + emission fetches (mining nodes only)**

Inside `onSlow()` after the `state.miningCandidate` update block (line ~260), add:

```js
  // Mining-panel enrichment (mining nodes only): refetch the 720-block
  // miner fold + emission facts once per full-block tip advance — a 4s
  // cadence would hammer a 720-header fold for data that only changes
  // per block (same discipline as refreshChartData).
  if (miningOn) {
    const mtip = tip?.best_full_block?.height ?? 0;
    if (mtip && mtip !== state.minerStatsAt) {
      state.minerStatsAt = mtip;
      api.minerStats(720).then((s) => {
        if (s) state.minerStats = s;
      });
      api.emissionAt(mtip).then((e) => {
        if (e) state.emission = e;
      });
    }
  }
```

- [ ] **Step 3: Chain-tip mini-list — append the miner**

In the mini-list row builder (line ~509), after `m.textContent = …`, add:

```js
        if (b.miner_address) {
          m.append(document.createTextNode(' · '), minerNode(b.miner_address, b.miner_pk, { head: 4, tail: 4 }));
        }
```

and change the `m` assignment from `m.textContent = \`…\`` — it stays as-is (textContent first, then append). No other change to the row.

- [ ] **Step 4: Mining panel — enrich + disabled stub + section link**

The panel block (line ~520) is `if (state.identity?.mining) { … duo.append(p); }`. Three edits:

1. After the `state.miningReward` block (the reward-address rows, ends ~line 560), still inside the `if`, add:

```js
    if (state.emission) {
      const base = Number(state.emission.minerReward) / 1e9;
      const re = Number(state.emission.reemitted || 0) / 1e9;
      body.append(kv('block reward', re ? `${base} + ${re} ERG` : `${base} ERG`, 'var(--tx2)'));
    }
    if (state.minerStats && ownPkHex()) {
      const mine = state.minerStats.miners.find((mm) => mm.pk === ownPkHex());
      body.append(
        kv(`your blocks · last ${num(state.minerStats.blocks)}`, String(mine?.count || 0), 'var(--tx2)'),
      );
    }
    const mfoot = document.createElement('div');
    mfoot.className = 'ov-foot';
    const mlink = document.createElement('a');
    mlink.className = 'ex-link';
    mlink.href = '#mining';
    mlink.textContent = 'Mining section →';
    mfoot.append(mlink);
    body.append(mfoot);
```

2. Add an `else if` branch after the `if (state.identity?.mining) { … }` block so a non-mining node shows a one-line stub instead of nothing (zero mining fetches — it renders from `state.identity` alone):

```js
  } else if (state.identity && !state.identity.mining) {
    const { panel: p, body } = panel('Mining');
    body.append(kv('mining', 'disabled', 'var(--tx3)'));
    const mfoot = document.createElement('div');
    mfoot.className = 'ov-foot';
    const mlink = document.createElement('a');
    mlink.className = 'ex-link';
    mlink.href = '#mining';
    mlink.textContent = 'Mining section →';
    mfoot.append(mlink);
    body.append(mfoot);
    duo.append(p);
  }
```

(Check how the existing block closes: the `if` ends with `duo.append(p); }` — attach the `else if` to that closing brace. The `.ov-duo--solo` single-child toggle, if present just below, now fires only when identity is still unknown — verify it still reads `duo.childElementCount`.)

- [ ] **Step 5: Verify + commit**

Run: `node --check ergo-api/web/js/overview.js` — expected: clean.

```bash
git add -A && git commit -m "feat(ui): overview miner attribution + mining panel enrichment/disabled stub

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: UI — dedicated Mining section

**Files:**
- Create: `ergo-api/web/js/mining.js`
- Modify: `ergo-api/web/index.html` (nav link + section element)
- Modify: `ergo-api/web/js/app.js` (import, SECTIONS, renderers)
- Modify: `ergo-api/src/web.rs` + `ergo-api/src/server.rs` (static registration)
- Modify: `ergo-api/web/dashboard.css` (small class set)

- [ ] **Step 1: Create `ergo-api/web/js/mining.js`**

```js
// Mining section: this node's mining state + the network mining landscape.
// Always visible — the network panels are meaningful on any node; the
// "Your node" panel shows an explicit disabled state when identity.mining
// is false. Heavy series (minerStats / emission / difficulty window /
// recent blocks) refetch only when the full-block tip advances.
import { api } from './api-client.js';
import { makeTable } from './table.js';
import { erg, num, bytes, dur, truncMiddle } from './format.js';
import { minerNode, poolLabel, fetchOwnPk, ownPkHex } from './miners.js';

const EPOCH = 128; // EIP-37 difficulty-adjustment period (blocks)

let root = null;
let els = null;
let recentTable = null;
let identity = null;
let candidate = null;
let candidateSeq = null;
let candidateSeqAt = null;
let rewardAddr = null;
let info = null;
let tip = null;
let stats = null; // minerStats for the selected window
let emission = null;
let diffPoints = null; // difficultyHistory over the current epoch window
let recentRows = [];
let lastFetchTip = 0;
let distWindow = 720;

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// Label/value row (overview's .ov-kv vocabulary). `value` may be a Node.
function kvNode(label, value, color) {
  const r = el('div', 'ov-kv');
  const l = el('span', null, label);
  const v = el('span');
  if (value instanceof Node) v.append(value);
  else v.textContent = value == null ? '—' : String(value);
  if (color) v.style.color = color;
  r.append(l, v);
  return r;
}

function hashrate(h) {
  if (!Number.isFinite(h) || h <= 0) return '—';
  const u = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
  let i = 0;
  let v = h;
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(2)} ${u[i]}`;
}

export function mount(elRoot) {
  root = elRoot;
  root.innerHTML = `
    <div class="pg-head">
      <div>
        <h1 class="pg-title">Mining</h1>
        <span class="pg-count micro-label" data-sub></span>
      </div>
    </div>
    <div class="mn-grid">
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Your node</h2></div>
        <div class="panel__body" data-you></div>
      </section>
      <section class="panel">
        <div class="panel__head"><h2 class="panel__title">Network</h2></div>
        <div class="panel__body" data-net></div>
      </section>
      <section class="panel mn-full">
        <div class="panel__head">
          <h2 class="panel__title">Miner distribution</h2>
          <span class="mn-win" data-win></span>
        </div>
        <div class="panel__body" data-dist></div>
      </section>
      <section class="panel mn-full">
        <div class="panel__head"><h2 class="panel__title">Recent blocks</h2></div>
        <div class="panel__body" data-recent></div>
      </section>
    </div>`;
  els = {
    sub: root.querySelector('[data-sub]'),
    you: root.querySelector('[data-you]'),
    net: root.querySelector('[data-net]'),
    win: root.querySelector('[data-win]'),
    dist: root.querySelector('[data-dist]'),
    recent: root.querySelector('[data-recent]'),
  };
  for (const w of [128, 720]) {
    const b = el('button', 'btn', String(w));
    b.type = 'button';
    b.setAttribute('aria-pressed', String(w === distWindow));
    b.onclick = () => {
      if (distWindow === w) return;
      distWindow = w;
      for (const x of els.win.children) x.setAttribute('aria-pressed', String(x.textContent === String(w)));
      refetchStats();
    };
    els.win.append(b);
  }
  recentTable = makeTable(
    els.recent,
    [
      { key: 'height', label: 'Height', width: 90, render: (b) => heightLink(b), sort: (b) => b.height },
      { key: 'age', label: 'Age', width: 80, align: 'right', render: (b) => dur(Math.max(0, Math.floor((Date.now() - b.ts_unix_ms) / 1000))), sort: (b) => -b.ts_unix_ms },
      { key: 'txs', label: 'Txs', width: 60, align: 'right', sort: (b) => b.txs },
      { key: 'size', label: 'Size', width: 80, align: 'right', render: (b) => bytes(b.size_bytes), sort: (b) => b.size_bytes },
      { key: 'miner', label: 'Miner', width: 150, render: (b) => minerNode(b.miner_address, b.miner_pk), sort: (b) => poolLabel(b.miner_address) || b.miner_address || '' },
      { key: 'id', label: 'Block ID', render: (b) => idLink(b), sort: (b) => b.header_id },
    ],
    { rowKey: (b) => b.header_id, initialSort: { key: 'height', dir: -1 } },
  );
  fetchOwnPk();
}

function heightLink(b) {
  const a = el('a', 'ex-link', num(b.height));
  a.href = `#explorer/block/${b.header_id}`;
  return a;
}
function idLink(b) {
  const a = el('a', 'ex-link', truncMiddle(b.header_id, 8, 8));
  a.href = `#explorer/block/${b.header_id}`;
  return a;
}

async function refetchStats() {
  const s = await api.minerStats(distWindow);
  if (s) {
    stats = s;
    render();
  }
}

export async function onSlow() {
  if (!identity) identity = await api.identity();
  const miningOn = !!identity?.mining;
  const [tipNow, infoNow, cand, rew] = await Promise.all([
    api.tip(),
    info ? null : api.info(),
    miningOn ? api.miningCandidate() : null,
    miningOn && !rewardAddr ? api.miningRewardAddress() : null,
  ]);
  if (tipNow) tip = tipNow;
  if (infoNow) info = infoNow;
  if (rew?.rewardAddress) rewardAddr = rew.rewardAddress;
  if (cand) {
    if (candidateSeq !== cand.template_seq) {
      candidateSeq = cand.template_seq;
      candidateSeqAt = Date.now();
    }
    candidate = cand;
  } else if (miningOn) {
    candidate = null; // 503 window: show the honest no-work state
  }

  const tipH = tip?.best_full_block?.height ?? 0;
  if (tipH && tipH !== lastFetchTip) {
    lastFetchTip = tipH;
    // Per-tip refetch: the fold, emission facts, the current epoch's
    // header timestamps (retarget estimate), and the block list.
    const epochLen = Math.max(2, (tipH % EPOCH) + 1);
    const [s, em, ds, recent] = await Promise.all([
      api.minerStats(distWindow),
      api.emissionAt(tipH),
      api.difficultyHistory(epochLen),
      api.recentBlocks(32),
    ]);
    if (s) stats = s;
    if (em) emission = em;
    if (ds?.points) diffPoints = ds.points;
    if (Array.isArray(recent)) recentRows = recent;
  }
  render();
}

function render() {
  if (!els) return;
  els.sub.textContent = stats
    ? `${stats.miners.length} miners · last ${num(stats.blocks)} blocks`
    : '';

  // ---- Your node ----
  els.you.replaceChildren();
  if (!identity) {
    els.you.append(el('div', 'micro-label', 'loading…'));
  } else if (!identity.mining) {
    els.you.append(kvNode('mining', 'disabled', 'var(--tx3)'));
    els.you.append(
      el(
        'div',
        'micro-label',
        'This node does not serve mining work. Enable mining in the node config (mining = true) to hand out candidates to external miners.',
      ),
    );
  } else {
    els.you.append(kvNode('mining', 'enabled', 'var(--green)'));
    if (candidate) {
      els.you.append(kvNode('work height', num(candidate.h), 'var(--tx2)'));
      if (candidateSeqAt) {
        els.you.append(
          kvNode(
            `template #${num(candidate.template_seq)}`,
            `refreshed ${dur(Math.max(0, Math.floor((Date.now() - candidateSeqAt) / 1000)))} ago`,
            'var(--tx2)',
          ),
        );
      }
      if (candidate.pk) els.you.append(kvNode('miner pk', truncMiddle(candidate.pk, 10, 8), 'var(--tx3)'));
    } else {
      els.you.append(kvNode('work', 'no candidate available (node syncing?)', 'var(--yellow)'));
    }
    if (rewardAddr) {
      const a = el('a', 'ex-link', truncMiddle(rewardAddr, 10, 6));
      a.href = `#explorer/address/${rewardAddr}`;
      els.you.append(kvNode('reward address', a));
    }
    if (stats && ownPkHex()) {
      const mine = stats.miners.find((m) => m.pk === ownPkHex());
      els.you.append(kvNode(`your blocks · last ${num(stats.blocks)}`, String(mine?.count || 0), 'var(--tx2)'));
    }
    const foot = el('div', 'ov-foot');
    const wl = el('a', 'ex-link', 'matured rewards → Wallet');
    wl.href = '#wallet';
    foot.append(wl);
    els.you.append(foot);
  }

  // ---- Network ----
  els.net.replaceChildren();
  const diffStr = tip?.best_header?.difficulty;
  els.net.append(kvNode('difficulty', diffStr ?? '—'));
  const tgtS = Math.max(1, (info?.target_block_interval_ms ?? 120000) / 1000);
  if (diffStr != null) {
    // Approximate parse is fine at display precision (chart.js precedent);
    // the verbatim string is shown one row above.
    els.net.append(kvNode('est. network hashrate', hashrate(Number(diffStr) / tgtS)));
  }
  const tipH = tip?.best_full_block?.height ?? 0;
  if (tipH) {
    const toGo = EPOCH - (tipH % EPOCH);
    let est = '';
    if (diffPoints && diffPoints.length >= 2) {
      const n = diffPoints.length;
      const spanS = (diffPoints[n - 1].timestamp_unix_ms - diffPoints[0].timestamp_unix_ms) / 1000;
      const avg = spanS / (n - 1);
      if (avg > 0) {
        const pct = Math.max(-67, Math.min(200, (tgtS / avg - 1) * 100));
        est = ` · est. ${pct >= 0 ? '+' : ''}${pct.toFixed(1)}%`;
      }
    }
    els.net.append(kvNode('next retarget', `${num(toGo)} blocks (~${dur(Math.round(toGo * tgtS))})${est}`));
  }
  if (emission) {
    const base = Number(emission.minerReward) / 1e9;
    const re = Number(emission.reemitted || 0) / 1e9;
    els.net.append(kvNode('block reward', re ? `${base} + ${re} ERG (re-emission)` : `${base} ERG`, 'var(--tx2)'));
    const issued = Number(emission.totalCoinsIssued);
    const remain = Number(emission.totalRemainCoins);
    if (issued > 0) {
      els.net.append(
        kvNode('supply issued', `${erg(emission.totalCoinsIssued)} ERG · ${((100 * issued) / (issued + remain)).toFixed(2)}%`),
      );
    }
  }

  // ---- Miner distribution ----
  els.dist.replaceChildren();
  if (!stats?.miners?.length) {
    els.dist.append(el('div', 'micro-label', 'no data yet'));
  } else {
    const total = stats.blocks || stats.miners.reduce((a, m) => a + m.count, 0);
    for (const m of stats.miners) {
      const row = el('div', 'mn-row');
      const label = el('span', 'mn-row__label');
      label.append(minerNode(m.address, m.pk, { head: 8, tail: 6 }));
      const bar = el('div', 'mn-bar');
      const fill = el('div', 'mn-bar__fill');
      const pct = total ? (100 * m.count) / total : 0;
      fill.style.width = `${Math.max(1, pct)}%`;
      bar.append(fill);
      row.append(label, bar, el('span', 'mn-row__count', `${num(m.count)} · ${pct.toFixed(1)}%`));
      els.dist.append(row);
    }
  }

  // ---- Recent blocks ----
  recentTable.update(recentRows);
}
```

- [ ] **Step 2: Wire the section into the shell**

`ergo-api/web/index.html` — insert the nav link after the Mempool link:

```html
      <a class="side__link" href="#mining" data-section="mining"><span class="side__glyph" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 20.5 12 13"/><path d="M9 4.5C12.5 3 17 3.7 19.5 6.2 17 6 13.6 6.6 11.2 9c-2.4 2.4-3 5.8-2.8 8.3C5.9 14.8 5.2 10.3 6.7 6.8"/></svg></span>Mining</a>
```

and the section element after `section-mempool` in `<main>`:

```html
    <section id="section-mining" class="section" aria-label="Mining" hidden></section>
```

`ergo-api/web/js/app.js` — add the import after the mempool import:

```js
import * as mining from './mining.js';
```

and update both registries:

```js
const SECTIONS = ['overview', 'explorer', 'peers', 'mempool', 'mining', 'voting', 'wallet'];
const renderers = { overview, explorer, peers, mempool, mining, voting, wallet };
```

`ergo-api/src/web.rs` — after `JS_MINERS`:

```rust
pub const JS_MINING: &str = include_str!("../web/js/mining.js");
```

`ergo-api/src/server.rs` — add `JS_MINING` to the web import and after the miners.js route:

```rust
        .route("/js/mining.js", get(|| async { js(JS_MINING) }))
```

- [ ] **Step 3: CSS**

Append to `ergo-api/web/dashboard.css`:

```css
/* ---- Mining section ---- */
.mn-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
  align-items: start;
}
.mn-grid > .panel { min-width: 0; }
.mn-full { grid-column: 1 / -1; }
@media (max-width: 900px) {
  .mn-grid { grid-template-columns: 1fr; }
}
.mn-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 3px 0;
}
.mn-row__label {
  flex: 0 0 180px;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mn-row__count {
  flex: 0 0 110px;
  text-align: right;
  color: var(--tx2);
}
.mn-bar {
  flex: 1 1 auto;
  height: 8px;
  border-radius: 4px;
  background: rgba(127, 127, 127, 0.18);
  overflow: hidden;
}
.mn-bar__fill {
  height: 100%;
  background: var(--accent, #4a9eff);
}
.mn-win { display: inline-flex; gap: 4px; }
.mn-win .btn { padding: 2px 10px; }
.mn-win .btn[aria-pressed='true'] { color: var(--accent, #4a9eff); }
.mn-cell .pill { margin-left: 4px; }
```

(Token check while editing: confirm `--accent` and `--tx2/--tx3` exist in `tokens.css`; if the accent token has a different name there, use that name.)

- [ ] **Step 4: Verify + commit**

Run: `node --check ergo-api/web/js/mining.js && node --check ergo-api/web/js/app.js`
Run: `cargo check -p ergo-api 2>&1 | tail -3`
Expected: all clean.

```bash
git add -A && git commit -m "feat(ui): dedicated Mining section — own-node state, network landscape, miner distribution

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Full workspace gate

- [ ] **Step 1: Run the complete gate (never `-p` subsets here)**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Expected: all green. If fmt fails, run `cargo fmt --all` and re-check. If clippy flags the new code, fix and re-run (do not `allow`-suppress without a reason worth a comment).

- [ ] **Step 2: Commit any fixes**

```bash
git add -A && git commit -m "chore: gate fixes (fmt/clippy)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

(Skip the commit if the tree is clean.)

---

### Task 8: Live verification against 9063 (devproxy + headless screenshots)

The deployed 9063 binary does NOT have the new endpoint/fields, which lets us verify BOTH paths: graceful degradation (plain proxy) and the full feature (enriching proxy that computes the new payloads from 9063's real data — the same trick as #152's devproxy-events.py).

- [ ] **Step 1: Write the enriching devproxy**

Create `/tmp/ui-shots/devproxy-miner.py`:

```python
#!/usr/bin/env python3
"""Serve the working-tree web/ on :8999; proxy the rest to the node.
Enrichment (unless PLAIN=1): synthesizes the NEW API surface from the
old node's real data so the UI can be verified before deploying:
  - /api/v1/blocks/recent        += miner_pk, miner_address
  - /api/v1/mining/minerStats     computed from /blocks/lastHeaders
MOCK_MINING_OFF=1 rewrites /api/v1/identity mining:false (disabled-state
screenshots)."""
import http.server, socketserver, json, os, sys, urllib.request, urllib.error

WEB = sys.argv[1] if len(sys.argv) > 1 else '.'
UP = sys.argv[2] if len(sys.argv) > 2 else 'http://127.0.0.1:9063'
PLAIN = os.environ.get('PLAIN') == '1'
MOCK_OFF = os.environ.get('MOCK_MINING_OFF') == '1'
addr_cache = {}

def up_json(path):
    with urllib.request.urlopen(UP + path, timeout=30) as r:
        return json.load(r)

def pk_to_addr(pk):
    if pk not in addr_cache:
        try:
            addr_cache[pk] = up_json(f'/utils/rawToAddress/{pk}')['address']
        except Exception:
            addr_cache[pk] = None
    return addr_cache[pk]

class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=WEB, **k)

    def send_json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.send_header('content-length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split('?')[0]
        if p == '/' or p.startswith(('/js/', '/fonts/')) or p.endswith(('.css', '.html')):
            if p == '/':
                self.path = '/index.html'
            return super().do_GET()
        try:
            if not PLAIN and p == '/api/v1/blocks/recent':
                blocks = up_json(self.path)
                for b in blocks:
                    hdr = up_json(f"/blocks/{b['header_id']}/header")
                    pk = hdr.get('powSolutions', {}).get('pk')
                    if pk:
                        b['miner_pk'] = pk
                        a = pk_to_addr(pk)
                        if a:
                            b['miner_address'] = a
                return self.send_json(blocks)
            if not PLAIN and p == '/api/v1/mining/minerStats':
                q = self.path.split('?')
                window = 720
                if len(q) > 1 and 'window=' in q[1]:
                    try:
                        window = max(1, min(16384, int(q[1].split('window=')[1].split('&')[0])))
                    except ValueError:
                        pass
                hdrs = up_json(f'/blocks/lastHeaders/{window}')
                agg = {}
                for h in hdrs:
                    pk = h['powSolutions']['pk']
                    c, lh = agg.get(pk, (0, 0))
                    agg[pk] = (c + 1, max(lh, h['height']))
                miners = [
                    {'pk': pk, 'address': pk_to_addr(pk), 'count': c, 'last_height': lh}
                    for pk, (c, lh) in agg.items()
                ]
                miners.sort(key=lambda m: (-m['count'], -m['last_height']))
                return self.send_json({
                    'tip_height': hdrs[-1]['height'] if hdrs else 0,
                    'window': window,
                    'blocks': len(hdrs),
                    'miners': miners,
                })
            if MOCK_OFF and p == '/api/v1/identity':
                ident = up_json(self.path)
                ident['mining'] = False
                return self.send_json(ident)
            if MOCK_OFF and p.startswith('/mining/'):
                return self.send_json({'error': 404, 'reason': 'not-found'}, 404)
            # passthrough
            req = urllib.request.Request(UP + self.path)
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                self.send_response(r.status)
                self.send_header('content-type', r.headers.get('content-type', 'application/json'))
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header('content-type', e.headers.get('content-type', 'application/json'))
            self.send_header('content-length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            try:
                self.send_error(502)
            except Exception:
                pass

    def do_POST(self):
        ln = int(self.headers.get('content-length') or 0)
        body = self.rfile.read(ln) if ln else None
        try:
            req = urllib.request.Request(UP + self.path, data=body, method='POST')
            if self.headers.get('content-type'):
                req.add_header('content-type', self.headers['content-type'])
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                self.send_response(r.status)
                self.send_header('content-type', r.headers.get('content-type', 'application/json'))
                self.send_header('content-length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header('content-type', e.headers.get('content-type', 'application/json'))
            self.send_header('content-length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            try:
                self.send_error(502)
            except Exception:
                pass

socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(('127.0.0.1', 8999), H) as s:
    mode = 'PLAIN' if PLAIN else 'ENRICHED'
    print(f'{mode} serving {WEB} on http://127.0.0.1:8999 -> {UP}')
    s.serve_forever()
```

(`/tmp` is a quota'd tmpfs — keep only scripts and screenshots there, no build artifacts.)

- [ ] **Step 2: Screenshot the enriched (full-feature) path**

```bash
mkdir -p /tmp/ui-shots/miner
cd /tmp/ui-shots && python3 devproxy-miner.py \
  /home/rkadias/coding/development/arkadianet/ergo/.claude/worktrees/ui-miner-attribution/ergo-api/web &
sleep 1
for view in "explorer" "mining" "" ; do
  chromium-browser --headless --screenshot=/tmp/ui-shots/miner/${view:-overview}.png \
    --window-size=1440,1400 --virtual-time-budget=12000 \
    "http://127.0.0.1:8999/#${view}" 2>/dev/null
done
# Block detail (uses only OLD endpoints — full end-to-end truth):
TIP=$(curl -s http://127.0.0.1:9063/info | python3 -c "import json,sys;print(json.load(sys.stdin)['bestFullHeaderId'])")
chromium-browser --headless --screenshot=/tmp/ui-shots/miner/block.png \
  --window-size=1440,1400 --virtual-time-budget=12000 \
  "http://127.0.0.1:8999/#explorer/block/$TIP" 2>/dev/null
```

Inspect each PNG (Read tool). Confirm:
- `block.png`: a "miner" row shows a pool label (or address) linked, above the "miner pk" row.
- `explorer.png`: the Recent-blocks table has a Miner column with mostly pool labels (2Miners/HeroMiners dominate mainnet).
- `mining.png`: all four panels populated — Your node (mining enabled, work height, reward address), Network (difficulty, hashrate, retarget countdown, block reward "3 + 9 ERG"), Miner distribution bars summing sensibly, Recent blocks with miners.
- `overview.png`: chain-tip mini-list rows end with miner labels; Mining panel shows block reward + "your blocks · last 720" + "Mining section →" link.

- [ ] **Step 3: Screenshot degrade + disabled states**

```bash
kill %1
PLAIN=1 python3 /tmp/ui-shots/devproxy-miner.py \
  /home/rkadias/coding/development/arkadianet/ergo/.claude/worktrees/ui-miner-attribution/ergo-api/web &
sleep 1
chromium-browser --headless --screenshot=/tmp/ui-shots/miner/explorer-degrade.png \
  --window-size=1440,1400 --virtual-time-budget=12000 "http://127.0.0.1:8999/#explorer" 2>/dev/null
kill %1
MOCK_MINING_OFF=1 python3 /tmp/ui-shots/devproxy-miner.py \
  /home/rkadias/coding/development/arkadianet/ergo/.claude/worktrees/ui-miner-attribution/ergo-api/web &
sleep 1
chromium-browser --headless --screenshot=/tmp/ui-shots/miner/mining-off.png \
  --window-size=1440,1400 --virtual-time-budget=12000 "http://127.0.0.1:8999/#mining" 2>/dev/null
chromium-browser --headless --screenshot=/tmp/ui-shots/miner/overview-off.png \
  --window-size=1440,1400 --virtual-time-budget=12000 "http://127.0.0.1:8999/" 2>/dev/null
kill %1
```

Confirm:
- `explorer-degrade.png`: Miner column renders `—` (no errors, no broken layout) — old-node compatibility.
- `mining-off.png`: Your node panel shows "mining disabled" + explainer; network panels still populated.
- `overview-off.png`: Mining panel is the one-line disabled stub with the section link (not absent).

Fix anything that looks wrong, re-screenshot, then commit fixes:

```bash
git add -A && git commit -m "fix(ui): visual polish from live verification

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

(Skip if no fixes were needed.)

---

### Task 9: Pre-PR review + PR

- [ ] **Step 1: codex review (BEFORE the PR — SANTA conformance)**

Run `codex review` against the branch diff (headless is slow, ~13 min — let it finish; a noisy stdin warning with exit 0 is normal). Address every blocking finding with the fix committed; note non-blocking ones for the PR description.

- [ ] **Step 2: Re-run the full gate after any codex fixes**

```bash
cargo fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all
```

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin feat/ui-miner-attribution
gh pr create --title "feat(ui): miner attribution + dedicated Mining section" --body "$(cat <<'EOF'
## Summary
- Every block surface now answers "who mined this": resolved P2PK address (pool label when known, curated 16-address map ≈93% of recent mainnet blocks) linked into the explorer, with a "you" pill on self-mined blocks
- `ApiRecentBlock` gains optional `miner_pk`/`miner_address` (derived at snapshot assembly; wire-compatible omission)
- New `GET /api/v1/mining/minerStats?window=N` — last-N-headers fold by miner pk, addresses derived server-side (rides the chain reader like difficulty/history)
- New always-visible **Mining** section: Your node (explicit disabled state), Network (difficulty, est. hashrate, EIP-37 retarget countdown + naive estimate, block reward incl. re-emission, supply issued), Miner distribution (128/720 window), Recent blocks
- Overview Mining panel enriched (block reward, your-blocks count, section link) and shows a disabled stub instead of vanishing on non-mining nodes

## Verification
- Unit/route tests incl. live-verified pk→address vector (2Miners)
- Full workspace gate green (fmt, clippy -D warnings, test --all); openapi snapshot regenerated
- Live-verified against 9063 via enriching devproxy: full path, old-node degrade path, mining-off states (screenshots in PR comments)

Design: docs/superpowers/specs/2026-07-05-ui-miner-attribution-design.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Attach the four key screenshots as a PR comment (`gh pr comment --body` with uploaded images, or reference paths for the user).

---

## Self-review checklist (done at authoring)

- **Spec coverage:** S1→Task 1, S2→Task 2, S3→Task 1 Step 3, U1→Task 3, U2→Task 4 Step 2, U3→Task 4 Step 3 + Task 5 Step 3, U4→Task 6, U5→Task 5 Step 4; error handling→each render path degrades (verified in Task 8 Step 3); testing→Tasks 1-2 (TDD), 7 (gate), 8 (live). No spec item unmapped.
- **Type consistency:** `miner_pk`/`miner_address` (snake_case wire keys, matching ApiRecentBlock's existing convention) read as `b.miner_pk`/`b.miner_address` in all JS; `ApiMinerStat.last_height` read as `m.last_height`; `minerStats` response keys `tip_height/window/blocks/miners` match `stats.blocks`/`stats.miners` usage; `rewardPubkey` (camelCase, Scala-parity route) read in `fetchOwnPk`.
- **Placeholders:** none — every step carries the actual code/commands.

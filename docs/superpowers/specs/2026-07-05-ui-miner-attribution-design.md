# Miner attribution + dedicated Mining section — design

**Date:** 2026-07-05 · **Branch:** `feat/ui-miner-attribution` (off main dcc81af) · **Status:** approved by user

## Goal

1. Show **who mined each block** everywhere blocks appear in the operator UI (explorer block
   detail, explorer home recent-blocks table, overview chain-tip mini-list), as a
   human-meaningful identity: known-pool label when available, P2PK address link otherwise,
   plus a "you" badge on blocks mined by this node.
2. Add a **dedicated Mining section** (new nav item, always visible) covering the node's own
   mining state and the network mining landscape.
3. **Enrich the overview Mining panel** in place and link it to the new section; show an
   explicit one-line disabled stub instead of hiding when `identity.mining` is false.

## Current state (verified 2026-07-05)

- Block detail (`ergo-api/web/js/explorer.js:527`) already renders `powSolutions.pk` as a raw
  truncated hex ("miner pk" row) — no address resolution, no link.
- Block lists use `GET /api/v1/blocks/recent` → `ApiRecentBlock`
  (`ergo-api/src/types.rs:665`) which carries no pk/miner field. Assembly happens in
  `ergo-node/src/node/snapshot_emit.rs` (`build_recent_blocks`, tip-keyed cache +
  `merge_delivered_by` serve-time overlay).
- `GET /utils/rawToAddress/:pubkey_hex` (`ergo-api/src/utils.rs:124`, ungated) converts a pk
  hex to a P2PK base58 address via `ergo_ser::address::encode_p2pk_from_pubkey`
  (network-prefix aware). Verified live on 9063: tip block pk → `9fQYeM…SACVmgx`.
- Mining panel exists (PR #153) inside `overview.js:520-562`, gated on `state.identity?.mining`
  — shows work height, template seq + refresh age, miner pk, reward address link.
- Native-endpoint precedent for header-window reads: the difficulty-history handler calls
  `chain.last_headers(blocks)` with `clamp(2, 16_384)` (`ergo-api/src/server.rs:1590-1605`);
  `last_headers` is `ergo-node/src/api_bridge/scala_compat.rs:259`.
- Client cache precedent: EIP-4 `tokenMeta` module Map + batched miss resolution
  (`explorer.js:128-177`).
- CSP `script-src 'self'` — no inline scripts; all enrichment from module code.

## Scope decisions (user)

- Attribution on **all three** block surfaces + **"you" badge**.
- **Curated pool labels**: small static map in the UI, address fallback, manual upkeep accepted.
- Mining UI: **both** enrich the overview panel in place **and** add a dedicated Mining
  section "covering as much from mining as possible".
- No other new sections this round; anything shipped must be fully completed. Epoch/retarget
  progress folds into the Mining section (mining-adjacent), soft-fork tracker and reorg
  history view are explicitly deferred.

## Approach

**Server-computed stats (Approach 1, approved).** Native endpoints are extended; Scala-parity
endpoints (`/blocks/*`, `/utils/*`) are not modified. No client-side crypto.

## Server changes (Rust)

### S1 — `ApiRecentBlock` gains miner fields

- `miner_pk: Option<String>` (33-byte compressed pk, hex) and
  `miner_address: Option<String>` (P2PK base58, network-prefix aware).
- Populated in `build_recent_blocks` (snapshot assembly reads the stored header; pk is in
  `powSolutions`). Address derivation via `encode_p2pk_from_pubkey`; the network prefix must
  be plumbed to the assembly site (or derived at serve time in the handler — implementation
  picks whichever keeps the tip-keyed cache semantics intact; the cached value must not
  change per-request, and the prefix is process-constant, so cache-time derivation is safe).
- `Option` so the endpoint stays schema-compatible if a header read faults; utoipa schema
  update + `openapi_native.yaml` snapshot regen + handler test covering the new fields.

### S2 — `GET /api/v1/mining/minerStats?window=N`

- Default window 720, clamped like difficulty-history. Response:
  `{ tip_height: u32, window: u32, blocks: u32, miners: [{ pk, address, count, last_height }] }`
  sorted by `count` desc (`blocks` = headers actually scanned, may be < window near genesis).
- Implementation folds `chain.last_headers(window)` by `powSolutions.pk`; address derived
  once per unique pk. Read-only, ungated, mounted in the native `/api/v1` block with the
  standard utoipa annotation; added to `NativeOpenApi` paths + schemas; snapshot regen;
  endpoint test with a stubbed chain.
- Not gated on `identity.mining` — it describes the network, not the node.

### S3 — stale doc comment fix

`ergo-api/src/types.rs:59` claims `mining` is "always false"; live nodes return true.
Correct the comment while touching the file.

## UI changes (JS, `ergo-api/web/`)

### U1 — `miners.js` (new module)

- Static curated map `POOL_LABELS: Map<address, name>` (top ~10 pools, seeded at
  implementation time from the public explorer's known-miners address book; entries verified
  against recent mainnet blocks). Unknown → no label.
- `minerLabel(address)` → pool name or null; callers fall back to `truncMiddle` address.
- pk→address session cache: module `Map<pkHex, address>`, misses resolved via
  `GET /utils/rawToAddress/{pk}` (plain read fetch, no api-key side effects), successes
  cached only (tokenMeta pattern).
- Own-pk state: when `identity.mining`, fetch `/mining/rewardPublicKey` once; expose
  `isOwnPk(pkHex)` for the "you" badge.

### U2 — explorer block detail (`explorer.js` renderBlock)

- New "miner" kv row above the existing "miner pk" row: pool label (when known) +
  address link to `#explorer/address/<addr>` + "you" badge when applicable.
- Rendered asynchronously after pk→address resolution; row shows the truncated pk as
  placeholder until resolved, and stays on pk if `/utils/rawToAddress` fails. "miner pk"
  row unchanged.

### U3 — block lists

- Explorer home table (`renderHome`): add "Miner" column between Size and Block ID —
  label-or-truncated-address link straight from `miner_address`, "you" badge, `—` when the
  field is absent (older node / fault).
- Overview chain-tip mini-list: append a compact miner element (label or 6+4 truncated
  address, linked) to each row.

### U4 — Mining section (new nav item `mining`, always visible)

- `SECTIONS` += `'mining'` in `app.js`; new `mining.js` view module following the section
  contract (mount/unmount/onSlow), h2 heading + `focusView()` a11y per #153 conventions.
- **Your node** panel: explicit enabled/disabled state; when enabled — work height,
  template # + refreshed-ago, honest "no candidate" state on 503, reward address (link) +
  reward pk, "your blocks in last N: count" (own pk vs minerStats), link to Wallet for
  matured-rewards retrieval. When disabled — a short explainer of how to enable mining.
- **Network** panel: difficulty, est. network hashrate (same formula as overview KPI),
  EIP-37 retarget progress — blocks until next 128-block boundary + estimated Δ% from
  `/api/v1/difficulty/history` interval-vs-target over the current epoch window, labeled
  "est." — and current block reward + emission stats from `GET /emission/at/{height}`
  (verified live on 9063: `{height, minerReward, totalCoinsIssued, totalRemainCoins,
  reemitted}` in nanoERG; display miner income as base reward + re-emission, e.g.
  3 + 9 ERG at the current height, plus supply-issued %).
- **Miner distribution** panel: horizontal share bars over the window — pool label or
  address (linked), count, percentage; window toggle 128 / 720; "you" badge on own row.
- **Recent blocks** table with miner column (same renderer/data as U3).
- All panels degrade independently: any failed fetch renders that panel's empty/error state
  without breaking the section.

### U5 — overview Mining panel enrichment

- Adds: current block reward, "your blocks (24 h): N" (minerStats, 720 window), panel
  header links to `#mining`.
- When `identity.mining` is false: render a one-line muted stub ("mining disabled ·
  Mining →") with zero mining fetches, replacing today's hidden-entirely behavior.

## Data flow & caching

- minerStats fetched on Mining-section mount and on overview slow-tick (4 s cadence is too
  hot for a 720-header fold → fetch once per tip advance: key the refetch on
  `status.bestFullHeight` change, same discipline as the charts series refetch).
- pk→address and pool-label lookups are session-cached in `miners.js`; recent-blocks
  surfaces don't need them (server sends `miner_address`).
- No new polling loops; everything rides existing mount/onSlow hooks.

## Error handling

Every new surface is additive and optional: missing `miner_address`/`miner_pk` fields,
failed minerStats/rawToAddress/emission calls, or a 503 candidate each degrade to exactly
today's rendering (raw pk row, list without miner column values, panel-local empty states).
No old surface gains a hard dependency on a new endpoint.

## Testing

- Rust: unit tests for minerStats fold (multi-miner, window clamp, near-genesis short
  window) and recent-blocks miner fields; openapi snapshot regen; full workspace gate
  (`cargo fmt --all`, `clippy --all-targets --all-features -- -D warnings`, `test --all`).
- UI: live verification against 9063 via devproxy (`/tmp/ui-shots/devproxy.py`) + headless
  chromium screenshots of block detail, explorer home, Mining section (both mining-on via
  9063 and mining-off via a stubbed identity), overview panel.
- Process: codex review before opening the PR.

## Out of scope

- Soft-fork vote activation tracker; reorg/fork history view (deferred, candidate next round).
- Batch pk→address endpoint (not needed — server sends addresses where lists need them).
- Scala-parity endpoint changes of any kind.
- Historical "your blocks" beyond the minerStats window (no indexer query).

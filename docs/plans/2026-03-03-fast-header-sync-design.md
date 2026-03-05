# Fast Header Sync via chainSlice

## Problem

During initial sync, headers must be fetched sequentially due to the P2P protocol's
Inv-based discovery: we send SyncInfo, a peer responds with up to 400 header IDs, we
request them, apply them, update our tip, and repeat. This serial loop bottlenecks at
~400 headers per round-trip regardless of how many peers are connected.

With 100 connected peers, 99 sit idle during header sync.

## Key Insight

Scala nodes expose `GET /blocks/chainSlice?fromHeight=X&toHeight=Y` — a public REST
endpoint returning up to 16,384 full headers per request. This sidesteps the Inv
discovery problem entirely: we don't need header IDs upfront, just height ranges.

Peers already advertise their REST API URL in the P2P handshake via
`RestApiUrlPeerFeature` (feature ID 4). We currently parse this as
`PeerFeature::Unknown` and ignore it.

## Design

### Opt-In Config

```toml
[ergo.node]
# Enable parallel header fetching via peers' REST APIs during initial sync.
fast_header_sync = false
# Headers per HTTP chunk request (max 16384, Scala's limit).
fast_sync_chunk_size = 8192
# Max concurrent HTTP fetch tasks.
fast_sync_max_concurrent = 8
```

Default off. When enabled, runs alongside existing P2P sync — does not replace it.

### Peer API Discovery

1. Add `PeerFeature::RestApiUrl(String)` variant — decode feature ID 4 from
   handshake (1-byte length + UTF-8 URL).
2. Store discovered URLs in a `HashMap<PeerId, String>` accessible to the fast
   sync task.
3. Only peers with known API URLs become HTTP header sources.

### Fast Sync Task

A dedicated `tokio::spawn` task running alongside the event loop:

1. **Discover chain height**: `GET /info` on any API peer → `bestHeaderHeight`.
2. **Divide work**: split `(our_height, best_height]` into chunks of
   `fast_sync_chunk_size`.
3. **Parallel fetch**: up to `fast_sync_max_concurrent` concurrent HTTP tasks,
   each assigned a chunk and a peer (round-robin across API peers).
4. **Per chunk**:
   a. `GET /blocks/chainSlice?fromHeight=X&toHeight=Y`
   b. Parse JSON response into `Header` structs.
   c. Validate PoW in parallel (rayon, same as `validate_headers_parallel`).
   d. Send validated headers to the processor thread via the existing
      `cmd_tx` channel (`ProcessorCommand::StorePrevalidatedHeader`).
5. **Schedule next**: as chunks complete, dequeue and fetch the next.
6. **Handoff**: stop HTTP fetching when within ~1000 headers of the tip.
   P2P Inv loop (which runs concurrently the whole time) handles the tail.

### Ordering & Verification

All consensus-critical checks remain identical to the existing path:

- **PoW verification**: done in the fast sync task before sending to processor.
- **Parent chain check**: done by the processor (`process_prevalidated_header`).
  Headers arriving before their parent go into `ModifiersCache` (capacity 8192).
- **Sequential application**: `apply_from_cache` drains buffered headers in
  height order once parents are stored.
- **Duplicate rejection**: processor's `has_header` check silently drops headers
  already stored via the concurrent P2P path.

### Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Event Loop                 │
                    │                                     │
  P2P peers ──────>│  SyncInfo/Inv/RequestModifier        │
  (existing)       │  (unchanged, always runs)            │
                    │                                     │
                    │  ┌──────────────────────────────┐   │
                    │  │  Fast Sync Task (if enabled) │   │
                    │  │                              │   │
  HTTP peers ──────>│  │  chainSlice fetcher          │   │
  (feature ID 4)   │  │  -> JSON parse               │   │
                    │  │  -> PoW validate (rayon)     │   │
                    │  │  -> cmd_tx.send(StoreHeader) │───│──> Processor Thread
                    │  └──────────────────────────────┘   │    (same as today)
                    └─────────────────────────────────────┘
```

### Existing Code Changes (Minimal)

| File | Change |
|------|--------|
| `ergo-settings/src/settings.rs` | Add 3 config fields with defaults |
| `ergo-wire/src/peer_feature.rs` | Add `RestApiUrl(String)` variant, decode feature ID 4 |
| `ergo-node/src/event_loop.rs` | Store API URLs from handshakes; spawn fast sync task when enabled |

### New Code

| File | Purpose |
|------|---------|
| `ergo-node/src/fast_header_sync.rs` | HTTP fetcher, JSON-to-Header conversion, chunk scheduler |

### Dependencies

- `reqwest` (with `rustls-tls` feature) for HTTP client.
- `serde_json` (already in workspace) for chainSlice response parsing.

### Bandwidth Estimate

At 8192 headers per chunk, ~2KB JSON per header = ~16MB per request.
With 8 concurrent fetches across different peers, throughput scales linearly
until limited by network bandwidth or peer capacity.

For a 1.2M header chain: ~147 chunks of 8192. At 8 concurrent with ~1s per
chunk, initial header sync would complete in ~18 seconds vs the current
sequential P2P path which takes hours.

### Failure Modes

- **No peers advertise API URL**: fast sync is a no-op, P2P path handles
  everything (identical to current behavior).
- **HTTP request fails**: retry with a different peer, log warning. After 3
  failures on a peer, remove from API peer pool.
- **Peer returns bad headers**: PoW validation catches it, peer is removed from
  pool, chunk reassigned.
- **Peer returns incomplete range**: accept what we got, re-request the
  remainder.
- **Config disabled**: zero code path change, feature completely inert.

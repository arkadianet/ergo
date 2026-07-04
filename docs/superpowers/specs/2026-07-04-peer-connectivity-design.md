# Peer connectivity — maximally-reachable public node

**Goal.** Make this node a maximally-reachable, well-connected public Ergo node:
accept many inbound dials, maintain a healthy and diverse outbound set, and keep
the candidate pool full so both fill quickly and stay full. Bounded and
network-friendly — not literally connected to every node (that is an O(N²)
anti-pattern; a gossip node reaches the whole network's *data* through a bounded
peer set via propagation).

**Non-goals.** Connecting to every reachable node; relaxing the anti-eclipse caps
(that was the "maximize distinct-node coverage" objective, explicitly not chosen);
rewriting the P2P stack. The peer layer is already mature (exponential dial
backoff, per-cycle dial budgets, gossip discovery mirroring Scala
`PeerSynchronizer`, redb-persisted address book). This raises its ceilings and
makes the fill loop + inbound capacity actually reach them.

## The in/out asymmetry (the principle behind the numbers)

Inbound and outbound are not symmetric:

- **Inbound** connections are ones other nodes *choose* to open to you. Accepting
  more is pure upside for network health and your data availability — be generous.
- **Outbound** connections consume *other* nodes' inbound slots. Gossip reach
  saturates around ~60–100 peers (you already receive the whole network's data
  through a modest, diverse set). Dialing far beyond that is wasteful and a poor
  citizen. So "maximize outbound" means *healthy and diverse*, not *dial everyone*.

Reference anchor: Scala's default `maxConnections = 30` (a single cap shared by
in+out, only dialing out when `total < 30`); its integration harness uses 100.
This node already improved on that by reserving outbound separately — this design
carries that further by giving inbound its own budget too.

## Current state (as of `main`)

`ergo-p2p/src/peer_manager/limits.rs`:
```
max_connections = 80   target_outbound = 60   per_ip = 1   per_subnet = 3
max_inbound() = max_connections - target_outbound = 20   ← leftover, the bottleneck
```
- Outbound is maintained by `needs_outbound()` / `outbound_deficit()`, dialed in
  `ergo-node/src/node/peer_actions.rs::try_dial_peers` on a ~5s tick, capped at
  `MAX_DIAL_ATTEMPTS_PER_CYCLE = 24` per cycle, with exponential per-address
  backoff (30s→2min→10min→30min→2hr) — **load-bearing** (it fixed a prod incident
  where dead seeds pinned peer count at 3–4).
- Discovery: one periodic `GetPeers` to a single random peer per `GOSSIP_INTERVAL`
  (mirrors Scala `PeerSynchronizer`), plus gossiped `Peers` replies feeding the
  redb address book.
- Inbound accept path: `register_inbound` rejects with `TooManyInbound` once
  `inbound_count >= max_inbound()`.
- Declared address is advertised in the handshake + `Peers` gossip
  (`config/resolved.rs`, `handshake.rs`), so peers can dial back.

**The core limitation:** inbound is only ever `max − outbound = 20`, so no matter
how the operator tunes things, the node accepts at most 20 inbound dials. That is
the primary blocker to "let others dial in."

## Design

### 1. Decouple inbound into its own budget  *(the key change)*
`PeerLimits` gains an explicit `max_inbound: usize` field. `max_inbound()` returns
it directly instead of `max_connections − target_outbound`. `max_connections`
stays as a **hard total ceiling** for resource safety (checked on every
register_outbound/inbound). Result: a full outbound set never starves inbound, and
inbound can be sized generously without stealing outbound slots.

New defaults (all operator-configurable via `[network]` toml; existing keys keep
working, new `max_inbound` key added):

| knob | old | new | why |
|------|-----|-----|-----|
| `target_outbound` | 60 | **96** | stronger, more redundant gossip reach; still a good citizen |
| `max_inbound` | 20 (leftover) | **256** | the reachability lever — accept many inbound dials |
| `max_connections` | 80 | **384** | hard ceiling ≥ 96+256 with slack for handshake/eviction races |
| `per_ip` / `per_subnet` | 1 / 3 | 1 / 3 | anti-eclipse, unchanged |

Resource note: ~384 connections ≈ a tokio task + bounded framing buffers each
(~tens of MB total) — comfortable on any real server; documented as tunable-down
for constrained hosts.

### 2. Reach the higher outbound target faster
- Raise `MAX_DIAL_ATTEMPTS_PER_CYCLE` 24 → **32** so a larger deficit closes in a
  few cycles without a thundering herd. Keep the 5s tick, the steady-state
  throttle (`DIAL_FAST_THRESHOLD` / `DIAL_SLOW_PERIOD`), and the backoff verbatim.

### 3. Keep the candidate pool full and diverse
- When the outbound deficit is large **or** the address book has few connectable
  candidates, send `GetPeers` to up to **3** peers per cycle instead of 1 (faster,
  more diverse candidate acquisition on cold start / after churn). Keep the single
  periodic gossip for steady-state topology refresh so we never spam at capacity.
- No change to the anti-eclipse selection in `addresses_to_connect` — diversity
  (per-IP / per-subnet) is preserved.

### 4. Inbound reachability (verify, minimal change)
- Confirm the listener accepts up to the new `max_inbound` (flows from the
  decoupled budget + the existing `register_inbound` check — no new mechanism).
- Confirm the declared address is advertised so peers can dial back (already the
  case; add a test asserting it round-trips into the handshake/Peers path).
- Being publicly *reachable* (port-forward / firewall) is an operator concern,
  out of code scope — but we make the node's advertised address correct and its
  inbound capacity generous so a reachable node fills up.

## Components touched

| file | change |
|------|--------|
| `ergo-p2p/src/peer_manager/limits.rs` | add `max_inbound` field + defaults; `max_inbound()` returns it; keep `max_connections` as hard ceiling |
| `ergo-p2p/src/peer_manager/mod.rs` | `register_inbound`/`register_outbound` enforce the decoupled budgets + total ceiling |
| `ergo-node/src/config/{toml_sections,load,resolved}.rs` | expose `max_inbound` config key; wire new defaults |
| `ergo-node/src/node/peer_actions.rs` | bump dial-per-cycle budget; multi-peer GetPeers when deficit/pool low |
| `ergo-node/src/config/mod.rs` (doc header) | update the documented defaults |

## Testing
- `peer_manager` unit tests: inbound accepted up to `max_inbound` independent of
  outbound occupancy; outbound maintained to `target_outbound` independent of
  inbound; `max_connections` hard ceiling still rejects past the sum; anti-eclipse
  caps (per-IP/subnet) unchanged. A regression test that a *full outbound set does
  not reduce inbound capacity* (the decoupling invariant).
- Config tests: `max_inbound` parses, defaults apply, back-compat for configs
  without the key.
- Dial-loop test: with a large deficit, a cycle attempts up to the new budget;
  backoff still skips backed-off addresses; multi-peer GetPeers fires only when
  deficit/pool is low.
- Declared-address round-trip test (handshake/Peers advertisement).
- Whole-workspace gate green (fmt/clippy/test).

## Risks / trade-offs
- **More bandwidth/CPU** at 384 vs 80 peers — intended; documented as tunable-down.
- **Outbound citizenship**: 96 outbound is a deliberate ceiling; not raised further
  to avoid consuming excess inbound slots network-wide.
- **Anti-eclipse unchanged**: keeps eclipse resistance; means a single subnet still
  can't fill your slots (correct for a public node).
- **No consensus impact**: this is the network/peer layer only; no block/tx
  validation or wire-format changes.

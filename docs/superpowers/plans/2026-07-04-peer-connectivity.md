# Peer Connectivity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make this node a maximally-reachable public Ergo node by decoupling the inbound connection budget from the outbound target, raising the connection ceilings, and keeping the dial/discovery loop feeding those higher targets — without touching the anti-eclipse caps.

**Architecture:** `PeerLimits` (in `ergo-p2p`) gains an explicit `max_inbound` field so inbound capacity no longer equals `max_connections − target_outbound` leftover. `max_connections` stays a hard total ceiling enforced in `check_can_connect`. The node config surfaces `max_inbound` as a `[peers]` TOML key. The dial loop (`peer_actions.rs`) raises its per-cycle budget and fans `GetPeers` to a bounded set of peers whenever the candidate pool is thin (not only when fully drained).

**Tech Stack:** Rust (workspace crates `ergo-p2p`, `ergo-node`), tokio, `serde`/TOML config, `cargo test`/`clippy`/`fmt`.

**Spec:** `docs/superpowers/specs/2026-07-04-peer-connectivity-design.md`

**Design numbers:** `target_outbound` 60 → **96**, `max_inbound` 20 (leftover) → **256** (own budget), `max_connections` 80 → **384**, `MAX_DIAL_ATTEMPTS_PER_CYCLE` 24 → **32**, new `GOSSIP_FANOUT` = **3**. Anti-eclipse caps (`per_ip_limit` 1 / `per_subnet_limit` 3) unchanged.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `ergo-p2p/src/peer_manager/limits.rs` | `PeerLimits` struct + default constants + `ConnectError` | Add `max_inbound` field + `DEFAULT_MAX_INBOUND`; raise defaults; `max_inbound()` returns the field |
| `ergo-p2p/src/peer_manager/tests.rs` | Unit tests for the manager | Widen `unique_addr`; decoupling + hard-ceiling tests |
| `ergo-p2p/src/peer_manager/mod.rs` | Connection lifecycle | `register_inbound` doc comment only (behavior already reads `max_inbound()`) |
| `ergo-node/src/config/toml_sections.rs` | `[peers]` TOML shape | Add `max_inbound: Option<usize>` |
| `ergo-node/src/config/load.rs` | Build `PeerLimits` from TOML | Wire `max_inbound` with `DEFAULT_MAX_INBOUND` fallback |
| `ergo-node/src/config/mod.rs` | Module doc header (example TOML) | Update documented defaults |
| `ergo-node/src/config/tests.rs` | Config parse/load tests | Parse + default + override + back-compat tests |
| `ergo-node/src/node/peer_actions.rs` | Dial scheduler + gossip fan-out | Raise dial budget; `getpeers_fanout` helper + thin-pool `GetPeers` |

**No change needed** (verified during recon, do not edit):
- `ergo-node/src/config/resolved.rs` — its doc already says "accepts inbound peers up to `peer_limits.max_inbound()`", which stays correct.
- `ergo-node/src/node/boot.rs` — passes the whole `config.peer_limits` struct to `PeerManager::new_with_limits`, and already logs `max_inbound()`; the new field flows through automatically.

---

## Task 1: Decouple `max_inbound` into its own budget (`ergo-p2p`)

Data change in `limits.rs` plus the `peer_manager` tests that assert on it. These move together: the new tests reference the `max_inbound` field and `DEFAULT_MAX_INBOUND`, which do not compile until the struct change lands — that compile failure is the "red".

**Files:**
- Modify: `ergo-p2p/src/peer_manager/limits.rs:11-39`
- Modify: `ergo-p2p/src/peer_manager/tests.rs:152-155` (`unique_addr` helper)
- Modify: `ergo-p2p/src/peer_manager/tests.rs:642-686` (two existing tests)
- Test: `ergo-p2p/src/peer_manager/tests.rs` (add new tests)

- [ ] **Step 1: Widen the `unique_addr` test helper to span distinct /16 subnets**

Raising `max_connections` to 384 makes `max_connections_enforced` register 384 addresses. The current helper wraps at `u8` 256, colliding on the 257th. Replace `ergo-p2p/src/peer_manager/tests.rs:152-155`:

```rust
fn unique_addr(i: usize) -> SocketAddr {
    // Distinct /16 subnet per index so per-IP (/32) and per-subnet (/16)
    // caps never collide for indices up to ~65k. octet0 starts at 1 to
    // stay off the 0.0.0.0/8 reserved block.
    let hi = 1 + (i / 256) as u8;
    let lo = (i % 256) as u8;
    addr(hi, lo, 0, 1, 9030)
}
```

- [ ] **Step 2: Run the existing p2p tests to confirm the helper change is inert**

Run: `cargo test -p ergo-p2p --lib peer_manager`
Expected: PASS (the helper still yields distinct addresses; defaults are still 80/60 at this point).

- [ ] **Step 3: Write the decoupling tests (these will NOT compile yet)**

Replace the existing `inbound_slot_limit_reserves_outbound` (`tests.rs:642-658`) and `custom_limits_drive_outbound_target_and_inbound_reserve` (`tests.rs:660-686`) with the three tests below. The struct literal now carries a `max_inbound` field and the code references `DEFAULT_MAX_INBOUND` — neither exists yet.

```rust
#[test]
fn default_limits_are_decoupled() {
    // The inbound budget is an explicit field, NOT `max - target`.
    assert_eq!(DEFAULT_MAX_CONNECTIONS, 384);
    assert_eq!(DEFAULT_TARGET_OUTBOUND, 96);
    assert_eq!(DEFAULT_MAX_INBOUND, 256);
    let limits = PeerLimits::default();
    assert_eq!(limits.max_inbound(), 256);
    // Proof of decoupling: the old leftover formula would give 288.
    assert_ne!(
        limits.max_inbound(),
        DEFAULT_MAX_CONNECTIONS - DEFAULT_TARGET_OUTBOUND,
        "max_inbound must be its own budget, not max_connections - target_outbound",
    );
}

#[test]
fn full_outbound_does_not_reduce_inbound() {
    // Decoupling invariant: filling the entire outbound target must not
    // steal a single inbound slot. Small custom limits keep the numbers
    // tractable and make max_inbound (12) distinct from the old leftover
    // max - target (20 - 5 = 15).
    let limits = PeerLimits {
        max_connections: 20,
        target_outbound: 5,
        max_inbound: 12,
        per_ip_limit: 1,
        per_subnet_limit: 3,
    };
    let mut mgr = PeerManager::new_with_limits(1, limits);
    let now = Instant::now();

    // Fill outbound to target.
    for i in 0..5 {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(mgr.outbound_deficit(), 0);

    // Inbound still reaches its full explicit budget (12), unaffected by
    // the full outbound set. 5 + 12 = 17 <= 20, so the total ceiling is
    // not the limiter here — max_inbound is.
    for i in 5..17 {
        mgr.register_inbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(
        mgr.register_inbound(unique_addr(17), now),
        Err(ConnectError::TooManyInbound),
    );
}

#[test]
fn custom_limits_decouple_inbound() {
    // max_inbound (4) is deliberately NOT max_connections - target_outbound
    // (12 - 7 = 5), proving the inbound cap is the explicit field.
    let limits = PeerLimits {
        max_connections: 12,
        target_outbound: 7,
        max_inbound: 4,
        per_ip_limit: 1,
        per_subnet_limit: 3,
    };
    let mut mgr = PeerManager::new_with_limits(1, limits);
    let now = Instant::now();

    assert_eq!(mgr.limits(), limits);
    assert_eq!(mgr.outbound_deficit(), 7);

    // Inbound caps at the explicit 4, not the leftover 5.
    for i in 0..4 {
        mgr.register_inbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(
        mgr.register_inbound(unique_addr(4), now),
        Err(ConnectError::TooManyInbound),
    );

    // Outbound still reaches its own target (4 + 7 = 11 <= 12).
    for i in 5..12 {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    assert_eq!(mgr.outbound_deficit(), 0);
}

#[test]
fn max_connections_is_hard_ceiling_over_sum() {
    // target_outbound + max_inbound (5 + 8 = 13) exceeds max_connections
    // (10). The total ceiling must still cap the sum: once 10 peers are
    // connected, the next register is rejected as TooManyConnections even
    // though the inbound budget (8) is not yet full.
    let limits = PeerLimits {
        max_connections: 10,
        target_outbound: 5,
        max_inbound: 8,
        per_ip_limit: 1,
        per_subnet_limit: 3,
    };
    let mut mgr = PeerManager::new_with_limits(1, limits);
    let now = Instant::now();

    for i in 0..5 {
        mgr.register_outbound(unique_addr(i), now).unwrap();
    }
    for i in 5..10 {
        mgr.register_inbound(unique_addr(i), now).unwrap();
    }
    // 10 total = max_connections. Inbound count is only 5 (< 8), yet the
    // total ceiling rejects first (check_can_connect runs before the
    // inbound-cap check in register_inbound).
    assert_eq!(
        mgr.register_inbound(unique_addr(10), now),
        Err(ConnectError::TooManyConnections),
    );
}
```

- [ ] **Step 4: Run to confirm it fails (red)**

Run: `cargo test -p ergo-p2p --lib peer_manager`
Expected: FAIL to compile — `no field 'max_inbound' on type PeerLimits` and `cannot find value 'DEFAULT_MAX_INBOUND'`.

- [ ] **Step 5: Apply the `limits.rs` data change**

Replace `ergo-p2p/src/peer_manager/limits.rs:11-39` with:

```rust
pub const DEFAULT_MAX_CONNECTIONS: usize = 384;
pub const DEFAULT_TARGET_OUTBOUND: usize = 96;
pub const DEFAULT_MAX_INBOUND: usize = 256;
pub const DEFAULT_PER_IP_LIMIT: usize = 1;
pub const DEFAULT_PER_SUBNET_LIMIT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLimits {
    /// Hard ceiling on total concurrent connections (inbound + outbound).
    /// Enforced on every register via `check_can_connect`; caps the sum
    /// even when `target_outbound + max_inbound` would exceed it.
    pub max_connections: usize,
    /// Outbound connections the node actively maintains (dials to reach).
    pub target_outbound: usize,
    /// Inbound connections the node accepts. Decoupled from
    /// `target_outbound`: a full outbound set never reduces inbound
    /// capacity. `0` = outbound-only (accept no inbound).
    pub max_inbound: usize,
    pub per_ip_limit: usize,
    pub per_subnet_limit: usize,
}

impl PeerLimits {
    /// Maximum inbound connections accepted. An explicit budget,
    /// independent of `max_connections` / `target_outbound` (the total
    /// ceiling still applies on top via `check_can_connect`).
    pub fn max_inbound(&self) -> usize {
        self.max_inbound
    }
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            target_outbound: DEFAULT_TARGET_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            per_ip_limit: DEFAULT_PER_IP_LIMIT,
            per_subnet_limit: DEFAULT_PER_SUBNET_LIMIT,
        }
    }
}
```

(A field and inherent method may share the name `max_inbound` in Rust — `self.max_inbound` is the field, `self.max_inbound()` the method. Keeping the method avoids touching the `mod.rs` / `boot.rs` call sites.)

- [ ] **Step 6: Run to confirm green**

Run: `cargo test -p ergo-p2p --lib peer_manager`
Expected: PASS — all `peer_manager` tests, including the four new ones and the auto-scaled `max_connections_enforced` (now 384) and `needs_outbound_tracks_target` (now 96).

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add ergo-p2p/src/peer_manager/limits.rs ergo-p2p/src/peer_manager/tests.rs
git commit -m "feat(p2p): decouple max_inbound from outbound target + raise defaults

max_inbound becomes an explicit PeerLimits field (default 256) instead of
the max_connections - target_outbound leftover. Defaults raised to
out=96 / in=256 / cap=384. max_connections stays a hard total ceiling."
```

---

## Task 2: Update the `register_inbound` doc comment (`ergo-p2p`)

Doc-only: the code already reads `self.limits.max_inbound()`, which now returns the decoupled field. Only the stale "reserve outbound slots" comment needs correcting. No test (comment change).

**Files:**
- Modify: `ergo-p2p/src/peer_manager/mod.rs:210-212`

- [ ] **Step 1: Replace the comment**

Replace `ergo-p2p/src/peer_manager/mod.rs:210-212`:

```rust
    /// Attempt to register a new inbound connection. Returns Err if limits prevent it.
    /// Inbound connections are capped at max_connections - target_outbound to
    /// reserve outbound slots (anti-eclipse).
```

with:

```rust
    /// Attempt to register a new inbound connection. Returns Err if limits prevent it.
    /// Inbound is capped at its own `max_inbound` budget (decoupled from
    /// `target_outbound`, so a full outbound set never reduces inbound
    /// capacity). The `max_connections` total ceiling still applies on top
    /// via `check_can_connect`.
```

- [ ] **Step 2: Confirm it still builds**

Run: `cargo build -p ergo-p2p`
Expected: PASS (no functional change).

- [ ] **Step 3: Commit**

```bash
git add ergo-p2p/src/peer_manager/mod.rs
git commit -m "docs(p2p): correct register_inbound comment for decoupled max_inbound"
```

---

## Task 3: Surface `max_inbound` in node config (`ergo-node`)

Expose `max_inbound` as a `[peers]` TOML key, wire it into `PeerLimits` with the `DEFAULT_MAX_INBOUND` fallback, and update the config tests + doc header. `max_inbound = 0` is a **legal** value (outbound-only), so — unlike `target_outbound` — it gets no zero-rejection.

**Files:**
- Modify: `ergo-node/src/config/toml_sections.rs:309`
- Modify: `ergo-node/src/config/load.rs:90-93`
- Modify: `ergo-node/src/config/mod.rs:14-18` (doc header)
- Test: `ergo-node/src/config/tests.rs:96-161` (update + add)

- [ ] **Step 1: Write/adjust the config tests (red)**

In `ergo-node/src/config/tests.rs`, update `peers_section_parses_connection_limits` (lines 96-109) to include the new key:

```rust
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
```

Replace `load_default_peer_limits_target_sixty_outbound` (lines 126-138) with:

```rust
#[test]
fn load_default_peer_limits_are_decoupled() {
    let toml = default_toml();
    let cli = minimal_cli(Some(&toml));
    let cfg = NodeConfig::load(cli).expect("load");
    assert_eq!(cfg.peer_limits, ergo_p2p::peer_manager::PeerLimits::default());
    assert_eq!(cfg.peer_limits.max_connections, 384);
    assert_eq!(cfg.peer_limits.target_outbound, 96);
    assert_eq!(cfg.peer_limits.max_inbound(), 256);
}
```

Replace `load_toml_peer_limit_override` (lines 140-161) with (adds the `max_inbound` key + struct field):

```rust
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
```

Add a back-compat test immediately after it:

```rust
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
```

- [ ] **Step 2: Run to confirm it fails (red)**

Run: `cargo test -p ergo-node --lib config`
Expected: FAIL to compile — `no field 'max_inbound'` on `TomlPeers` and on the `PeerLimits` literal.

- [ ] **Step 3: Add the `max_inbound` field to `TomlPeers`**

In `ergo-node/src/config/toml_sections.rs`, insert after line 309 (`pub(super) per_subnet_limit: Option<usize>,`):

```rust
    /// Maximum inbound connections accepted. Decoupled from
    /// `target_outbound`, so a full outbound set never reduces inbound
    /// capacity. `0` = outbound-only. Defaults to `DEFAULT_MAX_INBOUND`
    /// (256) when omitted.
    pub(super) max_inbound: Option<usize>,
```

- [ ] **Step 4: Wire it into `PeerLimits` in `load.rs`**

In `ergo-node/src/config/load.rs`, insert into the `PeerLimits { ... }` literal, immediately after the `target_outbound: ...` block (after line 93):

```rust
            max_inbound: toml_cfg
                .peers
                .max_inbound
                .unwrap_or(ergo_p2p::peer_manager::DEFAULT_MAX_INBOUND),
```

Leave the existing validations untouched. Do **not** add a `max_inbound == 0` rejection — outbound-only is a legitimate posture (mirrors an absent `bind_addr`).

- [ ] **Step 5: Update the config doc header**

Replace `ergo-node/src/config/mod.rs:14-18`:

```rust
//! [peers]
//! known = ["213.239.193.208:9030", "159.65.11.55:9030"]
//! target_outbound = 60
//! max_connections = 80
//! ```
```

with:

```rust
//! [peers]
//! known = ["213.239.193.208:9030", "159.65.11.55:9030"]
//! target_outbound = 96
//! max_inbound = 256
//! max_connections = 384
//! ```
```

- [ ] **Step 6: Run to confirm green**

Run: `cargo test -p ergo-node --lib config`
Expected: PASS — all four updated/added config tests, plus the untouched `load_rejects_outbound_target_above_max_connections`.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add ergo-node/src/config/toml_sections.rs ergo-node/src/config/load.rs ergo-node/src/config/mod.rs ergo-node/src/config/tests.rs
git commit -m "feat(node): expose [peers] max_inbound config key

Wires the decoupled inbound budget through TOML (default 256 when
omitted; 0 = outbound-only). Back-compat: configs without the key load
unchanged."
```

---

## Task 4: Feed the higher targets — dial budget + thin-pool GetPeers (`ergo-node`)

Two dial-loop changes from spec §2/§3: raise `MAX_DIAL_ATTEMPTS_PER_CYCLE` 24 → 32, and fan `GetPeers` to a bounded set of peers whenever the candidate pool is thin (not only when fully drained). The fan-out policy is factored into a pure `getpeers_fanout` helper so it is unit-testable without a tokio runtime or real sockets (the dial path itself spawns `dial_task`, which does network I/O and is exercised at integration level).

**Files:**
- Modify: `ergo-node/src/node/peer_actions.rs:17-34` (consts + comment fix)
- Modify: `ergo-node/src/node/peer_actions.rs:81-123` (dial-loop tail)
- Test: `ergo-node/src/node/peer_actions.rs` (add `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the `getpeers_fanout` unit tests (red)**

Append to the end of `ergo-node/src/node/peer_actions.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::{getpeers_fanout, GOSSIP_FANOUT};

    #[test]
    fn healthy_pool_asks_no_one() {
        // have >= want → never gossip when the pool already covers demand.
        assert_eq!(getpeers_fanout(32, 32, 100), 0);
        assert_eq!(getpeers_fanout(40, 32, 100), 0);
    }

    #[test]
    fn drained_pool_asks_everyone() {
        // have == 0 → dead-seed recovery: fan to every connected peer.
        assert_eq!(getpeers_fanout(0, 32, 5), 5);
        assert_eq!(getpeers_fanout(0, 32, 0), 0);
    }

    #[test]
    fn thin_pool_asks_bounded_set() {
        // 0 < have < want → cap the fan-out at GOSSIP_FANOUT...
        assert_eq!(getpeers_fanout(3, 32, 100), GOSSIP_FANOUT);
        // ...but never more peers than are actually connected.
        assert_eq!(getpeers_fanout(3, 32, 2), 2);
    }
}
```

- [ ] **Step 2: Run to confirm it fails (red)**

Run: `cargo test -p ergo-node --lib node::peer_actions`
Expected: FAIL to compile — `cannot find function 'getpeers_fanout'` / `GOSSIP_FANOUT`.

- [ ] **Step 3: Bump the dial budget, fix the stale threshold comment, add the fan-out const + helper**

Replace `ergo-node/src/node/peer_actions.rs:17-34` (the three existing consts and their doc comments) with:

```rust
/// Upper bound on concurrent dial attempts per dial cycle. Keeps the
/// initial fill-up from bursting too many SYNs at once when a large
/// batch of learned addresses lands. Sized a little above the Scala
/// reference node's per-tick budget so the larger outbound target
/// (`DEFAULT_TARGET_OUTBOUND = 96`) closes in a few 5s cycles without a
/// thundering herd.
const MAX_DIAL_ATTEMPTS_PER_CYCLE: usize = 32;

/// Upper bound on how many connected peers we fan a `GetPeers` request
/// to when the candidate pool is merely thin (non-empty but short of
/// this cycle's demand). A fully drained pool fans to every connected
/// peer instead — see [`getpeers_fanout`]. Kept small so a
/// well-connected node stays a polite gossip citizen.
const GOSSIP_FANOUT: usize = 3;

/// Once outbound deficit drops to or below this many slots, switch to
/// `DIAL_SLOW_PERIOD` between cycles. Above this threshold (cold start
/// / IBD) we dial on every 5s tick. Picked so that we stay aggressive
/// for the entire fill-up: at the default `target_outbound = 96` we
/// don't throttle until we have at least 88 outbound peers.
const DIAL_FAST_THRESHOLD: usize = 8;

/// Period between dial cycles once deficit ≤ `DIAL_FAST_THRESHOLD`.
/// Matches the original 30s cadence — gentle to the network in steady
/// state, where churn is rare.
const DIAL_SLOW_PERIOD: Duration = Duration::from_secs(30);

/// Decide how many connected peers to fan a `GetPeers` request to this
/// dial cycle.
///
/// * `have` — dial candidates currently available.
/// * `want` — candidates this cycle would like (already capped at
///   `MAX_DIAL_ATTEMPTS_PER_CYCLE`).
/// * `connected` — eligible connected peers we could ask.
///
/// Returns:
/// * `0` when the pool is healthy (`have >= want`) — a node at capacity
///   never spams GetPeers (the periodic single-peer gossip still runs).
/// * `connected` when the pool is fully drained (`have == 0`) — the
///   dead-seed recovery case: ask everyone, we have nothing to lose.
/// * `min(connected, GOSSIP_FANOUT)` when the pool is thin — top it up
///   from a bounded set without spamming.
fn getpeers_fanout(have: usize, want: usize, connected: usize) -> usize {
    if have >= want {
        0
    } else if have == 0 {
        connected
    } else {
        connected.min(GOSSIP_FANOUT)
    }
}
```

- [ ] **Step 4: Rewire the dial-loop tail to use `getpeers_fanout`**

Replace `ergo-node/src/node/peer_actions.rs:81-122` (from the `// Overshoot the deficit` comment through the closing `}` of the `for addr in addrs` loop) with:

```rust
    // Overshoot the deficit slightly to absorb dials that fail
    // immediately, but cap at the per-cycle budget.
    let want = (deficit + 1).min(MAX_DIAL_ATTEMPTS_PER_CYCLE);
    let addrs = state.peer_manager.addresses_to_connect(now, want);

    // Top up the candidate pool by asking connected peers for their peer
    // lists whenever ours is thin relative to this cycle's demand — not
    // only when it is fully drained. Firing on "thin" (not just "empty")
    // closes the large-deficit / few-candidates gap on cold start and
    // after churn; `getpeers_fanout` bounds how many peers we ask so a
    // node near capacity never spams GetPeers. A fully drained pool still
    // fans to everyone (the dead-seed recovery path that fixed a prod
    // incident where dead seeds pinned peer count at 3–4).
    let gossip_targets: Vec<_> = state
        .peer_manager
        .connected_peers()
        .map(|p| p.addr)
        .filter(|addr| state.registry.peers.contains_key(addr))
        .collect();
    let fanout = getpeers_fanout(addrs.len(), want, gossip_targets.len());
    if fanout > 0 {
        for addr in gossip_targets.iter().take(fanout) {
            send_to_peer(state, addr, message::CODE_GET_PEERS, Vec::new());
        }
        debug!(
            deficit = deficit,
            have = addrs.len(),
            want = want,
            fanned_to_peers = fanout,
            "dial tick: candidate pool thin, fanned GetPeers",
        );
    }

    for addr in addrs {
        match state.peer_manager.register_outbound(addr, now) {
            Ok(()) => {
                debug!(peer = %addr, deficit = deficit, "attempting dial");
                tokio::spawn(peer_loop::dial_task(
                    addr,
                    state.magic,
                    state.our_handshake.clone(),
                    state.event_tx.clone(),
                ));
            }
            Err(e) => {
                debug!(peer = %addr, error = %e, "cannot register outbound dial");
            }
        }
    }
```

Note: this removes the old `if addrs.is_empty() { … return; }` early-return. When the pool is empty, `getpeers_fanout` returns `connected` (fan to all — same behavior as before), and the `for addr in addrs` loop iterates an empty vec (no-op). `fanout ≤ gossip_targets.len()` always holds by construction, so `take(fanout)` and the `fanned_to_peers` log are exact.

- [ ] **Step 5: Run to confirm green**

Run: `cargo test -p ergo-node --lib node::peer_actions`
Expected: PASS — the three `getpeers_fanout` tests.

- [ ] **Step 6: Confirm the whole node crate still builds (the dial-loop edit compiles in context)**

Run: `cargo build -p ergo-node`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add ergo-node/src/node/peer_actions.rs
git commit -m "feat(node): raise dial budget + thin-pool GetPeers fan-out

MAX_DIAL_ATTEMPTS_PER_CYCLE 24 -> 32 to close the larger outbound
deficit in a few cycles. getpeers_fanout fans GetPeers to a bounded set
of peers when the candidate pool is thin (not only when fully drained),
preserving the fan-to-all dead-seed recovery path. Fixes a stale
target_outbound=75 comment."
```

---

## Task 5: Whole-workspace gate (CI parity)

Run the full gate exactly as CI does — whole workspace, never a `-p` subset (a subset misses cross-crate construction sites and mis-fires feature-gated lints).

**Files:** none (verification only).

- [ ] **Step 1: Format check**

Run: `cargo fmt --all -- --check`
Expected: PASS (no diff). If it fails, run `cargo fmt --all` and amend the relevant commit.

- [ ] **Step 2: Clippy, whole workspace, warnings-as-errors**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS (no warnings).

- [ ] **Step 3: Full test suite**

Run: `cargo test --all`
Expected: PASS. Sanity-scan the output for the touched areas: `ergo-p2p` `peer_manager` (decoupling + `max_connections_enforced` at 384 + `needs_outbound_tracks_target` at 96), `ergo-node` `config` (parse/default/override/back-compat) and `node::peer_actions` (`getpeers_fanout`).

- [ ] **Step 4: Final verification grep — no stale default numbers remain**

Run: `grep -rn "target_outbound, 60\|max_connections, 80\|max_inbound(), 20\|target_sixty" --include=*.rs`
Expected: no matches (all old-default assertions were replaced in Tasks 1 and 3).

---

## Spec Coverage Check

| Spec section | Task |
|--------------|------|
| §1 Decouple inbound into its own budget (`max_inbound` field, `max_connections` hard ceiling) | Task 1 |
| §1 New defaults (out 96 / in 256 / cap 384) | Task 1 (constants) + Task 3 (config surface) |
| §1 Operator-configurable via `[peers]` TOML, existing keys keep working | Task 3 |
| §2 Raise `MAX_DIAL_ATTEMPTS_PER_CYCLE` 24 → 32 | Task 4 |
| §3 Multi-peer `GetPeers` when the candidate pool is thin, bounded fan-out | Task 4 (`getpeers_fanout`, `GOSSIP_FANOUT = 3`) |
| §3 Anti-eclipse selection unchanged | Tasks 1–4 leave `per_ip_limit` / `per_subnet_limit` and `addresses_to_connect` untouched |
| §4 Inbound capacity flows from the decoupled budget + existing `register_inbound` check | Task 1 (behavior) + Task 2 (doc) |
| §4 Declared address advertised so peers can dial back | Already covered by `inbound_handshake_persists_declared_for_redial` (`peer_manager/tests.rs:25`) and `peers_for_sharing_excludes_non_routable_declared_addresses` (`tests.rs:1156`) — verified during recon, no new test needed |
| Testing: decoupling invariant, hard ceiling, config parse/default/back-compat, fan-out policy | Tasks 1, 3, 4 |
| Whole-workspace gate green | Task 5 |

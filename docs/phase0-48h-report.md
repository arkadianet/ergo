# Phase 0 observer — 48 h window report

**Window:** 2026-11-10 14:02 → 2026-11-12 14:02 AEST (boundary epoch ms
`1794456120000`, inclusive).
**Status:** closed. This is the deliverable required by
`phase0-observer.md` ("Post-redeploy, re-run `scripts/analysis/summarize.py`
on the final data and write the 48 h report …").

All numbers below are reproducible from the boundary-cut snapshot in
`/home/arkadias/observation/boundary-20261112/` (five stream cuts +
`MANIFEST.txt` with sha256s) and the analysis scripts
`scripts/analysis/{cut_boundary.py, summarize.py, announce_delay_ci.py,
window_metrics.py}`. Saved outputs: `summarize-boundary.txt/.json`,
`announce-delay-ci-boundary.txt`, `window-metrics.json`.

## 1. Scope and data

### 1.1 The five observation streams

The report covers **all five** running observation vantages, cut at the
boundary wall (`wall_ms <= 1794456120000`; the cut keeps no lower bound,
which matters only for the testnet hook — see §1.3):

| stream | source file | records in cut | span | first wall (AEST) | last wall (AEST) |
|---|---|---|---|---|---|
| `mainnet-hook` | `/home/arkadias/nodes/rust-mainnet/data/observer.jsonl` | 1,226,586 | 167,528 s (46.5 h) | 11-10 15:29:22 | 11-12 14:01:30 |
| `mainnet-standalone` | `/home/arkadias/observation/mainnet-standalone/observer.jsonl` | 231,253 | 172,791 s (48.0 h) | 11-10 14:02:04 | 11-12 14:01:54 |
| `mainnet-crawler` | `/home/arkadias/observation/mainnet-crawler/crawl.jsonl` | 190,504 | 169,241 s (47.0 h) | 11-10 15:01:18 | 11-12 14:01:59 |
| `testnet-crawler` | `/home/arkadias/observation/testnet-crawler/crawl.jsonl` | 193,512 (+1 torn line) | 169,240 s (47.0 h) | 11-10 15:01:19 | 11-12 14:01:58 |
| `testnet-hook` | `/mnt/fastdata/nodes/testnet-node/data/observer.jsonl` | 103,579 | 174,303 s (48.4 h) | 11-10 13:36:17 | 11-12 14:01:20 |

Cut sha256 (see `MANIFEST.txt` for full values and line counts in/out):
`5e04e253…ee54e74` (mainnet-hook), `d3c672e5…0894857` (standalone),
`887ac093…cdbb35` (mainnet-crawler), `8fa71b80…054af4` (testnet-crawler),
`dc888671…cf09da6` (testnet-hook). Re-running
`scripts/analysis/cut_boundary.py` reproduces every cut byte-identically
(verified for all five).

**Vantage coverage caveats.** The mainnet node hook starts 11-10 15:29:22,
so it covers 46.5 h of the 48 h window; the two crawlers start 11-10 15:01
(47.0 h); only the standalone observer covers the full window. The
testnet hook stream starts 11-10 13:36:17, i.e. **26 min before the window
start**, so testnet metrics cover 48.4 h rather than 48.0 h — an immaterial
asymmetry for a quiet secondary network.

### 1.2 Process sessions (`mono_ns` resets)

All five services were restarted in a coordinated restart on 11-11 15:38
and again by the machine reboot at 11-11 16:41 (journal + node-API
`started_at` evidence; no binary changed). Session starts in the cut:

| stream | session starts (AEST) |
|---|---|
| `mainnet-hook` | 11-10 15:29:22 · 11-11 15:38:03 · 11-11 16:41:43 · 11-12 14:01:12 (T0 swap) |
| `mainnet-standalone` | 11-10 14:02:04 · 11-10 15:01:18 · 11-11 15:38:02 · 11-11 16:41:42 |
| `mainnet-crawler` | 11-10 15:01:18 · 11-11 15:38:02 · 11-11 16:41:43 |
| `testnet-crawler` | 11-10 15:01:19 · 11-11 15:38:03 · 11-11 16:41:43 |
| `testnet-hook` | 11-10 13:36:17 · 11-11 07:23:09 (step-1 canary swap) · 11-11 15:38:03 · 11-11 16:41:43 |

The window-close redeploy (step 3: observer + both crawlers at 11-12
15:26:02) is **post-window** and does not appear in the cut. Every record in
the cut for the observer/crawler streams therefore predates the SyncInfo
tip fix — the empty-V2 era runs the whole window (§6). The mainnet node's
T0 swap (step 2, 11-12 14:01:12) is in-window but holds only ~18 s of data
(0 applied blocks).

Steady-state metrics exclude the first 300 s of each session. Note also
session 2 (11-11 15:38 → 16:40): `mono_ns` lags wall by 388.6 s in all
streams — a ~6.5 min system suspend — so `since_first_announce_us`
(monotonic-based) excludes that suspended time for session-2 blocks.

### 1.3 Reproducibility

- `cut_boundary.py --boundary-ms 1794456120000 …` rebuilds the snapshot;
  bytes are preserved verbatim (torn-write NUL blocks kept; the analysis
  tools strip leading NULs and recover the two recoverable records).
- `summarize.py` (per-stream event counts, RTT, section sizes, anomalies,
  clock, peer joins) → `summarize-boundary.txt/.json`.
- `announce_delay_ci.py` (head-line metric, session handling, bootstrap
  CIs, cross-check) → `announce-delay-ci-boundary.txt`.
- `window_metrics.py` (tx-flow, announce composition, outbound rates,
  per-session missing-fractions) → `window-metrics.json`.

## 2. Headline: tip-header announce→apply delay (mainnet)

From the mainnet node hook, `block_applied.since_first_announce_us` — the
time from the first peer announce of the tip header to block apply on our
node (1,363 blocks applied in 46.5 h ≈ the 2-min mainnet cadence):

| statistic | all blocks (n=1361) | steady-state (n=1354) | 95 % CI (steady-state) |
|---|---|---|---|
| **median** | 582.0 ms | **581.8 ms** | **[579.3, 584.4] ms** |
| **p90** | 886.9 ms | **884.2 ms** | **[860.1, 926.5] ms** |
| p99 | 2,734.8 ms | 2,737.6 ms | — |
| max | 222,445.5 ms | 222,445.5 ms | — |

- Bootstrap: B=10,000, resampled by block (a re-applied height is a
  distinct unit), seed 20261112.
- 14 of 1,361 blocks lie above the p99.
- The max (222,445.5 ms) is height 1914516 applied at 11-12 01:57:12 — the
  **second** apply of that height after a competing branch extended and was
  reorged (first apply 01:53:27). Legitimate tip event, not an outlier of
  the pipeline.
- 2 of 1,363 blocks carry no `since_first_announce_us`: h=1913717 (11-10
  23:07:33) and h=1913851 (11-11 03:40:44), both **mined locally** by this
  node (confirmed against `data/mining-history.json`, id + timestamp
  exact) — no peer announce precedes apply.
- Cross-check: every one of the 1,363 blocks joins to a logged announce
  event in the same session (1,363/1,363); the join reproduces the logged
  field to **max 0.2 ms** (median 0.0 ms; join ≤ field in 1,357/1,361, as
  expected from event-stamp ordering).

Testnet (for reference; quiet network, see §3.4): p50 **563.4 ms**, p99
15.9 s, max 54.3 s over the 762 peer-announced applied blocks.

## 3. Other interval estimates

### 3.1 Header validation (`header_validated.duration_us`, mono)

| vantage | n | p50 | p99 | max | missing |
|---|---|---|---|---|---|
| `mainnet-hook` | 935 | 11.6 ms | 28.6 ms | 178.6 ms | 429 (31.5 %) |
| `testnet-hook` | 749 | 8.6 ms | 16.4 ms | 26.3 ms | 49 (6.1 %) |

Missing-fractions are explained in §5 (pre-fix stamping bug; the testnet
split is the in-window verification of the fix).

### 3.2 Tx flow (node hooks, mono, within session, joined by tx id)

| vantage | n | announce→body p50 (p99) | body→outcome p50 (p99) | announce→outcome p50 (p99) |
|---|---|---|---|---|
| `mainnet-hook` | 15,503 | 276.8 ms (784.1) | 0.9 ms (9.3) | 279.1 ms (789.1) |
| `testnet-hook` | 1,180 | 275.5 ms (43.2 s) | 2.4 ms (11.2) | 276.9 ms (43.2 s) |

Outcomes (mainnet): 8,101 admitted / 7,402 rejected (`StorageRentPolicy`
3,716, `UnresolvedInput` 2,702, `DoubleSpendLoser` 741,
`ValidationFailed{ScriptFailed}` 175, `Structural` 55,
`UnresolvedDataInput` 13 — all reasons checked against the Scala
reference, see `phase0-observer.md` "Tx-outcome rejection parity"). The
announce→body gap (~277 ms at both vantages) is the peer's relay-to-modifier
delivery, not our processing; the testnet p99 tail is the same quiet-testnet
queueing effect as the block-apply tail below.

### 3.3 Request latency and header RTT

- **announce → first request** is p50 0.0–0.1 ms (max 0.1 ms) at the
  mainnet hook, the standalone, the mainnet crawler and the testnet hook
  (n = 15,590 / 2,932 / 2,564 / 1,193). The request fires immediately on
  announce; pacing shapes the request *rate*, not the decision latency.
  The testnet crawler is the exception in its tail (p99 30.4 s, max 25.0
  min, n=5,599): pacing against an almost-empty network, where connect p50
  = the 10 s timeout cap (43 successful connects all at the cap).
- **Header-fetch RTT (type 101), unsplit, full window:**

  | vantage | n | p50 | p99 | max |
  |---|---|---|---|---|
  | `mainnet-standalone` | 2,932 | 238.3 ms | 2,386.2 ms | 2,386.2 ms |
  | `mainnet-crawler` | 2,564 | 276.7 ms | 1,199.2 ms | 1,280.8 ms |
  | `testnet-crawler` | 5,599 | 41.4 ms | 2,275.3 ms | 2,767.3 ms |

  Because the whole window is the empty-V2 era (§6), these unsplit figures
  are dominated by early-chain re-sends. The **tip-only** rows (h > 400,
  the honest header-fetch RTT) are p50 **235 / 275 / 41 ms** (p99
  299 / 285 / 484 ms; split computed offline against the 20:35 snapshot
  per `phase0-observer.md` §"Header RTT: sample composition matters").
  Cite the tip rows with the caveat that the full window stays in the
  pre-fix era; post-fix (step 3 onward) the composition becomes
  tip-dominated by construction.
- **Section sizes** (type-101 receipts): mainnet tip headers constant
  **220 B** at every vantage; early mainnet headers 278/279 B (variable
  extension, content unimportant to parity); testnet 219–283 B. The 47
  header ids received at both the standalone and the node hook agree on
  size in all 47 cases — on-wire variation, not measurement drift.

### 3.4 Testnet: locally mined blocks

The testnet node mines the majority of testnet blocks: of 4,515
`block_applied` in the cut, 3,753 (83.1 %) carry no
`since_first_announce_us` because no peer announce precedes apply. The
762 peer-announced blocks show p50 563.4 ms (comparable to mainnet) but a
long tail (p99 15.9 s, max 54.3 s) — quiet-network queueing, not pipeline
latency.

## 4. Outbound cap: choice and headroom

**Chosen cap: 64 KiB/s (65,536 B/s) per session**, token-bucket
drop-not-queue at the send path, as recorded in every `observer_start`
(`outbound_bytes_per_sec`). Set on the standalone observer and both
crawlers; the node hooks run with the bucket disabled (0) — their outbound
is bounded by the node's own request pacing and is of the same small order
(mainnet hook 15,590 requests, testnet hook 1,193, over the full window).
The standalone service additionally carries `CPUQuota=10%`.

Measured against the cap, full window (from `request_sent` records,
overhead + 32 B/id):

| vantage | requests | total bytes | peak B/s | peak as % of cap | mean B/s |
|---|---|---|---|---|---|
| `mainnet-standalone` | 1,360 | 104,704 | 2,056 | **3.1 %** | 0.61 |
| `mainnet-crawler` | 1,385 | 93,128 | 4,112 | **6.3 %** | 0.55 |
| `testnet-crawler` | 4,420 | 214,528 | 2,056 | **3.1 %** | 1.27 |

The cap was **never binding**: peak request rate reached at most 6.3 % of
it, and typical egress is ~1 B/s — request pacing (per-peer interval,
≤64 ids/request, ≤4 outstanding per peer) is what bounds a normal session,
exactly as designed. The record schema has **no drop counter**, so the
absence of drops is established by the headroom above, not by a counter.
The 64 KiB/s cap is retained as the modest, defensible choice for the
report; the observed headroom means it is invisible in normal operation.

## 5. Missing `duration_us` fractions (and the in-window fix verification)

Root cause (fully worked out in `phase0-observer.md`
§"Missing `header_validated.duration_us`"): the header bytes reached the
validation pipeline without a stamped `Modifiers` receipt — the SyncInfoV2
continuation path and the coalesced header-Modifiers processor did not
stamp. Fix: `cd701a8c` (stamp at both sites; observation-only).

Full-window fractions, by session:

**Mainnet hook — 429/1,364 = 31.5 % missing, all pre-fix binary** (session
4, the 14:01:12 new-binary swap, holds 18 s and 0 header validations, so
mainnet cannot show the fix in-window):

| session | header_validated present | missing | missing % |
|---|---|---|---|
| 0 (11-10 15:29) | 490 | 230 | 31.9 % |
| 1 (11-11 15:38) | 21 | 8 | 27.6 % |
| 2 (11-11 16:41) | 424 | 191 | 31.1 % |

**Testnet hook — the in-window verification of the fix.** The step-1
canary put the fixed binary on the testnet node at 11-11 07:23:09, inside
the window:

| session | binary | header_validated present | missing | missing % |
|---|---|---|---|---|
| 0 (11-10 13:36) | old | 250 | 49 | 16.4 % |
| 1 (11-11 07:23) | **new** | 141 | 0 | **0.0 %** |
| 2 (11-11 15:38) | **new** | 11 | 0 | **0.0 %** |
| 3 (11-11 16:41) | **new** | 347 | 0 | **0.0 %** |

0 missing across all 499 post-swap `header_validated` records, versus 16.4 %
pre-swap. The fix works in production.

`block_applied.since_first_announce_us` missing: mainnet 2/1,363 (0.1 %) —
the two locally mined blocks, §2; testnet 3,753/4,515 (83.1 %) — locally
mined, §3.4. Neither is a defect.

## 6. Empty-V2-era artifacts (full window)

**Mechanism.** The pre-fix observer/crawler presents an honest-but-empty V2
SyncInfo; each ergoref 6.0.8 seed answers every `Younger` comparison with a
catch-up `Inv` of the first 400 header ids (heights 1–400), re-sent per
processed sync reply (full derivation in `phase0-observer.md`
§"Header RTT: sample composition matters"). Both sides behave honestly; it
is a measurement-composition effect, not a protocol divergence.

**Full-window composition** (announce id-occurrences, boundary cut):

| vantage | total occurrences | early (h ≤ 400) share | early distinct ids | re-announces/id (max = p50) | inv batch sizes |
|---|---|---|---|---|---|
| `mainnet-standalone` | 9,292,336 | **97.0 %** | 400 | 22,545 | {1: 176,307, 400: 22,545} |
| `mainnet-crawler` | 9,188,226 | **97.5 %** | 400 | 22,401 | {1: 138,806, 400: 22,401} |
| `testnet-crawler` | 3,704,522 | **92.2 %** | 400 | 8,543 | {1: 124,275, 400: 8,543} |

Every 400-id batch is the seed's continuation re-send; the single-id
announcements are genuine tip-region traffic. Consequences for this report:

1. The **unsplit** type-101 RTT figures (§3.3) are early-chain-dominated;
   the tip-only rows (p50 235/275/41 ms) are the honest header-fetch RTT.
2. The early-header receipts exist only because of the re-send; the
   278/279 B early-header size class is likewise an artifact of that era.

**The fix** (present the observed tip, verified against receipt bytes,
`06b44bdd` + `2067a235` on this branch) was A/B-verified against a mainnet
seed: 6 catch-up extensions per 300 s (one every ~60 s steady state) with
the empty-V2 binary vs **1** (only answering the honest initial reply) with
the fixed binary, after which the seed compares `Equal` and sends nothing.
Post-fix, a connection receives the 400-id catch-up exactly once and then
only tip-region announces.

**Era boundary.** Per the window-close plan, the running
observer/crawler binaries kept the empty-V2 behaviour until the window
closed; the fixed binaries started at step 3 (11-12 15:26:02),
**post-window**. All window data for the observer/crawler vantages
therefore contains the artifact; the node hooks (real nodes with their own
sync state) are unaffected. Post-window data from step 3 onward is the
first post-fix dataset.

## 7. Interop evidence and PR #715

**Live-byte verification of the fixed codec.** The 2,508 mainnet handshakes
captured 11-11 07:25–11:47 AEST from 55 unique peers
(`--capture-handshake-hex`) were replayed offline through the fixed codec
(`replay-captures`): **100 % parse-OK, 0 rejections, 0 newly-rejected** vs
the pre-fix codec. Per unique peer, excluding our own pre-fix node:
2,408/2,458 strict (98.0 %); 50 (2.0 %) `unknown:3` — all 50 from one other
pre-fix Rust peer (`ergo-rust-mainnet-nbg1`, old 12-byte big-endian
SessionId body), preserved verbatim as `Unknown` with the handshake
accepted, per the unknown-feature keep decision. Including our own node:
2,408/2,508 (96.0 %). Independent confirmation via the jar oracle (real
Scala 6.0.8 `HandshakeSerializer.parse`) on the testnet canary's captures
agrees. Evidence and replay procedure: `docs/unverified.md`
("Wire bytes: verified against live bytes").

**PR #715** (`fix/p2p-codec-fuzz`) carries the codec parity work to main:
SyncInfo V2 + Peers codec fixes with boundary tests (`4f35c10f`), golden
wire vectors + offline fuzz suite fixing the bugs it found (`b717970d`),
cross-generation SessionId evidence in-repo + CHANGELOG (`f26970c7`),
canonical feature-body enforcement (`19d6dc72`). This branch
(`p2p/phase0-observer`) carries the content-equivalent commits
(`85c1b052`, `ada81855`, `a9b20789`) plus the observer-branch-only stamp
fix (`cd701a8c`). Once #715 merges, main is merged into
`p2p/phase0-observer` (content-identical, no conflicts expected).

## 8. Data quality

- **Machine reboot, 11-11 16:41** restarted all five services (not a
  redeploy; journal + node-API `started_at` evidence; wall gaps 85.7 /
  95.7 / 90.8 s). Torn writes at the kill boundary, exactly one line per
  affected stream: mainnet-hook line 651161 (1,650 leading NULs, then the
  intact post-reboot `observer_start` — recoverable) and mainnet-crawler
  line 98847 (3,162 leading NULs, recoverable); testnet-crawler line
  103503 (456-byte truncated record, not recoverable) is carried verbatim
  in the cut and counted as the one schema anomaly. The analysis tools
  strip leading NULs before parsing, so the two recoverable records are
  counted as sessions.
- **`mono_ns` regressions:** every one is explained by the counted
  restarts (15:38 coordinated restart, 16:41 reboot, 14:01:12 T0 swap);
  all but the sub-60 s T0 swap are corroborated by ≥60 s wall gaps.
  No unexplained regressions remain (tool rule fixed in `8fcfc27f`).
- **System suspend, 11-11 15:38→16:40 session:** mono lags wall by 388.6 s
  in all streams; affects only the 29 mainnet session-2 blocks (see §1.2).
- **Clock:** chrony-configured offsets 0.0–1.8 ms; handshake-measured skew
  p50 −111.0 ms (standalone, n=42), −125.0 ms (mainnet-crawler, n=27),
  −138.5 ms (testnet-crawler, n=24). All inter-stream timing in this
  report uses per-process `mono_ns`, so wall-clock skew is not in the
  measurement path.
- **Peer overlap:** mainnet-crawler × mainnet-hook share 57 of the hook's
  69 peers (82.6 %); the standalone's 4 peers all appear in the crawler's
  117 (3 shared with the hook); testnet crawler × testnet hook share 3 of
  4. Cross-vantage measurements therefore see largely the same network.
- **Tip reorg at h=1914516** (11-12 01:53–01:57): the only re-applied
  height; carries the window-max announce delay (§2).
- **Locally mined mainnet blocks:** exactly two in-window
  (h=1913717, h=1913851; §2) — the node is an active miner at the 2-min
  cadence target.

## 9. Post-window items

Carried forward after the 14:02 boundary (details to be documented as they
are worked):

1. **Observer inbound limits** — the observer currently accepts inbound
   sessions without the bounded-outbound discipline's counterpart on the
   inbound side; limits to be defined and recorded.
2. **Crawler redesign** — the crawl loop's pacing/dial behaviour
   (testnet crawler's 10 s-timeout-dominated connects and 25-min request
   tails) motivates a redesign of the crawl strategy.
3. **Divergence docs** — the protocol-behaviour differences observed in
   code review (see `docs/unverified.md`, "Behavioural differences
   observed in code review") need a standing divergence document.
4. **Merge PR #715** into main, then merge main into
   `p2p/phase0-observer` (content-identical codec commits, no conflicts
   expected).

---

*Companion document: `docs/phase0-observer.md` (design, dataset boundaries,
redeploy record, fix derivations). Raw data and analysis outputs:
`/home/arkadias/observation/boundary-20261112/`.*

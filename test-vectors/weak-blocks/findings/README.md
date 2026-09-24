# Matrix (input blocks) — divergence findings

Artifacts written when the port and the pinned reference node disagreed,
or when something was measured that the spec's findings list needed a
number for. **Nothing here is patched over**: a finding is recorded with
both nodes' raw REST bodies and the Rust debug-log window around the
observation, and the port's response is written down beside it.

"Matrix" is the protocol's name. `weak-blocks` appears only as the
upstream branch and pin name.

## The pins

The artifacts here and the vectors in the parent directory are NOT on
the same reference build.

* The vectors in the parent directory are pinned to `ergoplatform/ergo`
  branch `weak-blocks`, commit `62c10315e1ebcac4480dba6bacdc2100a38119e5`,
  with sigma-state `6.0.5-22-368a860b-SNAPSHOT`
  (`368a860be033af94aa14895381f42099b3646db6`). Each vector's `manifest`
  records that pin (re-pinned in `c250f3c9`).
* Every artifact in this directory was written BEFORE that re-pin, during
  the M2/M3 rounds against the earlier pin, `weak-blocks` commit
  `31a8de804f7328704f2753a1cf151dda8f64689f` (same sigma-state). None
  has been regenerated at `62c10315`, and none is evidence about that
  build on its own.

| artifact | where it records the pin |
| --- | --- |
| `2026-09-22-1.json` | `scala_app_version` = `6.0.4-492-31a8de80-SNAPSHOT` |
| `2026-09-22-2.json` | `component` names `weak-blocks @ 31a8de80…` |
| `2026-09-22-3.json` | `component` names `weak-blocks @ 31a8de80…` |
| `2026-09-22-3/captured-block.json` | `scala_app_version` = `6.0.4-492-31a8de80-SNAPSHOT` |
| `2026-09-22-4.json` | `component` names `weak-blocks @ 31a8de80…` |
| `2026-09-22-5.json` | records no Scala version (a Rust follower throughput observation); written in the same 31a8de80 rounds, last changed in `fc102970` before the re-pin |
| `2026-09-22-6/7/8.json` | the Scala node's `/info` `appVersion` = `6.0.4-492-31a8de80-SNAPSHOT` |

A finding that has to be quoted against `62c10315` needs a fresh run at
that pin; the M4 evidence under `dev-docs/upstream/matrix-findings/`
names the run each of its numbers comes from.

## Where they come from

| producer | what it writes |
| --- | --- |
| `scripts/devnet-matrix/smoke.py` | the M2 mixed-node smoke (six assertions) |
| `scripts/devnet-matrix/campaign.py` | the M3 campaign (seven scenarios) |

Both write every artifact to their own gitignored `.work/findings/`
first. Only findings a human PROMOTES land here — an uncapped run writes
hundreds of near-identical files, and committing those is noise, not
evidence.

## Naming

`<date>-<n>.json`, allocated in order on the day. A companion directory
of the same stem (e.g. `2026-09-22-3/`) holds raw bytes too large for
the JSON: captured blocks, announcement frames.

## What a promoted artifact carries

* `id`, `title`, `severity` (`divergence` | `observation`), `status`;
* `component` — which side it is a finding about, with the pin;
* `spec_finding` when it is evidence for an `F*` row of the design
  spec's §12;
* `summary` in prose, then the raw evidence: both nodes' REST bodies at
  the observation, the Rust event tail, the matching debug-log window,
  and the announcement bytes for every block id it names;
* `port_response` — what the port does about it, naming the divergence
  (`D1`-`D8`) when the port deliberately differs;
* `upstream_action` — the change that would fix it upstream.

An artifact that cannot say what the node did next is a FAILURE of the
run that wrote it, not a shrug: the harnesses fail rather than record an
`unverifiable` outcome.

## Current artifacts

| file | severity | subject |
| --- | --- | --- |
| `2026-09-22-1.json` | observation | follower retains only a short suffix of the miner's input chain (throughput, later fixed by D6/D7) |
| `2026-09-22-2.json` | divergence | miner announces a `prevTransactionsDigest` its own extension does not commit to (F4c') |
| `2026-09-22-3.json` (+ dir) | divergence | miner and follower assemble an ordering block's transactions in opposite orders (F12) |
| `2026-09-22-4.json` | divergence | follower reads the collected input chain under a key that never has one (F5) |
| `2026-09-22-5.json` | observation | instantaneous tip equality is unreachable; the gate is consistency-under-lag |
| `2026-09-22-6/7/8.json` | divergence | `bestInputChain` prefix mismatches recorded at mismatch time (the same lag artifact) |

Upstream issue drafts for these — one file per finding, with the vector
hex — live under `dev-docs/upstream/matrix-findings/` (gitignored: the
user posts them).

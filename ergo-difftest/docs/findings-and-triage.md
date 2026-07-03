# Fuzz-differential — findings, acceptance methodology, triage queue

Written by the lead engineer after running the generators through the re-injection
gate and the live JVM oracle. This is the honest signal assessment — what is
proven, what is not, and what a human must decide. Nothing here auto-resolves a
which-side-is-right call.

## What is PROVEN

1. **Generator coverage.** The SER structure-aware generators reach 16/16 declared
   adversarial features across all surfaces (`cargo test -p ergo-difftest --test
   gen_coverage`, 9/9). Every wire-reachable known-bug feature is emitted, honestly
   `intended_valid`-tagged, and lands on the intended codec verdict.

2. **Re-injection rediscovery (controlled delta).** Re-injecting
   `relation2-0x85-noncanonical` (bug #12) and running the **structured generator
   through the JVM oracle** produces a clean-vs-patched delta that surfaces the bug:

   | tree | Canonical divergences / 4000 (ergo_tree, seed 1) |
   |------|--------------------------------------------------|
   | clean HEAD | 356 |
   | #12 re-injected | 1321 |

   The +965 Canonical jump (and the exact `00938503` compact-form repro) is the
   rediscovery signal. The gate agent also proved #12 hermetically via
   `--check-canonical` and `fundef-ntpeargs-signed-byte` (#14) via the oracle, each
   with clean=pass / patched=fail static triggers.

## What is NOT yet trustworthy (the red-oracle findings — surfaced, not papered)

### Finding A — acceptance must be DIFFERENTIAL and PER-SURFACE, never absolute count
`--structured --oracle` on bare `ergo_tree` reports ~969 divergences / 4000 on
**clean, current-main code**. That is not 969 bugs. The node validates in *layers*
— `read_ergo_tree` is intentionally lenient (SANTA hook), and the real gates fire
one layer up: box-script rules (1001 sigma-prop-root, 1012 size-bit,
tree-version-supported) at `ergo_box_candidate`, and the group-element curve check
at tx validation (`tx/ge.rs`). The JVM's `ErgoTreeSerializer` is monolithic and
rejects all of these at parse. So the bare `ergo_tree` differential over an
adversarial generator **over-reports by construction**.

Consequence: the generator-acceptance gate must (a) target the surface where the
bug's gate actually lives (box-script bugs → `ergo_box_candidate`; GE/monetary →
a validation surface; only pure-ser bugs → `ergo_tree`), and (b) assert a
**clean-vs-patched delta on the specific class/feature**, not a raw divergence
count. Raw `divergences > 0` is meaningless here.

### Finding B — the oracle campaign reports NON-REPRODUCING divergences
Some divergences the campaign counts do **not** reproduce when their printed
`--repro <input_hex>` is replayed standalone (they come back `agree`):

| printed repro | campaign said | standalone `--oracle --repro` |
|---------------|---------------|-------------------------------|
| `080208d3` | Canonical | **agree** (does not reproduce) |
| `0008cd02ff…ff` (off-curve GE) | divergence | **agree** (does not reproduce) |
| `00728080808008` | AcceptReject | **AcceptReject** (reproduces) |

The campaign's `run_oracle` dedups by `divergence_signature` and prints the first
representative's `input_hex`; either the signature grouping is coarser than the
input that actually diverged, or a per-input state/version-context differs between
the campaign `diff` path and the `run_oracle_repro` path. Until every reported
divergence is **minimized and repro-verified** (drop any whose minimized input
does not reproduce), the raw `--structured --oracle` stream is not an actionable
signal. This makes Slice 3 (minimize → repro-verify → auto-file → human triage)
load-bearing, not optional.

## Triage queue (human decides which side is right — NOT the harness, NOT the lead)

### TRIAGE-001 — ValUse with undefined val id: node accepts, JVM rejects
- **Input** (reproduces): `00728080808008`
- **Decode:** ErgoTree header `00` (v0, no size bit, no constant segregation) →
  `ValUse` (opcode `0x72`) → val id VLQ `8080808008` (≈ 2^28), which is not a
  defined val in scope.
- **Verdicts:** `rust=Accept("00728080808008")` · `jvm=Reject("NoSuchElementException")`
  (Scala eagerly resolves the ValUse's type from the valdef type store at
  deserialize and throws on the missing id; the node defers ValUse type resolution
  and accepts the tree).
- **Class:** accept/reject (potential accept-invalid) on the pure `ergo_tree` ser
  surface.
- **Open question (consensus-truth — escalated, unresolved):** is an undefined-id
  `ValUse` reachable in a real box script such that the node would treat as valid a
  script every Scala node rejects at parse? Or is it caught at a later node layer
  (eval/box) or unreachable, making this a bare-surface artifact like the
  layered-validation cases in Finding A? A human must make this call before any
  Rust change. Do NOT "fix" the node to match itself.

## Recommended next steps (in order)
1. **Slice 3 first** — minimize + repro-verify every divergence; only repro-stable,
   minimized cases enter the triage queue. This directly resolves Finding B and
   turns the noisy stream into a clean signal.
2. **Per-surface, differential acceptance gate** — extend `reinject_gate.sh` to run
   the *generator* (not just static triggers) on the bug's correct surface and
   assert a clean-vs-patched delta on the bug's class/feature (Finding A). This is
   the automated form of the #12 proof above.
3. **Route box-script/validation bugs to their surfaces** — #9/#17/#25 →
   `ergo_box_candidate`; #4 → a validation surface; keep #1/#12/#14/#20 on
   `ergo_tree`.
4. Triage TRIAGE-001 with a human consensus-truth call.

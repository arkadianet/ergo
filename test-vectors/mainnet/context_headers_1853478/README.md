# CONTEXT.headers divergence — mainnet 1,853,462 – 1,853,480 (2026-08-17/18)

Oracle vectors for a **live accept-invalid consensus divergence**: this Rust node
accepted and applied 15 blocks that the Scala reference node rejected as malformed.

## The rule

Scala exposes **9** headers to `CONTEXT.headers` when validating a block, not 10.

`ErgoStateContext.scala` (ergo-master):

- `process(header, ext)` → `newHeaders = header +: lastHeaders.take(LastHeadersInContext - 1)`
  — the context used to validate block `H` has `lastHeaders = [H, H-1 … H-9]` (10 entries).
- `sigmaPreHeader = lastHeaders.head` → `H`
- `sigmaLastHeaders = lastHeaders.drop(1)` → **`[H-1 … H-9]`, 9 entries**

So during block validation the maximum valid index is `CONTEXT.headers(8)`.
`CONTEXT.headers(9)` throws `ArrayIndexOutOfBoundsException` and the block is rejected.

`UpcomingStateContext` (candidate construction, `/transactions/check`, mempool) overrides
`sigmaLastHeaders` with the **whole** `lastHeaders` sequence — 10 entries, `[H-1 … H-10]` —
because the block being built is carried separately in `predictedHeader`. That asymmetry is
the JVM-side bug that let the transaction into the mempool and into candidates.

`scala_verification_context.json` is the live oracle: the Scala node's own context dump while
rejecting block `3a011457…` at height 1,853,462.

```
preHeader.height = 1853462          (the block under validation)
headers.length   = 9
headers heights  = 1853461 … 1853453   (H-1 … H-9, tip-first)
```

## What this node does

`SnapshotView::last_headers_window()` (`ergo-state/src/store/snapshot/mod.rs`) returns
`[tip-9 ..= tip]` — **10** headers — and that vector reaches the evaluator unchanged via
`ergo-validation/src/block/validate.rs` → `TransactionContext.last_headers` →
`ReductionContext.last_headers` (`ergo-validation/src/tx/script/mod.rs`).

Entries 0..8 match Scala exactly. The 10th (`H-10`) is spurious and must not be visible
during block validation.

The candidate path (`CandidateValidationContext.last_headers: [Header; 10]`,
`ergo-validation/src/pre_header.rs`) and the mempool tip path
(`ergo-node/src/node/tip_context.rs`) match `UpcomingStateContext` and are correct as-is.

Note `CONTEXT.headers.size` is script-observable, so the divergence is bidirectional: a
contract branching on size can make this node **reject** a block Scala accepts, not only
accept one it rejects.

## The trigger

`tx_b44970ed.json` spends `a18124cb…` (creationHeight 1,853,457, see `spent_input_boxes.json`).
The script computes `HEIGHT - SELF.creationInfo._1 - 1` and, for values ≥ 9, falls through to a
hardcoded `CONTEXT.headers(9).id`. At height 1,853,478 that index is 20 → the fallback fires.

## Expected behaviour

| vector | expectation |
| --- | --- |
| `block_reject_cb0df53b.json` (h 1,853,478) | **REJECT** — script verification fails on `b44970ed…` input #0 |
| `block_reject_e2c62f4c.json` (h 1,853,479) | **REJECT** — same cause |
| `block_accept_7f0ee965.json` (h 1,853,478) | **ACCEPT** — the canonical sibling, no poison tx |

`ancestor_headers_tip_first.json` holds the 10 ancestors of `cb0df53b…`
(1,853,477 → 1,853,468) so the validation context can be built without a synced chain.
A correct implementation feeds the evaluator only the first 9 of them.

**ADProofs caveat.** Only `block_accept_7f0ee965.json` carries `adProofs` (5,696 bytes of
`proofBytes`). Every rejected block has `adProofs: null` — this node never persisted proofs
for blocks it later reorged away, and `/blocks/{id}/proofFor` 404s for them. So the reject
vectors do **not** support standalone pruned-mode replay; they must be validated against a
UTXO state at the parent height, or driven through the tx/script layer directly using
`ancestor_headers_tip_first.json` + `spent_input_boxes.json`. For a `CONTEXT.headers` parity
test that is sufficient — the divergence is in script evaluation, well before the AVL digest
check that would need the proofs.

## Observed divergence

`rust_divergence_windows.json` — every poisoned block this node applied as its best tip and
later reorged away. 15 blocks, 1,853,462 → 1,853,480, cumulatively **~10.6 hours** on an
invalid tip between 2026-08-17T21:44Z and 2026-08-18T09:32Z. Recovery was by cumulative
work each time, never by validation: this node never rejected any of them.

`rejected_blocks.json` — all 19 blocks our Scala node rejected in the window, with local
timestamps and first validation error. 18 are attributable to `b44970ed…`, matching the
count reported independently on the JVM side.

`scala_verification_context.log` — raw log excerpt the JSON was parsed from.

`rejected_block_bodies/` — the remaining 14 rejected blocks, full bodies, named
`<height>_<id12>.json`. 13 contain `b44970ed…`; `1853301_437601cd2079.json` is the unrelated
proofHash rejection below. These exist on this node because it wrongly applied them; the
Scala node discarded the bodies and serves 404 for them.

`rust_held_rejected_blocks.json` — index of every rejected block this node holds, with
height, timestamp, miner pk, tx count and parent.

## Unrelated, do not conflate

Block `437601cd…` at height 1,853,301 (02:07:37 local) was rejected by Scala with
`Regenerated proofHash is not equal to the declared one` — a different cause. This node also
briefly applied it (697 s) before reorging to the canonical `ff2cd7ee…`, which both nodes now
agree on. Tracked separately; it is not evidence for the header-count rule.

## Provenance

Captured 2026-08-18 from the operator's own archival nodes: Rust `ergo-rust-mainnet-0.5.3`
(:9063) and Scala `ergo-0.0.0-38-6a54ca17-20260806-1819-SNAPSHOT` (:9053), both at
height 1,853,562 and agreeing on `bestHeaderId` at capture time.

# Relay captures

These lines are copied verbatim (including `relay_ts`) from
`matrix-evidence/relay-refresh-2026-09-28/smoke/campaign/steady-{scala,scala2,scala3}-1.log`.
The source run used base a1bd938ef and syncfix 6fad0e04e.

The slice starts at the recorded measurement start, 1790532377.0621312,
and ends at 2026-09-27T18:07:55Z. It contains:

- All successful UtxoState applications in the slice (heights 21–23).
- The first two mined IDs in each interval and their follower receipt lines.
  Six IDs belong to completed intervals, two to the terminal open interval.
- All SyncInfo message lines, plus the first line for each socket pair, to
  retain the cross-node connection identity without unrelated DEBUG traffic.

`relay-samples.json` copies the first two raw M2 samples for each follower
from `steady.json` → `relay_refresh.M2.<node>.raw_samples`.
`relay-stale.json` copies all seven Scala2 stale samples from that same source.
Only tests explicitly described as perturbations change captured values.
The Rust receipt API is mocked in collector tests; live receipt validation
belongs to the smoke evidence, not these Scala log fixtures.

For the three completed intervals, each Scala follower received all six
retained mined IDs. Receiver SyncInfo counts are [0, 1, 1] from the miner at
Scala2, [0, 1, 1] from Scala2 at the miner, and [0, 2, 2] from Scala3 at the
miner. Their minimum gaps are 60.181 s, 60.181 s and 4.607 s respectively.
The first interval has zero messages and remains in the mean denominator.

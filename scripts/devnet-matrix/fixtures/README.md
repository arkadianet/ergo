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


`relay-a1.json` contains verbatim lines from archived run
`/home/rkadias/coding/development/arkadianet/matrix-evidence/relay-refresh-2026-09-28/A1/campaign/steady-{scala,scala2,scala3}-1.log`.
Each `{line, text}` entry preserves the original full-log line number and
text, including newline and relay timestamp. The cases select the first
stock stale non-send, +2 drop and gap drop in Q3's per-ID table; nearby
traffic is included to test socket attribution. Preceding full-height
lines establish mined intervals. `cases[].samples` and `recovery.samples`
are verbatim `steady.json` / `relay_refresh.M2.*.raw_samples` values.
`recovery` captures the 70 delayed H55 IDs plus the first prompt ID, their
mining/admission lines and samples around the 37.443815-second episode.
The fixture's case labels and restricted M1 sets are derived annotations,
not node log fields. Negative tests explicitly perturb these captures to
exercise classes absent from A1 (`a-not-sent-other`, `other`) and ambiguous
or missing evidence. Tests do not need an A1 archive unless
`RELAY_A1_EVIDENCE` is set for the full-run Q3 parity check.

`relay-acceptance.json` is a small verbatim subset of A1's captured
`relay_refresh.source_lines`: the first three ordering blocks, follower
receipt/header/reconstruction/application lines mentioning them, and early
SyncInfo arrivals. `source_line` records the 1-based captured entry index,
not the full-log line number. Its window is shortened at the third miner
application, with a two-second receipt tail. It deliberately omits input-block
traffic; tests supply explicit input denominators and control omissions to
verify that header acquisition is not counted as announcement receipt.
Threshold and percentile tests perturb the real receiver events' timestamps.

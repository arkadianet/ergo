# Miner candidate inspection and local accounting

The Mining page includes an operator-authenticated **Candidate contents** panel.
It inspects the exact work ID (`msg`) and publish sequence the miner received,
including recently superseded templates while the node retains them.

The report lists transactions in block order with their origin, fee, measured
validation cost, serialized size, inputs, outputs, scripts, token amounts and
canonical signed bytes. An export button saves the same frozen JSON report.
Exclusions name the transactions the build considered and left out, with the
reason. A reason starting with `required_` marks a block-policy requirement
that this template does not satisfy; the panel lists those first and work is
published without them (see [miner-block-policy.md](miner-block-policy.md)).
Header votes and extension fields show the commitments actually present in that
template. All ERG and token quantities in the inspection API are decimal strings;
browser clients must keep them as strings or use `BigInt`.

Miner proceeds distinguish emission, collected transaction fees and storage rent,
with the actual payout boxes and their spendable heights. Rent collection can
produce several payout boxes; the report includes every miner payout and excludes
recreated owner outputs, even when their owner is also the miner. Tokens held in
recreated boxes are not miner income. Recovered and burned token amounts come from
the final claim's input/output difference, after selection and trimming.

The storage-rent scan count is the bounded set resolved for that build, rather
than the whole eligible backlog. It includes overdue boxes. Actual selected inputs,
recreation/consumption branches, collected ERG and token-preservation deferrals are
shown separately. `/blockchain/storageRent/eligibleAt/{height}` can inspect the
index's wider eligibility view; it is a separate live/indexed read and must not be
presented as the frozen candidate inventory. Upcoming rent on Overview measures
newly maturing boxes and serves a different purpose.

## Operator endpoints

Send the configured `api_key` header to all inventory and history endpoints:

- `GET /api/v1/mining/candidate-details?msg=<64-hex>&template_seq=<sequence>`
  matches both selectors against one retained template. Omitting both selects
  current offered work. An evicted or mismatched historical selector returns 404;
  missing current work returns 503. Status distinguishes `current`, `superseded`,
  `stale_parent` and `withdrawn`.
- `GET /api/v1/mining/history` returns the most recent 16 retained templates plus
  at most 128 local solution outcomes. Template retention resets on restart.
- `GET /api/v1/mining/status` is public and reports real current-template age,
  height, work ID and sequence without transaction or wallet contents. With mining
  enabled its `synced` flag is the mining-started latch, matching the candidate
  serve gate.

An `initial` template is the first emission-only publish after a new parent; its
`enriched` refresh includes selected private/public transactions and rent. The
published timestamp comes from the cache, rather than browser observation time.

## Submission history

The node atomically persists bounded local mining outcomes in
`<data_dir>/mining-history.json` with owner-only permissions. Applied-block entries
retain the candidate's actual emission, fees, rent and received tokens, so later
cache eviction and restarts do not erase that accounting. Retrying an accepted
submission for the same block does not duplicate its proceeds.

The history endpoint checks accepted block IDs against **the applied full-block
chain**, with the tip and requested heights taken from one committed database
snapshot. Each accepted entry reports canonical membership and confirmations;
reorged blocks remain visible as orphaned, with their original proceeds. A missing
chain-reader capability or unavailable height yields an unknown status, not proof
of canonical membership. This is a bounded local ledger, not an all-time wallet
balance or a complete record of blocks found by other nodes using the same key.

A history-write failure does not invalidate an already applied block. The endpoint
reports `journal_error` and retains the observation in memory for the operator to
inspect. An invalid existing journal fails startup rather than silently resetting
stored accounting.

Candidate inventories and signed private transaction bytes remain behind the
operator gate. Public status and public mempool/explorer endpoints do not publish
those contents before a block containing them is announced.

# Miner block policy

The Mining page's **Block contents policy** panel controls the transactions
this node puts in its own candidates. These are local assembly preferences;
they never relax consensus validation, script checks, output minimums, or the
network-voted block size and cost limits.

`GET /api/v1/mining/policy` reads the active policy and
`PUT /api/v1/mining/policy` replaces it. Both require the operator API key.
Writes validate the entire policy before changing it, persist it to
`mining-policy.json` in the node data directory, and retire previously offered
templates. An invalid policy answers 400; a storage failure answers 500 and
changes neither the saved nor the active policy. In-flight builds with an
older policy revision or operator queue generation cannot publish. The saved
policy overrides the TOML boot default on restart. A malformed saved file
refuses startup rather than silently mining with different preferences.
Temporary files a crash leaves beside it are removed at startup.

An example policy:

```json
{
  "rent_max_cost_basis_points": 9375,
  "rent_max_size_basis_points": 9375,
  "private_reserved_cost_basis_points": 1000,
  "private_reserved_size_basis_points": 1000,
  "required_tx_ids": [],
  "excluded_tx_ids": [],
  "required_bundles": [],
  "rent_token_policy": "preserve"
}
```

The UI displays percentages; the API uses basis points (100 equals 1%).
Boot defaults can be placed under `[mining.block_policy]` in `ergo-node.toml`.

## Budget allocation

The emission transaction and mandatory framing/cost margin are deducted
first. The rent ceiling is the lower of:

- The configured rent share of the voted block limit, minus overhead.
- The available budget after leaving room for operator work: the configured
  private share while private or required transactions are waiting, and never
  less than the measured serialized size and admission cost of the available
  required transactions and their ancestors.

Reservations keep rent from crowding out private and required work. They are
not hard caps on those lanes: after the rent prefix, required transactions,
then private transactions, and their available ancestors are selected before
ordinary public transactions. Public transactions can fill the remaining
budget. A zero reservation disables the private share; it does not exclude
private transactions, and required work is still measured. Selection
revalidates every transaction, so a requirement whose cost grew since
admission can still miss the budget and be reported. Rent claims also avoid
inputs reserved by private or required transactions.

The final fee-collection transaction is measured and validated too. Assembly
may trim transactions from the tail until the complete section fits. Required
transactions are selected first, so they are trimmed only after every
optional transaction. Candidate details contain exact retained categories,
sizes, costs and exclusion reasons from that template rather than estimates
from the live mempool.

## Required and excluded transactions

Required IDs, including every ID listed in a bundle, get priority inclusion
and never withhold work. Each requirement and its available ancestors are
selected before private and public transactions, and rent claims avoid their
inputs. Available parents are included before children; listed bundle order
is used when no dependency requires a different order. Requirements can refer
to public or private transactions.

A requirement that cannot be included is left out of that candidate, which is
still published. Candidate details list it among the exclusions with a reason
that starts with `required_`:

- `required_unavailable`: the ID is in neither the mempool nor the private
  queue, for example because it was mined, replaced or expired.
- `required_excluded_ancestor`: it depends on an excluded transaction.
- `required_` followed by an ordinary selection reason, such as
  `required_input_unavailable`, `required_input_conflict`,
  `required_consensus_validation_failed` or `required_cost_budget`: selection
  could not include it or one of its ancestors.
- `required_final_fee_or_section_budget`: it was trimmed, after every
  optional transaction, so that the fee transaction and section fit.

Bundles set an order; they are not atomic. Each member is included or
reported on its own. Initial emission-only templates are published as usual,
and requirements arrive with the enriched refresh.

Requirements remain operator policy until cleared. A requirement that has
confirmed keeps being reported, as `required_input_unavailable` while the
mempool still holds it and then as `required_unavailable`, until you remove
it from the policy.

Excluded IDs are never selected. Requirements and exclusions are compared by
decoded transaction ID, so hexadecimal case cannot bypass a contradiction.
The policy permits at most 1,024 required IDs, 1,024 excluded IDs and 128
nonempty bundles.

## Rent proceeds and tokens

Eligibility is an age/index observation, not a promise of inclusion. A claim
must resolve against the candidate's committed state and pass all rent,
reemission, output and block-budget rules. Recreated boxes preserve their
script, registers and tokens; only fully consumed boxes transfer their tokens
to the miner.

`preserve` is the default token policy. Identical recovered token IDs are
aggregated with checked amounts. A full-consume box whose assets cannot fit
the miner payout is deferred as a whole. This is deliberately conservative:
remaining eligible assets can be claimed in a later block, and no overflow
tokens are silently discarded. Existing distinct-output rent rules still
apply, including the ERG required to fund each payout's output minimum.

`burn_overflow` explicitly permits the previous behavior: recovered tokens
that exceed the payout count or serialized box-size limits are discarded.
Burns become permanent only when the candidate is mined and accepted.
The inspector derives recovered and burned token amounts from the exact
resolved rent inputs and retained outputs, and reports preservation deferrals
separately from included claims.

# Miner block policy

The Mining page's **Block contents policy** panel controls the transactions
this node puts in its own candidates. These are local assembly preferences;
they never relax consensus validation, script checks, output minimums, or the
network-voted block size and cost limits.

`GET /api/v1/mining/policy` reads the active policy and
`PUT /api/v1/mining/policy` replaces it. Both require the operator API key.
Writes validate the entire policy before changing it, persist it to
`mining-policy.json` in the node data directory, and retire previously offered
templates. In-flight builds with an older policy revision or operator queue
generation cannot publish. The saved policy overrides the TOML boot default
on restart. A malformed saved file refuses startup rather than silently
mining with different preferences.

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
- The available budget after reserving the configured private share when
  private transactions are waiting.

Reservations keep rent from crowding out private work. They are not hard caps
on the private lane: after the rent prefix, private transactions and their
available ancestors are selected before ordinary public transactions. Public
transactions can fill the remaining budget. A zero reservation disables that
additional protection; it does not exclude private transactions. Rent claims
also avoid inputs reserved by private or required transactions.

The final fee-collection transaction is measured and validated too. Assembly
may trim optional transactions from the tail until the complete section fits.
An included required transaction cannot be trimmed to make room for fees.
Candidate details contain exact retained categories, sizes, costs and exclusion
reasons from that template rather than estimates from the live mempool.

## Required and excluded transactions

Required IDs and every ID listed in a mandatory bundle must appear together
in a valid final candidate. Available parents are included before children;
listed bundle order is used when no dependency requires a different order.
Requirements can refer to public or private transactions. Missing IDs,
excluded ancestors, conflicts, failed validation or a budget that cannot fit
the whole requirement withhold a candidate. Initial emission-only templates
are disabled while requirements are present.

Requirements remain operator policy until cleared. Clear completed or stale
requirements to resume ordinary mining after those transactions confirm or
are replaced. The UI explains this behavior before saving. Use the ordinary
private queue for transactions that may wait across candidate rebuilds without
requiring the whole miner to wait.

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

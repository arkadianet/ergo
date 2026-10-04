# Mining templates and fee estimates

The Rust operator API provides full mining artifacts and request-specific transaction selection while retaining the existing block validation rules. Mining must be enabled in UTXO mode with a ready reward key. Mining endpoints require the operator `api_key`; the fee forecast is read-only. See [operating the node](operating.md) for configuration and authentication.

## Inspect the current template

```sh
curl --fail -H "api_key: $ERGO_API_KEY" \
  http://127.0.0.1:9053/api/v1/mining/template
```

The result contains `work`, `header_without_pow`, `parent_id`, `version`, ordered `transactions` (each with `id` and canonical `bytes`), `extension` key/value pairs, `ad_proofs`, and `required_transaction_ids`. All binary values use lowercase hex. `blake2b256(bytes.fromhex(header_without_pow))` equals `work.msg`; the complete response belongs to that same frozen candidate. Transactions include the emission transaction, selected transactions and any fee collection transaction.

This endpoint reads the cache and never triggers generation. `503 candidate_unavailable` means the current tip has no published candidate. Existing `GET /api/v1/mining/candidate?longpoll=<msg>` and solution submission retain their behavior.

## Require transactions in one candidate

```sh
curl --fail -H "api_key: $ERGO_API_KEY" -H 'Content-Type: application/json' \
  --data-binary @required-transactions.json \
  http://127.0.0.1:9053/api/v1/mining/candidate-with-txs
```

`required-transactions.json` has the shape `{ "transactions": ["<signed canonical transaction hex>"] }`. Signed Scala transaction JSON objects are also accepted in the array. The request accepts at most 256 transactions and 1 MiB of decoded transaction bytes; the voted block size and cost budgets remain authoritative and may reject a smaller request.

Dependencies can be submitted in either order. Required pool ancestors are included automatically; identical repeated transaction IDs appear once. Different serialized witnesses for the same requested ID are rejected. Every required transaction and ancestor is validated against the frozen upcoming-block context, before spare capacity is filled from the pool. Optional rent sweeping is omitted for this request so it cannot preempt a requested rent claim. Required transactions are never trimmed to make room for the fee transaction: the complete set either fits and validates, or the request fails with `400 bad_request`. Failure leaves both the pool and the previously served template unchanged.

Success returns a full template, publishes it into the usual bounded solution cache and wakes candidate long-pollers. It does not admit or broadcast the requested transactions. Requests are specific to the returned template; they do not establish a persistent mining policy. An ordinary background refresh may supersede it, while solutions against retained templates continue through the usual stale-parent and block-validation checks.

Only one requested build may run at a time. Another request returns `503 candidate_unavailable`; retry with backoff. Requests have a 30-second deadline. A timeout or disconnect cancels work at transaction/phase boundaries, and the worker retains its concurrency permit until it exits. A speculative AVL operation completes safely before cancellation. A tip change or persist lag returns `503`; request a fresh candidate.

## Estimate fees from current observations

```sh
curl --fail 'http://127.0.0.1:9053/api/v1/mempool/fee-estimate?target_wait_seconds=240&tx_size_bytes=1000&tx_cost_units=25000'
```

`target_wait_seconds` defaults to 120 and accepts 1–86400. `tx_size_bytes` defaults to 1000 and accepts 1–1048576. Optional `tx_cost_units` supplies the transaction's measured validation cost; omitting it leaves that transaction's own cost unknown (0), while competing pooled transactions still contribute their observed admission costs.

The forecast uses up to 32 contiguous canonical full blocks, median observed block intervals, measured transaction-section overhead and the current voted byte/cost capacity. Fee-paying transaction counts, sizes and median fee rates come from actual block contents. A same-height reorg replaces the sample window by parent ancestry; pool conflicts, replacements and other evictions never count as confirmations.

`available: false`, `confidence: "insufficient_data"` and null estimated amounts mean there is too little or stale data. At least four blocks, three valid timestamp intervals and three confirmed fee-paying transactions are required. A snapshot over 60 seconds old, a block tail behind the applied tip or a tip timestamp more than one hour old also disables the estimate.

Available results include the observed interval, projected byte/cost capacities, confirmed sample count, `recommended_fee_nano_erg`, `estimated_wait_ms`, `target_feasible` and `estimate_capped`. Amounts are exact decimal strings. Confidence is `low`, or `medium` after at least 16 blocks and 32 fee-paying confirmations. A target shorter than the observed block interval is marked infeasible. Forecasts are capped at one day.

These are capacity projections, not guaranteed confirmation deadlines. Fee competition is projected by fee per byte; actual miner ordering, transaction dependencies, cost changes during revalidation, fee-collection cost, private transactions and partial blocks can change inclusion. Pool admission costs and the current protocol budgets are inputs, not historical measured execution costs for every confirmed transaction. The observed median confirmed fee rate is reported separately from the congestion premium.

The Scala compatibility scalar routes keep their existing JSON shape: `/transactions/getFee` returns the configured relay floor when data is insufficient; `/transactions/waitTime` returns `18446744073709551615` for an unknown wait. The wait histogram assigns unknown waits to its overflow bucket. Use the operator forecast when consumers need explicit unknowns and coverage.

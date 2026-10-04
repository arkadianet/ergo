# Mining templates and fee estimates

The Rust operator API provides full mining artifacts and observed fee forecasts while retaining the existing block validation rules. Mining must be enabled in UTXO mode with a ready reward key. Mining endpoints require the operator `api_key`; the fee forecast is read-only. See [operating the node](operating.md) for configuration and authentication.

## Inspect the current template

Use the authenticated `GET /api/v1/mining/candidate-details` to inspect a retained candidate. Its `work`, `header_without_pow` and `ad_proofs` fields accompany the existing ordered transactions (with canonical bytes), extensions, votes, metrics and accounting. Binary fields are lowercase hex; the BLAKE2b-256 hash of the decoded header equals `work.msg`. Optional `msg` and `template_seq` selectors inspect the same retained snapshot, including superseded work. Serialization runs outside the cache lock using the retained `Arc`. See [block policy and candidate inspection](miner-block-policy.md).

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

# Upcoming-block context vectors

What ergo-core 6.0.7 exposes to scripts when it validates a transaction for
the block after a tip: its mempool context (`ErgoStateContext.simplifiedUpcoming()`,
used by mempool admission, its cleanup and `/transactions/check`) and a mining
candidate's (`ErgoStateContext.upcoming(...)`).

`cases.json` holds the inputs: the ten headers of the first
`../evaluator/methods.json` entry, newest first, and the same headers with the
tip's miner key replaced by 7·G. With a tip mined by the generator, the generator
as `minerPk` would not show where the value comes from. `cases.jvm.jsonl` is the
oracle's output, one object per case, in input order.

Regenerate from the repository root with the JVM toolchain loaded:

```bash
source ~/.local/kdex-toolchain/env.sh
scala-cli run scripts/reference_evaluator_oracle/UpcomingContextOracle.scala \
  --server=false --jvm system -- test-vectors/reference-6.0.7/upcoming-context/cases.json \
  > test-vectors/reference-6.0.7/upcoming-context/cases.jvm.jsonl
```

`ergo-validation/tests/it/reference_607_upcoming_context.rs` checks
`TransactionContext::mempool_upcoming` and `UPCOMING_LAST_HEADERS` against it.

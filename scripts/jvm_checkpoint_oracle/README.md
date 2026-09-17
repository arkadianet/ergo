# Checkpoint cost oracle

Uses the pinned Ergo 6.0.5 node classpath provisioned by
`python3 scripts/jvm_block_oracle/provision.py`. The reference checkout is read
only; the classpath is built inside this worktree.

```sh
python3 scripts/jvm_checkpoint_oracle/run.py test-vectors/ergo-sigma/cost-total/checkpoint-pairing.json
```

The script calls the production `ErgoState.execTransactions` for the ten frozen
mainnet transactions at 700000–700001. It records four checkpoint settings per
transaction: absent, height − 1, height, and height + 1. Both the returned cost
and the number of box lookups are observed. No interpreter or tariff is replaced.
The Rust consumer checks cost pairing for valid transactions; this does not claim
that Rust bypasses every structural/stateful check exactly as the Scala block
checkpoint path does.

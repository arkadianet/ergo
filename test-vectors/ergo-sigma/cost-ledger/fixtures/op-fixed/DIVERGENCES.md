# CreateAvlTree parser residual (OP-0xB6)

Tracking: JIT-cost conformance task 9.1-fix, deferred parser task.
Classification: rejection-order (both reject; parser arity changes failure class,
charged-to-failure cost, and cost-limit precedence).

The pinned sigma-state 6.0.2 JVM parses CreateAvlTree's four operands and rejects
execution with java.lang.RuntimeException. Rust treats 0xB6 as zero-arity and
retains an UnparsedErgoTree, rejecting with sigma.exceptions.InterpreterException.
For opb6-prefix4 the JVM evaluator failure cost is 1 block unit and Rust's is 0.
At low limits the JVM can reject with CostLimitException instead.

All 36 cases in zero-cost-rejects.json.gz carry exact observed Rust/JVM field
differences; JVM expectations are unchanged. The runner requires this DIVERGENT
ledger row and fails if the recorded differences change or disappear. This
annotation does not establish conformance or close OP-0xB6.

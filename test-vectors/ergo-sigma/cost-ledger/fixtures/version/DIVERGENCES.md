# Deferred version parser divergences

Oracle: pinned sigma-state 6.0.2, `scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala`.
Task 9.2-fix leaves VERSION-G008, VERSION-G016 and VERSION-G018 DIVERGENT for the next parser task.
Only these 14 cases have markers. The runner requires their exact differences and rejects stale markers.
`rejection-order` means both reject, but parser behavior changes which failure happens first.
The VERSION-G018 validation-settings residual also requires the settings-aware harness described in ledger.toml.

| Row | Case | Classification | Exact differences |
|---|---|---|---|
| VERSION-G016 | byindex-byte-t2-a3 | reject-valid | `{"failure_class": {"jvm": null, "rust": "java.lang.ClassCastException"}, "verdict": {"jvm": "Accept", "rust": "RejectScript"}}` |
| VERSION-G018 | function-parameter-t2-a3 | accept-invalid | `{"failure_class": {"jvm": "sigma.exceptions.InterpreterException", "rust": null}, "total_block_cost": {"jvm": 0, "rust": 1}, "verdict": {"jvm": "RejectScript", "rust": "Accept"}}` |
| VERSION-G016 | method-empty-args-t3-a3 | accept-invalid | `{"failure_class": {"jvm": "java.lang.AssertionError", "rust": null}, "verdict": {"jvm": "RejectOther", "rust": "Accept"}}` |
| VERSION-G016 | byindex-byte-t2-a3-limit7 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.CostLimitException", "rust": "java.lang.ClassCastException"}, "verdict": {"jvm": "RejectCost", "rust": "RejectScript"}}` |
| VERSION-G016 | byindex-byte-t2-a3-limit8 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.CostLimitException", "rust": "java.lang.ClassCastException"}, "verdict": {"jvm": "RejectCost", "rust": "RejectScript"}}` |
| VERSION-G016 | byindex-byte-t2-a3-limit9 | reject-valid | `{"failure_class": {"jvm": null, "rust": "java.lang.ClassCastException"}, "verdict": {"jvm": "Accept", "rust": "RejectScript"}}` |
| VERSION-G018 | function-parameter-t2-a3-limit0 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.InterpreterException", "rust": "sigma.exceptions.CostLimitException"}, "verdict": {"jvm": "RejectScript", "rust": "RejectCost"}}` |
| VERSION-G018 | function-parameter-t2-a3-limit1 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.InterpreterException", "rust": "sigma.exceptions.CostLimitException"}, "total_block_cost": {"jvm": 0, "rust": 1}, "verdict": {"jvm": "RejectScript", "rust": "RejectCost"}}` |
| VERSION-G008 | subst-sizedFalse-poolFalse-t1-a1 | accept-invalid | `{"eval_block_cost": {"jvm": 16, "rust": 18}, "total_block_cost": {"jvm": 16, "rust": 18}, "verdict": {"jvm": "RejectScript", "rust": "Accept"}}` |
| VERSION-G008 | subst-sizedTrue-poolFalse-t1-a1 | cost-only | `{"eval_block_cost": {"jvm": 18, "rust": 16}, "total_block_cost": {"jvm": 18, "rust": 16}}` |
| VERSION-G008 | subst-sizedFalse-poolFalse-t1-a1-limit17 | rejection-order | `{"failure_class": {"jvm": null, "rust": "sigma.exceptions.CostLimitException"}, "total_block_cost": {"jvm": 16, "rust": 18}, "verdict": {"jvm": "RejectScript", "rust": "RejectCost"}}` |
| VERSION-G008 | subst-sizedTrue-poolFalse-t1-a1-limit17 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.CostLimitException", "rust": null}, "total_block_cost": {"jvm": 18, "rust": 16}, "verdict": {"jvm": "RejectCost", "rust": "RejectScript"}}` |
| VERSION-G008 | subst-sizedTrue-poolFalse-t1-a1-limit18 | rejection-order | `{"failure_class": {"jvm": "sigma.exceptions.CostLimitException", "rust": null}, "total_block_cost": {"jvm": 18, "rust": 16}, "verdict": {"jvm": "RejectCost", "rust": "RejectScript"}}` |
| VERSION-G008 | subst-sizedTrue-poolFalse-t1-a1-limit19 | cost-only | `{"eval_block_cost": {"jvm": 18, "rust": 16}, "total_block_cost": {"jvm": 18, "rust": 16}}` |

# CreateAvlTree parser parity (OP-0xB6)

Resolved by task 9.1e: `fix(ser,sigma): parse CreateAvlTree with its four operands and reject it at evaluation like Scala`.

CreateAvlTree parses four generic expressions in serializer order: operationFlags,
digest, keyLength, valueLengthOpt. Its static result type is SAvlTree.
Inherited Value.eval throws java.lang.RuntimeException before evaluating children
or charging for the node (sigma-state 6.0.2 values.scala:101-102).

All 36 CreateAvlTree cases in zero-cost-rejects.json.gz compare without divergence
annotations. The regenerated JVM expectations are unchanged. Prefixes 0..9 expose
evaluator failure block costs 0,0,0,0,1,1,1,2,2,2; low limits preserve RejectCost
precedence. Full verify totals on these rejections remain unavailable.

# Per-item opcode fixtures

`scripts/gen-op-per-item.py` constructs wire bytes directly, without
an ErgoScript compiler. It never computes expectations. The context comes from
`../interpreter/p2pk.json`; all trees use version 0, activated version 3, zero
initial cost, and no proof. A block binds each target result and returns true,
so Boolean false results do not obscure successful evaluation.

## Matrix

Each opcode has grouped JSON with independently verified `cases`; empty
SigmaAnd/SigmaOr cases live in dedicated `*-empty.json` files. The shared
`manifest` hashes the ordered request/response JSONL streams. Every case has its
own request, expected verify record, length `n`, exact target/body bytes and
prefix index. The runner executes every case and includes its index in failures.
The generator refuses an empty batch or a response-count mismatch, and writes
atomically only after all JVM calls and provenance collection succeed.

For chunk size `k`, lengths are `0, 1, k−1, k, k+1, 2k+1`, with duplicates
removed. Each reachable length has ten prefix variants: zero through four empty
blocks, with or without an outer `If(true, target, SigmaProp(true))`. Empty
blocks cost 2 JIT each; the If and its Boolean constant cost 15 JIT together.
These ten offsets cover every remainder modulo ten. Expectations remain JVM
block costs; source constants explain the construction only. This makes even a
one-JIT target-cost error observable in at least one variant.

| Opcode | k | Charged quantity |
| --- | ---: | --- |
| AND | 32 | All examined elements (all true) |
| OR | 64 | All examined elements (all false) |
| XorOf | 32 | Boolean collection length |
| Xor | 128 | Equal-length byte-array operands |
| Append | 100 | Sum of both operand lengths, split across operands |
| Slice | 100 | Requested interval length; receiver deliberately empty |
| Filter, Map, Exists, ForAll, Fold | 10 | Input collection length; callbacks visit every element |
| CalcBlake2b256 | 128 | Input bytes |
| CalcSha256 | 64 | Input bytes |
| SigmaAnd, SigmaOr | 1 | Number of expression children |
| AtLeast | 5 | Input proposition count; bound zero |
| SubstConstants | 1 | Original constant pool size; replacement lists empty |
| BlockValue | 10 | Number of bindings |
| SigmaPropBytes | 1 | Proposition nodes: 1, 2, 3 |

AND/OR use packed Boolean constants. Fold takes one tuple argument and returns a
Boolean constant. SigmaAnd/Or use expression children; AtLeast uses a constant
collection of propositions. SubstConstants receives a hand-serialized segregated
tree with an unused Boolean pool, distinguishing pool size from replacement
count. SigmaPropBytes receives unsimplified wire constants: a trivial proposition
or a unary/binary CAND containing trivial propositions.

## Unreachable requested cases

SigmaPropBytes cannot receive a proposition with zero nodes. Scala
`core/shared/src/main/scala/sigma/data/SigmaBoolean.scala` gives trivial and DLog
leaves size 1, DHT leaves size 4, and conjectures one plus their children's sizes.
Its n=0 and k−1 cases therefore cannot be constructed; no zero-node evidence is
claimed. The row closes over all reachable requested node counts (1, 2, 3).

DeserializeContext and DeserializeRegister declare `PerItemCost(1,10,128)` in
`data/shared/src/main/scala/sigma/ast/transformers.scala:558,571`, but inherit
`Value.eval`; they have no evaluator implementation invoking that descriptor.
`Interpreter.deserializeMeasured` parses the embedded expression, then charges
2 block units per byte and substitutes the expression before evaluation.
Register substitution uses the same method through `ErgoLikeInterpreter`.
Successful full-verify fixtures would exercise interpreter substitution, not
these OP descriptors. Empty embedded bytes also cannot deserialize an expression.
These OP rows remain OPEN. L1 JVM descriptor extraction and direct `cost(n)`
boundary tests can close the declared descriptor obligation. Task 3.4e owns the separate embedded-script accounting obligation.

## Reproduce

```sh
python3 scripts/gen-op-per-item.py
for fixture in test-vectors/ergo-sigma/cost-ledger/fixtures/op-per-item/*.json.gz; do
    scripts/gen-cost-fixture.sh "$fixture"
done
cargo test -p ergo-sigma --test it cost_ledger_fixtures -- --nocapture
python3 scripts/cost-ledger.py render
python3 scripts/cost-ledger.py check
```

The constructor preserves expectations only when every request is unchanged.
Fresh or changed requests omit `expected`, so the normal runner fails until JVM
regeneration. The JVM generator also continues to support the original single
request fixture shape used by the other families.

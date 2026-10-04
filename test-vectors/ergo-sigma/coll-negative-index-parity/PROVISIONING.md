# Source-derived models for the Coll negative-index family

This tree holds the durable re-extraction artifact for the Rust
sigma evaluator's `Coll.patch`, `Coll.updated`, `Coll.indexOf`, and
`Slice` semantics at negative-index boundaries. The Rust impl matches
Scala 2.13.16 stdlib `scala-library`; the expected outputs pinned in
`ergo-sigma/src/evaluator/tests.rs` (`coll_patch_*`,
`coll_indexof_negative_from_*`, `slice_negative_*`, `slice_until_*`
test arms) are bytecode-decoded from the cached JAR, not inferred
from prose.

## Re-extraction recipe

```bash
# 1. Locate the cached scala-library JAR (Coursier puts it here on
#    Windows; on Linux it's typically ~/.cache/coursier/v1/...).
JAR=$(find ~/AppData/Local/Coursier ~/.cache/coursier -name \
  'scala-library-2.13.*.jar' 2>/dev/null | head -1)

# 2. Extract the two backing classes.
mkdir -p /tmp/scala-bytecode
( cd /tmp/scala-bytecode && jar xf "$JAR" \
    scala/collection/ArrayOps\$.class \
    scala/collection/immutable/StrictOptimizedSeqOps.class )

# 3. Disassemble Coll.patch (Array-backed) and Vector.patch (default
#    impl Vector inherits).
javap -p -c /tmp/scala-bytecode/scala/collection/ArrayOps\$.class \
  | awk '/public final <B, A> java.lang.Object patch\$extension/,/^  public/' \
  | head -200
javap -p -c \
  /tmp/scala-bytecode/scala/collection/immutable/StrictOptimizedSeqOps.class \
  | awk '/public default <B> CC patch\(int,/,/^  public/' | head -120
```

The chunk1/chunk2 model in `Oracle.java` is a transcription of the decoded
algorithm. It loads neither scala-library nor the Rust evaluator. Rerunning
it checks agreement between the saved Java models; it cannot detect changes
in either implementation. After an implementation or dependency change,
repeat the disassembly and compare actual pinned Scala and Rust calls before
making a runtime parity claim.

## What the oracle covers

| Method            | Negative-input semantics                       |
|-------------------|------------------------------------------------|
| `Coll.updated`    | Throws `IndexOutOfBoundsException`             |
| `Coll.patch`      | Both `from < 0` and `replaced < 0` clamp to 0  |
| `Coll.indexOf`    | `from < 0` clamps via `math.max(from, 0)`      |
| `Slice` / `Coll.slice` | Both bounds clamp via `Array.slice`       |

`Oracle.java` re-derives all four method semantics in one program:
- `runPatch()` exercises the chunk1/chunk2 model (12 cases)
- `runUpdated()` exercises the `Array.updated` throw + happy path
  (8 cases, including i32 extremes)
- `runIndexOf()` exercises `math.max(from, 0)` clamp (7 cases)
- `runSlice()` exercises `Array.slice` two-sided clamp + the
  `if (hi > lo)` empty gate (9 cases)

The test arms in `ergo-sigma/src/evaluator/tests.rs` (`coll_patch_*`,
`coll_updated_*`, `coll_indexof_*`, `slice_*`) mirror this matrix.
`Oracle.java` plus the disassembly recipe above is what makes those
arms re-derivable rather than locally reasoned.

## Build + run

```bash
cd test-vectors/ergo-sigma/coll-negative-index-parity
javac Oracle.java   # requires JDK 11+
java Oracle
```

Expected last line: `ALL CASES MATCH` (36 cases across 4 methods).
A divergent run means the two saved model implementations disagree. A
successful run provides no evidence that current Scala or Rust code was
executed. Keep real implementation regressions separate from model checks.

## Why no JSON fixture

This artifact stores models rather than runtime input/output captures. Its
36 cases sample the listed boundary inputs; they do not prove exhaustive
coverage of all i32 pairs. Independent runtime fixtures are required for any
claim that a production refactor or Scala dependency update preserves behavior.

## Cost evidence

This model executes no interpreter and observes no JIT costs. Current Rust
`patch` and `updated` use their per-item tariffs; `Slice` has its own cost
path. Consult the named tests and independent captures in
[`../cost-ledger/LEDGER.md`](../cost-ledger/LEDGER.md) for each cost obligation.
Do not infer cost closure from `ALL CASES MATCH`.

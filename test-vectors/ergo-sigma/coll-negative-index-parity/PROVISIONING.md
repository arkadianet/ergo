# Scala-parity oracle for Coll negative-index family

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

The chunk1/chunk2 model in `Oracle.java` is the decoded form. Re-run
`Oracle.java` after any scala-library bump to verify the algorithm
has not drifted.

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
A divergent run means either (a) one of the underlying Scala
algorithms changed in a newer scala-library release, or (b) the
corresponding Rust arm was refactored. Either way, stop and re-decode.

## Why no JSON fixture

Unlike the cost-total fixtures in `../cost-total/`, this tree pins
**algorithmic** parity rather than specific input/output byte rows.
The 36 cases in `Oracle.java` cover every i32-boundary class across
all four methods (happy paths, negative single args, negative pairs,
arg > length, arg < -length, i32::MAX, i32::MIN); adding more rows
would not improve coverage of the underlying algorithms. A future
PR that also pins per-test JSON rows is welcome but not load-bearing.

## Residual gaps (out of scope for the negative-index sweep)

- `Coll.patch` / `Coll.updated` JIT cost: the Rust arms charge the
  fixed `0xDC` MethodCall opcode cost
  (`cost_table.rs::opcode_cost(0xDC) = fixed(4)`) regardless of
  `coll.length`. Scala `methods.scala::patch_eval` /
  `updated_eval` declare `PerItemCost(...)` and charge over
  `xs.length + patch.length` / `coll.length` respectively. Closing
  this requires its own Scala-anchored cost-oracle fixture
  (re-extract via `ErgoTreeEvaluator` cost trace on a mainnet-synced
  Scala node) plus a mainnet scan to bound the consensus impact
  before the fix lands. Not bundled here.
- `Slice` JIT cost: `eval_slice` charges over `sliced.len()` post-
  clamp; Scala `Slice.eval` charges over `Math.max(0, until - from)`
  pre-clamp. Same shape of follow-up as above.

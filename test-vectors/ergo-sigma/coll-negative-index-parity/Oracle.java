/*
 * Re-extractable Scala-parity oracle for sigma evaluator Coll family.
 *
 * Mirrors three Scala 2.13 algorithms whose bytecode is decoded from
 * `scala-library-2.13.16.jar`:
 *   - `scala.collection.ArrayOps$.patch$extension`   (Coll.patch backing)
 *   - `scala.collection.immutable.StrictOptimizedSeqOps.patch` (Vector.patch)
 *   - `scala.collection.ArrayOps.slice`              (Coll.slice / Slice op)
 *
 * The `Coll.patch` formula was decoded from `javap -p -c
 * scala/collection/ArrayOps$.class` on the cached coursier JAR. The
 * bytecode locals map: 1=from, 3=replaced, 4=builder, 5=counter,
 * 7=knownSize, 8=clampedReplaced, 9=chunk1, 10=chunk2. The decoded
 * algorithm is:
 *
 *     chunk1            = if (from > 0) min(from, xs.length) else 0
 *     clampedReplaced   = if (replaced < 0) 0 else replaced
 *     chunk2            = xs.length - chunk1 - clampedReplaced
 *     if (chunk2 > 0) suffix = xs[xs.length - chunk2 .. xs.length] else []
 *     result            = xs[0..chunk1] ++ patch ++ suffix
 *
 * Both negative `from` and negative `replaced` clamp to 0; neither
 * throws `IndexOutOfBoundsException`. `Coll.updated` is the only Coll
 * method whose Scala backing (`Array.updated`) throws.
 *
 * The Rust impl at `ergo-sigma/src/evaluator/opcodes/method_call.rs`
 * `(12, 19)` arm uses `from.max(0) as usize` + `replaced.max(0) as
 * usize` + `coll.splice(from.min(n)..(from + replaced).min(n), patch)`,
 * which is byte-identical to the Scala chunk1/chunk2 model for every
 * i32 input pair. This program prints both formulas side by side so a
 * future operator can verify continuity if either side ever changes.
 *
 * USAGE
 *   javac Oracle.java
 *   java Oracle
 *
 * Re-extraction of the underlying bytecode (optional, to verify the
 * Scala side has not changed in a newer scala-library):
 *   JAR=~/AppData/Local/Coursier/cache/v1/.../scala-library-2.13.16.jar
 *   jar xf "$JAR" scala/collection/ArrayOps$.class
 *   javap -p -c scala/collection/ArrayOps$.class | \
 *     awk '/patch\$extension/,/^  public/' | head -200
 *
 * Scala-source reference (algorithm parity at the spec level):
 *   reference/sigmastate-interpreter/core/shared/src/main/scala/sigma/
 *     data/CollsOverArrays.scala:94-98 (Coll.patch -> Array.patch)
 *   reference/sigmastate-interpreter/data/shared/src/main/scala/sigma/
 *     ast/transformers.scala:86-103 (Slice.eval -> Array.slice)
 *   reference/sigmastate-interpreter/data/shared/src/main/scala/sigma/
 *     ast/methods.scala:1080-1100 (indexOf_eval, math.max(from, 0))
 */
public class Oracle {
    public static void main(String[] args) {
        boolean allMatch = true;
        allMatch &= runPatch();
        allMatch &= runUpdated();
        allMatch &= runIndexOf();
        allMatch &= runSlice();
        System.out.println(allMatch
            ? "\nALL CASES MATCH"
            : "\nDIVERGENCE FOUND — re-run the bytecode decode");
        if (!allMatch) System.exit(1);
    }

    static boolean runPatch() {
        int[] xs = {1, 2, 3, 4, 5};
        int[] patch = {99};
        int[][] cases = {
            {0, 2}, {-1, 2}, {0, -1}, {2, -1},
            {10, 2}, {2, 100}, {Integer.MAX_VALUE, 1},
            {Integer.MIN_VALUE, 10}, {2, Integer.MAX_VALUE},
            {-5, 0}, {0, 0}, {5, 5},
        };
        boolean all = true;
        System.out.println("=== Coll.patch (negative-index parity) ===");
        for (int[] c : cases) {
            int from = c[0], replaced = c[1];
            int[] s = scalaArrayOpsPatch(xs, from, patch, replaced);
            int[] r = rustEvaluatorPatch(xs, from, patch, replaced);
            boolean match = java.util.Arrays.equals(s, r);
            all &= match;
            System.out.printf(
                "%s from=%-11d replaced=%-11d | scala=%-30s rust=%s%n",
                match ? "OK  " : "FAIL",
                from, replaced,
                java.util.Arrays.toString(s),
                java.util.Arrays.toString(r));
        }
        return all;
    }

    static boolean runUpdated() {
        int[] xs = {1, 2, 3};
        int[][] cases = {
            {0, 99},           // valid head
            {1, 99},           // valid middle
            {2, 99},           // valid tail
            {-1, 99},          // negative -> throw
            {3, 99},           // == length -> throw
            {100, 99},         // > length -> throw
            {Integer.MIN_VALUE, 99},
            {Integer.MAX_VALUE, 99},
        };
        boolean all = true;
        System.out.println("\n=== Coll.updated (throw on out-of-range) ===");
        for (int[] c : cases) {
            int idx = c[0], elem = c[1];
            Result s = scalaArrayUpdated(xs, idx, elem);
            Result r = rustEvaluatorUpdated(xs, idx, elem);
            boolean match = s.equals(r);
            all &= match;
            System.out.printf(
                "%s idx=%-12d elem=%-4d | scala=%-30s rust=%s%n",
                match ? "OK  " : "FAIL",
                idx, elem,
                s.toString(),
                r.toString());
        }
        return all;
    }

    static boolean runIndexOf() {
        int[] xs = {1, 2, 3};
        int needle = 2;
        int[] fromVals = {0, -1, -100, Integer.MIN_VALUE, 1, 2, 5};
        boolean all = true;
        System.out.println("\n=== Coll.indexOf (negative from clamps to 0) ===");
        for (int from : fromVals) {
            int s = scalaIndexOf(xs, needle, from);
            int r = rustEvaluatorIndexOf(xs, needle, from);
            boolean match = s == r;
            all &= match;
            System.out.printf(
                "%s needle=%d from=%-12d | scala=%-4d rust=%d%n",
                match ? "OK  " : "FAIL",
                needle, from, s, r);
        }
        return all;
    }

    static boolean runSlice() {
        int[] xs = {1, 2, 3, 4, 5};
        int[][] cases = {
            {0, 3}, {-1, 3}, {0, -1}, {4, 2},
            {0, 5}, {0, 100}, {-100, 100},
            {Integer.MIN_VALUE, Integer.MAX_VALUE},
            {Integer.MAX_VALUE, Integer.MAX_VALUE},
        };
        boolean all = true;
        System.out.println("\n=== Slice (clamp + empty-when-inverted) ===");
        for (int[] c : cases) {
            int from = c[0], until = c[1];
            int[] s = scalaArraySlice(xs, from, until);
            int[] r = rustEvaluatorSlice(xs, from, until);
            boolean match = java.util.Arrays.equals(s, r);
            all &= match;
            System.out.printf(
                "%s from=%-12d until=%-12d | scala=%-22s rust=%s%n",
                match ? "OK  " : "FAIL",
                from, until,
                java.util.Arrays.toString(s),
                java.util.Arrays.toString(r));
        }
        return all;
    }

    // Simple Optional-like carrier so both Scala throw / Rust throw and
    // normal returns can be compared in one shape.
    static final class Result {
        final boolean threw;
        final int[] coll;
        Result(boolean threw, int[] coll) { this.threw = threw; this.coll = coll; }
        static Result thrown() { return new Result(true, null); }
        static Result ok(int[] c) { return new Result(false, c); }
        @Override public String toString() {
            return threw ? "THROW (out of bounds)" : java.util.Arrays.toString(coll);
        }
        @Override public boolean equals(Object o) {
            if (!(o instanceof Result)) return false;
            Result other = (Result) o;
            return threw == other.threw && java.util.Arrays.equals(coll, other.coll);
        }
        @Override public int hashCode() {
            return java.util.Objects.hash(threw, java.util.Arrays.hashCode(coll));
        }
    }

    /**
     * Scala 2.13.16 `mutable.ArrayOps.patch$extension`, bytecode-decoded.
     * Both negative `from` and negative `replaced` clamp to 0.
     */
    static int[] scalaArrayOpsPatch(int[] xs, int from, int[] other, int replaced) {
        int chunk1 = (from > 0) ? Math.min(from, xs.length) : 0;
        int clampedReplaced = (replaced < 0) ? 0 : replaced;
        int chunk2 = xs.length - chunk1 - clampedReplaced;
        java.util.ArrayList<Integer> out = new java.util.ArrayList<>();
        for (int i = 0; i < chunk1; i++) {
            out.add(xs[i]);
        }
        for (int v : other) {
            out.add(v);
        }
        if (chunk2 > 0) {
            for (int i = xs.length - chunk2; i < xs.length; i++) {
                out.add(xs[i]);
            }
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Mirror of the Rust `(12, 19)` arm: `n.max(0) as usize` clamps
     * plus `Vec::splice(start..end, patch)` where start =
     * `from.min(len)`, end = `(from + replaced).min(len)`.
     */
    static int[] rustEvaluatorPatch(int[] xs, int from, int[] patch, int replaced) {
        long fromU = Math.max(0, from);
        long replacedU = Math.max(0, replaced);
        long n = xs.length;
        long start = Math.min(fromU, n);
        long end = Math.min(fromU + replacedU, n);
        java.util.ArrayList<Integer> out = new java.util.ArrayList<>();
        for (long i = 0; i < start; i++) {
            out.add(xs[(int) i]);
        }
        for (int v : patch) {
            out.add(v);
        }
        for (long i = end; i < n; i++) {
            out.add(xs[(int) i]);
        }
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Scala `Array[A].updated(idx, elem)`. Throws on idx < 0 || idx >=
     * length (per JDK's `Array.updated` which underlies it).
     */
    static Result scalaArrayUpdated(int[] xs, int idx, int elem) {
        if (idx < 0 || idx >= xs.length) return Result.thrown();
        int[] out = xs.clone();
        out[idx] = elem;
        return Result.ok(out);
    }

    /**
     * Mirror of the Rust `(12, 20)` arm with the explicit
     * `if idx_i32 < 0 || idx_i32 as usize >= n` gate.
     */
    static Result rustEvaluatorUpdated(int[] xs, int idx, int elem) {
        if (idx < 0 || idx >= xs.length) return Result.thrown();
        int[] out = xs.clone();
        out[idx] = elem;
        return Result.ok(out);
    }

    /**
     * Scala `indexOf_eval` per
     * `data/shared/.../ast/methods.scala:1080-1100`:
     *   `val start = math.max(from, 0)`
     *   loop from start, return first matching index or -1.
     */
    static int scalaIndexOf(int[] xs, int needle, int from) {
        int start = Math.max(from, 0);
        for (int i = start; i < xs.length; i++) {
            if (xs[i] == needle) return i;
        }
        return -1;
    }

    /**
     * Mirror of the Rust `(12, 26)` arm: `v.max(0) as usize` for
     * `from`, then iterate with `.skip(from)`.
     */
    static int rustEvaluatorIndexOf(int[] xs, int needle, int from) {
        long fromU = Math.max(0, from);
        for (long i = fromU; i < xs.length; i++) {
            if (xs[(int) i] == needle) return (int) i;
        }
        return -1;
    }

    /**
     * Scala `Array.slice(from, until)`:
     *   `lo = math.max(from, 0)`
     *   `hi = math.min(math.max(until, 0), xs.length)`
     *   `if (hi > lo) copyOfRange(xs, lo, hi) else new Array[A](0)`
     */
    static int[] scalaArraySlice(int[] xs, int from, int until) {
        int lo = Math.max(from, 0);
        int hi = Math.min(Math.max(until, 0), xs.length);
        if (hi > lo) {
            return java.util.Arrays.copyOfRange(xs, lo, hi);
        }
        return new int[0];
    }

    /**
     * Mirror of `eval_slice` in `evaluator/opcodes/collection.rs`:
     * both bounds clamped via `v.max(0) as usize`, then capped at
     * `len`, then `items.skip(from).take(until - from)` when
     * `from <= until` else empty.
     */
    static int[] rustEvaluatorSlice(int[] xs, int from, int until) {
        long fromU = Math.max(0, from);
        long untilU = Math.max(0, until);
        long len = xs.length;
        long lo = Math.min(fromU, len);
        long hi = Math.min(untilU, len);
        if (lo <= hi) {
            int[] out = new int[(int) (hi - lo)];
            for (long i = 0; i < (hi - lo); i++) {
                out[(int) i] = xs[(int) (lo + i)];
            }
            return out;
        }
        return new int[0];
    }
}

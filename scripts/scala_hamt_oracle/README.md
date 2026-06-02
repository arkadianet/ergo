# Scala 2.12 HAMT oracle extractor

A small Java program that extracts `scala.collection.immutable.HashMap[Byte, Int]`
iteration order from the real Scala 2.12 standard library, used to oracle-verify
`ergo-ser/src/scala_hamt.rs` against the Scala consensus reference.

## Why

The Rust HAMT port in `ergo-ser/src/scala_hamt.rs` reproduces Scala 2.12's
`HashTrieMap` iteration order so `ContextExtension` serialization stays Scala-
parity for `≥ 5` entries (see `docs/parity-checklist.md` §4.3). The algorithm
itself is documented in `scala_hamt.rs` with the Scala 2.12 source quoted, but
a self-derived test oracle was the only verification — Codex review on commit
`76f0305` flagged this as a residual gap.

This script closes that gap by extracting **real Scala-execution-derived**
vectors and committing them as expected outputs in the Rust test suite. The
result: every change to the Rust algorithm is checked against what Scala's
own `HashTrieMap` actually produces, not against what we *thought* it would
produce.

## How to run

You need a JDK 11+ on PATH and a Scala 2.12 `scala-library` JAR. Maven Central
hosts these; fetch one (any 2.12.x patch is acceptable — the `improve` and
HAMT iteration are stable across patches):

```bash
curl -sSL -o scala-library-2.12.18.jar \
  https://repo1.maven.org/maven2/org/scala-lang/scala-library/2.12.18/scala-library-2.12.18.jar

javac -cp scala-library-2.12.18.jar ExtractHamtVectors.java
java  -cp 'scala-library-2.12.18.jar;.' ExtractHamtVectors   # Windows path sep
# OR
java  -cp 'scala-library-2.12.18.jar:.' ExtractHamtVectors   # POSIX path sep
```

Output: one line per keyset, of the form `[key1, key2, ...] -> [order1, order2, ...]`.

## Provenance

These keysets are pinned in `ergo-ser/src/scala_hamt.rs::tests` as
`hamt_order_scala_oracle_*` cases. If you add a new keyset to the test suite,
add it to the `sets` array in `ExtractHamtVectors.java`, re-run, and commit
the new expected output alongside the test.

Algorithm source in Scala: `scala.collection.immutable.HashMap.improve` (Scala
2.12), with `HashTrieMap` recursing on 5-bit chunks of the improved hash
starting from the LSB. The Java entry-point uses Scala's `+` operator (which
appears as `$plus` from Java due to Scala name mangling) to insert entries;
the underlying `HashMap` factory switches from `Map4` to `HashTrieMap` at 5
entries automatically.

## Verification cycle

If a test in `scala_hamt.rs::tests::hamt_order_scala_oracle_*` ever fails:

1. Re-run the extractor with the failing keyset.
2. If Scala output matches the Rust output, the test fixture itself is stale.
3. If Scala output differs from the Rust output, the Rust `scala_212_improve`
   or `scala_212_hamt_sort_key` has drifted from Scala 2.12 — root-cause
   before changing anything.

The extractor is intentionally kept under `scripts/` rather than wired into
`cargo test` because it requires a JVM + Scala JAR; we don't want CI to depend
on a JDK install for what is a one-shot oracle generation.

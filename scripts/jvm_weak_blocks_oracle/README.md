# Scala weak-blocks oracle: provisioning

This directory builds a pinned Scala reference for the `weak-blocks` (input
blocks / subblocks) feature branch and exports its Java classpaths, so later
tasks in this port can run the real Scala node code offline as an oracle for
the Rust port, without depending on a live node or a shared build cache.

## Pinned commits

- `ergo` (ergoplatform/ergo): `31a8de804f7328704f2753a1cf151dda8f64689f`
- `sigma-state` fork (ScorexFoundation/sigmastate-interpreter):
  `368a860be033af94aa14895381f42099b3646db6`, published locally as
  `6.0.5-22-368a860b-SNAPSHOT`

The ergo `weak-blocks` branch pins this exact sigma-state SNAPSHOT version, so
`provision.py` builds and `+publishLocal`s the sigma-state fork itself before
building ergo — the published jars are not available from any public
repository.

## Run

From the Rust worktree root, with sbt, scala-cli, and Java 17:

```sh
python3 scripts/jvm_weak_blocks_oracle/provision.py
```

This clones both repos into `.work/` (git worktrees, not touched by hand),
checks out the pinned commits, `+publishLocal`s sigma-state under
`~/.ivy2/local/org.scorexfoundation`, and exports the ergo build's `Runtime`
and `Test` classpaths via `sbt export`.

Reused checkouts under `.work/` are hard-reset and cleaned
(`git reset --hard <pinned commit> && git clean -fdx`) before every build, and
the checkout is verified clean (`git status --porcelain --untracked-files=all`
empty) after that reset. This guards against local edits or leftover
untracked/ignored build artifacts from a prior run silently riding along with
the pinned commit — the manifest's `ergo_commit`/`sigma_commit` only mean
anything if what actually got built is byte-for-byte the pinned commit's tree.

If `sbt +publishLocal` fails cross-building sigma-state for Scala 2.11 (the
ergo build only consumes 2.12 and 2.13), retry with:

```sh
sbt -batch 'set ThisBuild / version := "6.0.5-22-368a860b-SNAPSHOT"' \
    'set crossScalaVersions := Seq("2.12.20", "2.13.16")' +publishLocal
```

and record that this workaround was used.

## Outputs

- `.work/classpath` — one line, the ergo build's `Runtime / fullClasspath`.
  Kept as the Runtime-scope record and used by the smoke test below; **no
  vector is generated from it** (see below).
- `.work/test-classpath` — one line, the ergo build's `Test / fullClasspath`.
  `gen.py` runs **every** subcommand on this one.
- `.work/manifest.json` — `{ "ergo_commit", "sigma_commit", "sigma_version",
  "sigma_artifacts" }`, where `sigma_artifacts` maps each published sigma-state
  jar's filename to its SHA-256, so a stale or mismatched local publish is
  detectable.

Smoke-test the exported classpath:

```sh
CP=$(cat scripts/jvm_weak_blocks_oracle/.work/classpath)
scala-cli --skip-cli-updates run --scala 2.12.20 --classpath "$CP" \
  -e 'println(org.ergoplatform.network.Version.SubblocksVersion)'
# => 6.5.0
```

## Regenerating oracle vectors

Once provisioned, regenerate vectors with:

```sh
python3 scripts/jvm_weak_blocks_oracle/gen.py
```

(`gen.py` is added by Task 2 of this port.)

### Why every vector runs on the Test classpath

`WeakBlocksOracle.scala` is a single compilation unit, and the
`input_block_validation` subcommand (Task 9) builds its fixture from ergo's own
Test-scope helpers — `ValidBlocksGenerators`, `ErgoCoreTestConstants`,
`ErgoNodeTestConstants`. The file therefore only compiles against
`.work/test-classpath`, so `gen.py` uses that classpath for all subcommands
rather than splitting the harness across two source files. The Test classpath
is a superset of the Runtime one, so this changes nothing about what the
runtime-scope vectors observe (verified: regenerating them after the switch
changes only their manifest lines).

`input_block_validation` additionally runs with the working directory set to
`.work/source`, because `ErgoNodeTestConstants.initSettings` reads
`src/test/resources/application.conf` by a relative path.

## Moving the pins

Moving either pin is a deliberate spec change; refresh every vector and record the new manifest.

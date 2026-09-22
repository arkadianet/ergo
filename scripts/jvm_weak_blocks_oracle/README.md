# Scala weak-blocks oracle: provisioning

This directory builds a pinned Scala reference for the `weak-blocks` (input
blocks / subblocks) feature branch and exports its Java classpaths, so later
tasks in this port can run the real Scala node code offline as an oracle for
the Rust port, without depending on a live node or a shared build cache.

## Pinned commits

- `ergo` (ergoplatform/ergo): `62c10315e1ebcac4480dba6bacdc2100a38119e5`
  (the M4 pin, `weak-blocks` after master merged 6.0.6; it replaced
  `31a8de804f7328704f2753a1cf151dda8f64689f`, and every vector payload except
  `input_block_validation`'s fixture bytes was byte-identical across the move)
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

This clones both repos into `.work/`, checks out the pinned commits,
`+publishLocal`s sigma-state under `~/.ivy2/local/org.scorexfoundation`, and
exports the ergo build's `Runtime` and `Test` classpaths via `sbt export`.

### One build per work directory (M4)

M4 measures one upstream patch at a time, so several builds live side by side
and every flag is explicit:

```sh
python3 scripts/jvm_weak_blocks_oracle/provision.py \
  --ergo-source ~/coding/development/arkadianet/ergo-scala \
  --ergo-ref matrix/F16-input-block-routes \
  --work-dir <root>/.work-F16 --sigma-reuse
```

- `--ergo-source` may be a git URL (cloned) or a LOCAL checkout, in which case
  a detached `git worktree` is added at `--ergo-ref`. A worktree because the
  fork's patch branches all live in one checkout, and because another session
  works in that checkout directly.
- Nothing is ever `git clean`ed. A provisioned build's untracked content is its
  compiled output: deleting it would throw away the incremental state a patch
  cycle depends on, and could delete the build a running devnet is using
  (spec §7a, "artifacts are immutable while a devnet runs"). Tracked files are
  still asserted clean after the checkout, which is what "the pinned ref is
  what got built" actually requires.
- `--sigma-reuse` skips the sigma `publishLocal` only when the jars already in
  `~/.ivy2/local` hash EXACTLY the same as the ones a recorded manifest was
  built against. A jar with the right name is not evidence.

`scripts/devnet-matrix/builds.toml` lists the work directories and the names
(`stock`, `F16`, `F12F05`, `F14`, `F13`, `F04`, `F11`, `all`) that
`campaign.py --build` accepts; `python3 scripts/devnet-matrix/builds.py
--verify` checks each one against its manifest.

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
- `.work/manifest.json` — `{ "ergo_source", "ergo_ref", "ergo_commit",
  "sigma_commit", "sigma_version", "sigma_artifacts", "app_version",
  "class_dir_sha256" }`. `sigma_artifacts` maps each published sigma-state
  jar's filename to its SHA-256, so a stale or mismatched local publish is
  detectable. `class_dir_sha256` is the build's IDENTITY: the SHA-256 over the
  sorted `<project>/<path>` plus content of every class file on the exported
  runtime classpath. A devnet role refuses a build that no longer reproduces
  it, because a number attributed to the wrong build is worse than no number.
  A manifest written before that field existed is tolerated — the hash is
  computed on first use and cached in a `<work-dir>.computed.json` SIDECAR,
  never written inside the immutable build directory.

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
WEAK_BLOCKS_ORACLE_WORK=<the build's work dir> \
  python3 scripts/jvm_weak_blocks_oracle/gen.py [vector...] [--seed N]
```

Generation is SEEDED (`--seed`, default 1600000000000) and therefore
reproducible: regenerating at the same ergo commit produces byte-identical
payloads. Without the seed, `ValidBlocksGenerators.validFullBlock` took its
first block's timestamp from the wall clock and every `input_block_validation`
fixture — header ids, the scripts naming them, the boxes holding those
scripts, the state root — moved on every run, so a vector diff could not tell
a re-pin from a re-run. Changing the seed rewrites those fixtures and nothing
else; it is part of the vectors, and the value is recorded in each vector's
manifest block.

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

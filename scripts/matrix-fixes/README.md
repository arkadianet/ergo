# Matrix (input blocks): Scala gate

Task 1 of Plan 3 (M4 upstream patch set). Controller destination:
`scripts/matrix-fixes/scala-gate.sh` and `scripts/matrix-fixes/README.md` in the Rust worktree.
No commit was made and no tracked Scala worktree files were changed.

## Usage

Requires Bash, Python 3, Java, sbt on PATH, and provisioned dependencies.

```bash
./scala-gate.sh /home/rkadias/coding/development/arkadianet/ergo-scala-wt-m4   ergoCore 'org.ergoplatform.network.InputBlockMessageSpecsSpec'
```

The executable exports `SIGMASTATE_VERSION=6.0.5-22-368a860b-SNAPSHOT` and starts
exactly ONE sbt process with these arguments, in the specified worktree:

```bash
sbt -batch "++2.12.20" "<proj>/compile" "<proj>/Test/testOnly <patterns>"   "++2.13.18" "<proj>/compile" "<proj>/Test/testOnly <patterns>"
```

Quote space-separated fully qualified spec names or wildcard patterns. Extra sbt
commands and ScalaTest runner options are rejected. Output streams to stdout;
redirect both streams to preserve evidence. No log file is silently overwritten by
the wrapper. It sets JVM logging properties to disable ANSI/supershell output and
`sbt.server.autostart=false`. It does not launch a node or network service.

Four successful sbt task completions, confirmations of both Scala switches, nonzero
aggregate `Tests: succeeded N` counts in each test phase, and sbt exit zero are required.
Any `[error]`, failed test, aborted suite, missing completion, or zero test count
returns 1. ScalaTest summaries are assigned to the test task between consecutive
compile/test completion records; counts cannot carry over between Scala versions.
The summary format is:

```text
gate: 2.12 compile Xs tests Ys | 2.13 compile Xs tests Ys
```

Task times are sbt's integer `Total time: N s` wall times. The tests task includes
Test compilation and setup; it is not just ScalaTest execution time. A separate
`wall=...s` measures total sbt subprocess time including launch and cross-version
reloads. Unfinished tasks show `n/a` in place of a number. The wrapper deliberately
fails closed on unrecognized/missing task or ScalaTest summaries.

## Project IDs and cross versions

Read from `build.sbt:7–9,229–351`; shared `scalaVersion` is 2.12.20 (`build.sbt:14`).

| sbt project ID | Directory | Published name | Declared crossScalaVersions |
| --- | --- | --- | --- |
| `avldb` | `avldb/` | `avldb` | `Seq(scala213, scalaVersion.value, scala211)` = initially 2.13.18, 2.12.20, 2.11.12 |
| `avldb_benchmarks` | `avldb/benchmarks/` | `avldb-benchmarks` | No explicit declaration; sbt default follows scalaVersion (initially 2.12.20) |
| `ergoCore` | `ergo-core/` | `ergo-core` | Same explicit three-version sequence |
| `ergoWallet` | `ergo-wallet/` | `ergo-wallet` | Same explicit three-version sequence |
| `ergo` | `.` (root/node) | `ergo` | No explicit declaration; sbt default follows scalaVersion (initially 2.12.20) |

There is no project ID `root`, `ergo-core`, or `ergo-wallet` in this build. Use
`ergo`, `ergoCore`, and `ergoWallet` respectively. The separate wallet build file
is not the project-ID declaration for this multi-project build.

**Use this two-version gate only for projects declaring both requested versions.**
Plain `++2.13.18` can exclude projects without that cross version; a global switch
message alone does not prove the root/node project switched. The required wrapper
command sequence does not force excluded projects. For a root compatibility probe,
use `++2.13.18!` and `ergo/compile` separately. Do not interpret a root wrapper run
as proof of a Scala 2.13 node build. Runtime `show .../crossScalaVersions` could not
be collected here; the table distinguishes explicit source declarations from defaults.

## Baseline findings

**Build baseline is blocked by the execution sandbox, not an observed Scala compile
failure. Neither version reached compilation or test execution.** Consequently this
Task 1 delivery has no passing two-version baseline or measured warm build run.

Identity: clean `matrix-fixes-base` at
`62c10315e1ebcac4480dba6bacdc2100a38119e5` (upstream branch `weak-blocks`), sigma
`6.0.5-22-368a860b-SNAPSHOT` (fork pin
`368a860be033af94aa14895381f42099b3646db6`). Java is Amazon Corretto OpenJDK
17.0.17+10-LTS; `project/build.properties` pins sbt 1.11.1. The installed sbt shell
launcher is from distribution 1.12.0, which loads the project's pinned sbt.
Run date: 2026-09-22. `/home` had 467 GB available before builds (above 100 GB).

Selected real spec:
`ergo-core/src/test/scala/org/ergoplatform/network/InputBlockMessageSpecsSpec.scala`,
fully qualified `org.ergoplatform.network.InputBlockMessageSpecsSpec`. This exercises
Matrix (input blocks) message serialization and malformed payload handling.

| Attempt / evidence file | Total subprocess wall | Scala 2.12 compile / tests | Scala 2.13 compile / tests | Outcome |
| --- | --- | --- | --- | --- |
| `baseline-first.log` | 0.25 s | unavailable / unavailable | unavailable / unavailable | sbt exit 1, read-only home boot lock |
| `baseline-short-runtime.log` | 0.50 s | unavailable / unavailable | unavailable / unavailable | sbt exit 2, Unix socket bind denied |
| `baseline-repeat.log` | 1.91 s | unavailable / unavailable | unavailable / unavailable | sbt exit 2, same denial; NOT a warm build measurement |
| `root-213.log` | 1.89 s (`time -p`) | not requested | unavailable / not requested | sbt exit 2 before root probe commands |

All logs are adjacent to this README in the delivery directory. Counts printed as
zero mean no successful test summaries were observed; they do not mean the selected
spec contains zero tests. The initial failure was:

```text
java.io.FileNotFoundException: /home/rkadias/.sbt/boot/sbt.boot.lock (Read-only file system)
```

Existing sbt boot/global, Ivy (including local sigma), and Coursier caches were copied
using `cp -a --reflink=auto` into `target/matrix-gate-cache/` to allow lock/cache writes.
The next obstacle was `/run/user/1000/.sbt/...: Read-only file system`.
A worktree-local runtime path exceeded Unix socket name length (`baseline-runtime.log`).
A short, writable `/tmp/m4-sbt-runtime.*` path exposed the underlying blocker:

```text
sbt.internal.ServerAlreadyBootingException: java.io.IOException: org.scalasbt.ipcsocket.NativeErrorException: [1] Operation not permitted
    at sbt.internal.BootServerSocket.newSocket(BootServerSocket.java:357)
    at sbt.internal.BootServerSocket.<init>(BootServerSocket.java:296)
```

`sbt.server.autostart=false` prevents the normal sbt server but not sbt 1.11.1's
local Unix boot socket. Trying `sbt.boot.server=false` also did not prevent it; that
ineffective property is absent from the delivered wrapper. No network service was
started. No tracked build settings or production/test sources were changed to work
around this. Sandbox approval is unavailable in this session.

Root probe attempted (one separate sbt process, with the same sigma and writable
cache settings):

```bash
sbt -batch 'projects' 'show ergo/crossScalaVersions'   'show avldb_benchmarks/crossScalaVersions' '++2.13.18!' 'ergo/compile'
```

It failed at the identical boot-socket bind, before any commands ran. **No specific
root/node Scala 2.13 compiler error has been established.** The controller's decision
on a 2.12-only node gate plus dual-version library gates remains pending a genuine
forced 2.13 root compile. The source declares dual-version support only for the
library projects; this does not establish root compatibility or incompatibility.

## Completing the measurements

Run the wrapper twice in an execution environment that permits sbt's local Unix
boot socket, retaining separate logs. A first run using existing caches is a first
measured run, not necessarily a cold build. Record all four task times, both test
counts, and total wall time for each run; only the second successful run is a warm
baseline. Then run the forced root probe above and preserve exact compiler errors
if it fails. Do not fix baseline production code.

For reproducing the sandbox cache setup (copies already exist in this worktree):

```bash
cd /home/rkadias/coding/development/arkadianet/ergo-scala-wt-m4
export JDK_JAVA_OPTIONS="-Dsbt.boot.directory=$PWD/target/matrix-gate-cache/sbt/boot -Dsbt.global.base=$PWD/target/matrix-gate-cache/sbt/1.0 -Dsbt.ivy.home=$PWD/target/matrix-gate-cache/ivy2"
export COURSIER_CACHE="$PWD/target/matrix-gate-cache/coursier/v1"
export XDG_RUNTIME_DIR=$(mktemp -d /tmp/m4-sbt-runtime.XXXXXX)
```

This addresses read-only cache paths only; it does not overcome the socket denial.

## Wrapper validation

`bash -n` passed. Ten simulated sbt transcript cases passed: normal success,
ANSI-colored success, zero tests separately in each version, failed tests, aborted
suite, compile error, nonzero process exit, missing task completion, and missing
Scala switch. Every case asserted exactly one invocation and the exact seven sbt
arguments (including `-batch`), plus the sigma environment override. See
`wrapper-validation.log`. These are wrapper checks, not Scala build evidence.

Build identity SHA-256 hashes are in `task-1-identity.sha256` alongside this README.

## Measured baseline (controller run outside the codex sandbox, 2026-09-22, matrix-fixes-base @ 62c10315)

`scala-gate.sh <wt> ergoCore org.ergoplatform.mining.AutolykosPowSchemeSpec` on a warm ivy cache
(sigma snapshot already published, ergo-core dependencies resolved):

```
gate: 2.12 compile 8s tests 6s | 2.13 compile 13s tests 7s
gate: succeeded 2.12=4 2.13=4; wall=45.13s; sbt exit=0
```

Both Scala versions compile `ergoCore` at base; wall time for a warm incremental gate cycle is under a
minute. The codex sandbox denies sbt's boot socket (`Operation not permitted`), so gates for
codex-written patches are run by the controller or a Claude subagent, or codex is launched with full
local access to its task worktree.

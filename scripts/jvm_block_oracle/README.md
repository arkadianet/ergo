# Scala block-cost oracle

This offline oracle applies synthetic blocks through Ergo 6.0.5
`UtxoState.applyModifier(block, None)(_ => ())`. It observes the actual
`ErgoState.execTransactions` return value used by that call. No node connection,
wallet, mempool, or node restart is involved.

## Run

From the Rust worktree root, with sbt, scala-cli 1.12, Java 17 and Python 3.12+:

```sh
python3 scripts/jvm_block_oracle/provision.py
python3 scripts/jvm_block_oracle/run.py evaluate scripts/jvm_block_oracle/p2pk.json.gz
python3 scripts/jvm_block_oracle/run.py self-test scripts/jvm_block_oracle/p2pk.json.gz
```

Provisioning archives commit `5528ef569a41ebccbc8658212e6ee3c97d990b96`
(Ergo v6.0.5) from `ERGO_REFERENCE`, defaulting to
`~/coding/development/arkadianet/ergo-scala`. It builds inside `.work/source`.
The published 6.0.5 ergo-core/ergo-wallet and sigma-state 6.0.6 dependencies
must be available as described in `test-vectors/ergo-sigma/cost-total/PROVISIONING.md`.
The complete node source is needed because `UtxoState` is outside ergo-core.
The reference checkout is read-only. Provisioning removes any
`SIGMASTATE_VERSION` environment override; the oracle also checks the resolved
Sigma jar version. sbt/Coursier use their normal dependency caches.

The one production source change is mechanically verified against a pinned
SHA-256 and changes this expression in `UtxoState.applyTransactions`:

```scala
ErgoState.execTransactions(transactions, currentStateContext, ergoSettings.nodeSettings)(checkBoxExistence)
```

into `CostObservation.observe(theOriginalExpression)`. `observe` saves and returns
the same `ValidationResult[Long]` object. It does not alter the interpreter,
limit, running accumulator, rounding, errors, AVL changes, or rollback.
The observer is reset after parent replay, so the emitted sum belongs only to
the target block. Execution is single-threaded.

`sum_block_cost` is the successful production payload, including when later AVL
validation rejects. It is **null** when transaction execution fails or does not
run: the production invalid result does not expose a partial total.
`failure_class` is the JVM exception class, with its text in `rejection_detail`.
Malformed fixtures and parent setup failures exit nonzero, rather than producing
an apparent target-block verdict. Stdout contains one JSON record; logs use stderr.

## Build blocks

```sh
python3 scripts/devnet-mixed/build-block.py REQUEST.json OUTPUT.json
```

The Python command invokes the pinned JVM's difficulty-one Autolykos miner and
AVL proof generator. A request contains the signed transactions and synthetic
parent-state fields described in the [fixture schema](../../test-vectors/ergo-sigma/cost-ledger/blocks/README.md).
A supplied complete fixture can also serve as a request: its recorded parent
chain is replayed and `transactions_hex` determines the new target block.
Target transactions are not prevalidated; this allows cost-invalid blocks to be
mined for conformance testing. Structurally impossible AVL operations cannot be
mined by this builder.

Generate a new signed P2PK smoke fixture with:

```sh
python3 scripts/jvm_block_oracle/run.py smoke scripts/jvm_block_oracle/.work/p2pk-new.json
```

The checked-in compressed fixture freezes its generated signature and bytes.
Rebuilding that fixture preserves block bytes; generating a new signature need
not preserve the PoW header. The independent expected total is **12503**:
Task 3.4e's JVM P2PK result supplies 5 evaluation + 398 cryptographic units;
the pinned JVM transaction initialization supplies 10000 + 2000 input + 100
output units. No ledger row is closed by this infrastructure task.

The self-test has 16 checks: accepted P2PK, one observed call, exact cap,
two chained transactions totaling 25006, serialization, deterministic rebuild,
fresh-state replay, cap+1 rejection, unchanged rejection root, malformed parent
setup, invalid proof commitment, invalid signature, post-execution digest
rejection, AVL rollback, and two independent-oracle checks.

## Scope

The harness validates PoW, parent linkage and section commitments before the
state application. It is not an `ErgoHistory` consensus harness: difficulty
retargeting, timestamps relative to wall time and other history rules are out
of scope. The parent chain is a synthetic development context. Its first 128
blocks carry a bootstrap box through a complete devnet voting epoch so parameters
are parsed from the epoch extension and the last-header window is populated.
A mainnet UTXO subset cannot recreate a historical AVL root.

The new Scala harness compiles with `-Xfatal-warnings`. A clean build of the
pinned upstream node can emit upstream sbt deprecation/unused-setting and Scala
warnings; these sources are not rewritten to suppress them. No Rust command is
needed for this task, per the controller's task-specific instruction.

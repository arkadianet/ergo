These fixed mainnet triplets replace the audit-era activation cost stubs with
43 observed transactions. Every input was evaluated once per reference run;
all302 input observations and43 totals reconciled with production
`ErgoTransaction.validateStateful` using its cumulative block budget.

| Window | Block versions | Transactions | Initial external boxes | Block costs |
| --- | --- | --- | --- | --- |
| 417791 /417792 /417793 | 1 /2 /2 | 7 /1 /1 | 4 | 98942 /12344 /12344 |
| 844671 /844672 /844673 | 2 /2 /2 | 8 /23 /3 | 249 | 427117 /435936 /300052 |

The first window crosses Autolykos1→2. The second crosses the EIP37 difficulty
activation. It does **not** represent JIT activation or rule409 deactivation:
the captured full cumulative settings are initial (`0000`), and215/409 remain
active. The pinned mainnet configuration identifies their deactivation with
the later6.0 protocol update. The old stub's EIP37 governance association was
stale.

The native consumer starts from only the immutable external input/data-input
subset, validates every complete block's transactions with all nine immediate
script-visible parents, and carries actual spends and outputs forward. It
checks full decoding, raw box/transaction identity, recorded parent roots,
epoch extension roots, all eight voted numeric parameters by name, the full
parameter table and cumulative settings, plus every transaction position and
cost. Token access and data input costs are both 100 in every captured epoch,
so these fixtures cannot detect an exchange of those two parameter ids.
It parses each recorded voted row rather than using `mainnet_default()`
and fails on missing prerequisites. It checks target PoW, but this sparse history
is not a complete retarget/governance or peer-admission proof. It does not
reconstruct a global historical UTXO database or certify persisted reopen.

`capture-inputs.json` retains the exact UTF-8 texts of the finite public
captures and selected previously committed header fixtures. Their per-file
SHA-256 hashes, including each archived box, are in `provenance.json`.
Public operator software versions differ from the offline oracle version;
operator JSON is input data, not an independent reference verdict. The
reference evaluates the SHA-256 pinned official6.0.5 release assembly
(82,384,324 bytes); the binary itself is not committed. Exact6.0.5 source and
configuration snapshots are included under `reference`, with source hashes
and tag commit in the manifest. The current live producer's6.0.5 operator
gate remains unchanged.

To reproduce offline, obtain the assembly from the manifest URL and the
Scala2.12.20 compiler, reflect and library jars. Supply absolute paths and a
new disposable output directory:

```bash
python3 test-vectors/ergo-state/historical-costs/recapture.py \
  --java /path/to/java \
  --scalac-classpath /path/scala-library-2.12.20.jar:/path/scala-compiler-2.12.20.jar:/path/scala-reflect-2.12.20.jar \
  --assembly /path/ergo-6.0.5.jar --output /tmp/historical-cost-recapture
```

The runner verifies the assembly, bundled capture texts, helper and source
snapshots before compiling the shipped helper. Its dependency classpath is
only the assembly; compiler tooling is pinned separately by basename and exact SHA-256.
Verification uses explicit errors that remain active under Python optimization. It passes the saved
configuration root explicitly, records commands/jar hashes/stdout/stderr,
and compares every emitted box, header, context, parameter and transaction
against the saved observations. It performs no HTTP requests, starts no
node and performs no signing. The native consumer runs in normal tests:

```bash
cargo test --locked -p ergo-state --test it historical_activation_costs
```

The optional700000..700200 legacy corpus harness remains `NOT_RUN` without
its missing files. These six bodies do not establish a historical JIT/6.0
rule activation, a full global UTXO snapshot, or crash/power-loss behavior.

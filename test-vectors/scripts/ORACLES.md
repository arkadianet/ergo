# Capture tool contracts

These tools use pinned Scala 2.12.20, ergo-wallet 6.0.6 and sigma-state 6.0.6.
Set `SCALA_CLI` to select the executable; compilation/setup failures are not
reference verdicts. Their finite observations do not certify whole-chain parity.

Maven Central has sigma-state 6.0.6 but not ergo-wallet 6.0.6. Publish it to
the local Ivy repository from the tagged reference source first, as CI's
"Publish reference wallet locally" step does:

```sh
git clone --depth 1 --branch v6.0.6 https://github.com/ergoplatform/ergo.git ergo-v6.0.6
cd ergo-v6.0.6
test "$(git rev-parse HEAD)" = 23aabead88774d27f2c9190ace3c9abbc8f1d5cb
sbt "ergoWallet/publishLocal"
```

Scala CLI then resolves `ergo-wallet:6.0.6` from `~/.ivy2/local`. The
dependency is pinned by version only, with no checksum: any jar published
locally as 6.0.6 satisfies it, so publish it from that commit.

`extract_bytes_to_sign.sh INPUT OUTPUT` compares every row in a nonempty
transaction array with `PrintBytesToSign.scala`. Its JSON report retains matches,
mismatches and helper errors. A mismatch or helper error causes a nonzero exit;
malformed inputs never replace an existing report.

`build_rejection_corpus.sh OUTPUT` uses `NODE_URL` to capture one source box and
reference tip. It chooses a token-free unspent P2PK box, then feeds the captured
box and height to `BuildMutations.scala`. That helper performs no network reads
and encodes each submitted JSON object and wire transaction from the same Scala
transaction. The driver requires all seven unique mutation labels and a stable
full tip around every submission. Only a structured validation HTTP 400 response
is recorded; accepted transactions, authentication/infrastructure responses,
missing cases and context changes abort without replacing the old corpus.
`expectedCategory` describes the mutation target. The exact response, submitted
JSON, wire bytes, source box and reference node info are retained for review;
the category is not inferred independently from the response.

`ReduceTransactionScripts.scala` is a reduction diagnostic with limited
structural and monetary prechecks. It deliberately emits
`REDUCED_UNVERIFIED`, even for a non-trivial proposition with an invalid spending
proof. It performs no protocol proof verification and does not certify signed
transaction validity. Use the pinned node's validation operation or the actual
interpreter verifier for that claim. This replaces the unused, misleading
`ValidateTransaction.scala` contract.

`record_l4_provenance.py RESULTS` hashes the capture storage selected by the replay
consumer, preferring gzip when both forms exist and including overlapping
headers. Hashes describe uncompressed JSON. Missing required transaction/cost
captures are listed explicitly; observed selected/executed/failed counts remain
unchanged. Historical evidence must retain its original execution attribution.

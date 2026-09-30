# Block-section storage oracle

This oracle uses the unmodified official Ergo 6.0.7 assembly, commit
`3a6b00d37e3bda2b36447a922606b4ca5a09568f`, with Scala 2.12.20 and Java 17.
The assembly SHA-256 is checked by `run.py`; it is not built from a patched
reference checkout. Download the assembly from the release URL recorded in
`test-vectors/scala/block_section_storage_6_0_7.json`. Obtain Scala compiler
and reflect 2.12.20 from Maven Central. The assembly supplies scala-library.

```sh
python3 scripts/jvm_section_oracle/run.py \
  --java /path/to/jdk17/bin/java \
  --jar /path/to/ergo-6.0.7.jar \
  --compiler /path/to/scala-compiler-2.12.20.jar \
  --reflect /path/to/scala-reflect-2.12.20.jar \
  --output test-vectors/scala/block_section_storage_6_0_7.json
cargo test -p ergo-node --lib section_wire_policy
```

The oracle parses each entire BlockTransactions section, computes transaction
IDs, transaction/witness Merkle root and section identity, and inserts the
parsed object through production `HistoryStorage.insert`. It reads persisted
bytes using `modifierBytesById`, obtains the type and bytes through
`modifierTypeAndBytesById` (the lookup used by `ErgoNodeViewSynchronizer.modifiersReq`),
and reopens LevelDB to verify persistence. It separately captures
`BlockTransactions.jsonEncoder`, used by `/blocks/{id}/transactions`, with
the parsed object cached and after reopening. It does not start a Scala HTTP
server or actor network; the production storage and response data are exercised
directly. The Rust regression drives typed persistence and the actual
RequestModifier handler, and calls the production REST bridge.

There are 22 accepted cases across block versions 1 and 4: the existing
Boolean/context-extension evaluated-value cases, canonical identity
GroupElements and zero-prefixed identity encodings with nonzero trailing bytes.
These synthetic transactions establish parser and authenticated section
acceptance. Their input boxes are not provisioned and their synthetic headers
are not mined; this is not evidence of full-block consensus acceptance.

Eight input sections differ from Scala's canonical stored/P2P bytes. Parsed
transaction IDs, Merkle roots, section IDs and canonical writer output agree.
REST values agree too. For the four shorter Boolean leaf encodings, Scala's
section `size` changes from received length to canonical length when its
parsed-object cache is lost; Rust consistently reports received length.
Transaction `size` is canonical on both implementations. Rust deliberately
retains received P2P bytes; see `docs/compatibility.md` for the policy.

Do not infer that arbitrary embedded boxes or headers can be canonicalized
without affecting identity. Their retained-byte identity contracts (#357)
remain separate. The fixture generator operates in temporary directories,
closes LevelDB before cleanup and does not open any deployed node database.

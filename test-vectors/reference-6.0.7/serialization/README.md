# Reference serialization fixtures

All companions were generated with sigma-state 6.0.7; transaction, header and
section identifiers also use ergo-core 6.0.7. Positive controls accompany parse
and serialization failures. These files pin reference behavior; costs are block
cost units, and rejected transactions have no recorded cost.

| Fixture family | Coverage |
| --- | --- |
| `readers-receivers`, `receiver-types` | Constructor receiver/type reads, root types, sized and sizeless trees, registers, context extensions, nested boxes, production outputs |
| `readers-avl`, `avl-lengths` | Wrapped key/value lengths on read and write; constants, registers, extensions, nested scripts/boxes, deserializeTo and serialize |
| `readers-nested-box`, `nested-boxes` | Nested script write errors; tuple arity and unparsed controls; read-only consumers, serialize, embedded scripts |
| `readers-relations`, `relations` | Every relation opcode, constants and nonconstant operands, explicit casts, v0/v1/v2/v3, box bytes/IDs, embedded scripts |
| `readers-encodings`, `transaction-encodings` | Accepted alternate Boolean, integer/count, BigInt, Boolean collection, group element and AVL flag encodings; extension order/duplicates |
| `readers-headers`, `headers`, `node-headers` | Extension-size/payload layouts, signed versions, Header constants and nested carriers, deserializeTo, PoW, node and value IDs |

Reader TSV columns: name, result, consumed position, wrapped validation rule
(or `-`), serialized bytes (or `-`), and extra identity/type fields (or `-`).
`ACCEPT` includes successful read-only modes with no write. `WRAPPED` preserves a
sized tree's opaque body; other result strings describe the JVM exception.
Transaction TSV columns: name, validation Boolean, cost (or `null`). Identifier
TSVs record transaction ID, signing message, output ID/bytes/proposition bytes,
and legacy/versioned section bytes, serialized bytes, Merkle roots and IDs.
Node-header TSV columns: name, parse Boolean, consumed position, node ID,
serialized bytes, PoW Boolean.

From the repository root, with scala-cli and a JVM on PATH:

```sh
python3 scripts/jvm_serde_oracle/serialization_companions.py test-vectors/reference-6.0.7/serialization/readers-*.json
python3 scripts/jvm_serde_oracle/serialization_companions.py test-vectors/reference-6.0.7/serialization/receiver-types.json test-vectors/reference-6.0.7/serialization/avl-lengths.json test-vectors/reference-6.0.7/serialization/nested-boxes.json test-vectors/reference-6.0.7/serialization/relations.json test-vectors/reference-6.0.7/serialization/transaction-encodings.json test-vectors/reference-6.0.7/serialization/headers.json test-vectors/reference-6.0.7/serialization/node-headers.json
python3 scripts/jvm_serde_oracle/serialization_companions.py --ids test-vectors/reference-6.0.7/serialization/relations.json test-vectors/reference-6.0.7/serialization/transaction-encodings.json
scala-cli run scripts/jvm_serde_oracle/CompileSerializationFixtures.scala --server=false --jvm system -- test-vectors/reference-6.0.7/serialization/runtime-scripts.tsv
```

The regeneration wrapper uses temporary scala-cli workspaces and checks fixture
names/order before replacing a companion. `runtime-scripts.tsv` records the
compiler recipes used for runtime deserialization and embedded-script vectors.
Tests in ergo-ser compare reader/writer outcomes and identifiers; ergo-validation
checks both block and mempool validation/costs; ergo-mempool checks its production
adapter's identifiers; ergo-sync checks header receipt and section identities.

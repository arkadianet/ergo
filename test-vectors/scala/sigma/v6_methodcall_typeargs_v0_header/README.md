# v6 method-call explicit type args inside v0-header trees

Scala-extracted oracle vectors for the `(type_id, method_id)`-keyed
explicit-type-arg read in `ergo-ser::opcode` (`method_explicit_type_args_count`).
Every vector is a complete wire-format `ErgoTree` whose header byte is `0x10`
(`version=0`, `constant_segregation=true`, `has_size=false`) and whose body
carries a Sigma 6.0 / EIP-50 method call with a trailing explicit type byte.

## Oracle source

`[empirical]` Compiled by the official Scala reference node, release jar
`ergo-6.1.2.jar` (sha256
`cb1a684ee30299445271a5ede9218f7e972e9de2dc43c683378d37019be77b93`, from
https://github.com/ergoplatform/ergo/releases/tag/v6.1.2), run unsynced on
mainnet settings, extracted 2026-06-06.

Per vector:

1. `POST /script/p2sAddress` (api-key protected) with body
   `{"source": "<ErgoScript>", "treeVersion": 3}` — the address in each
   vector entry is the node's response.
2. Base58-decode the address locally; tree bytes = decoded bytes minus the
   one-byte network/type prefix (`0x03`, mainnet P2S) and the 4-byte
   checksum suffix.

The node's own `GET /script/addressToBytes/{address}` cannot be used for
step 2: it fails with `Cannot handle ValidationException, ErgoTree
serialized without size bit` (the unsynced node's version context does not
expose v6 methods, the inner `ValidationException` cannot be soft-fork
wrapped because a sizeless tree cannot be skipped). That failure is itself
oracle signal: Scala's parse verdict for these trees depends on the
activated-version context, never on the tree-header version byte.

## What the vectors establish

- `[empirical]` The Scala 6.1.2 compiler emits v6 method calls inside
  v0-header (`0x10`) trees. `treeVersion: 3` in the request gates compiler
  *method visibility* only — with `treeVersion` 0/1/2 the same sources fail
  to compile (`Cannot find method 'deserializeTo' …`), and the emitted
  header byte stays `0x10` regardless. The tree-header version is a
  wire-format selector, not a script-version selector.
- All six `(type_id, method_id)` pairs carrying `hasExplicitTypeArgs` in
  Sigma 6.0.2 are covered: SBox.getReg `(99,19)`, SContext.getVarFromInput
  `(101,12)`, SGlobal.deserializeTo `(106,4)`, SGlobal.fromBigEndianBytes
  `(106,5)`, SGlobal.some `(106,9)`, SGlobal.none `(106,10)`.
- Control vector: `SELF.getReg[Int](4)` with a *literal* register index
  folds to the legacy `ExtractRegisterAs` primitive (opcode `0xc6`) — no
  MethodCall, no type byte. The `(99,19)` MethodCall form is only emitted
  for a dynamic index (`SELF.getReg[Int](INPUTS.size)`).

## Re-extraction

Start the node (`java -jar ergo-6.1.2.jar --mainnet -c <conf with
scorex.restApi.apiKeyHash>`), wait for `/info`, then run

```
NODE_URL=http://127.0.0.1:9099 API_KEY=<key> \
  test-vectors/scripts/extract_v6_typearg_vectors.sh
```

and diff the emitted `name<TAB>address<TAB>tree_hex` lines against the
entries in `golden_vectors.json`. The node does not need to sync;
compilation is chain-state independent.

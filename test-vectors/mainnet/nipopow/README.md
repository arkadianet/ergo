# NiPoPoW mainnet oracle fixtures

Frozen captures from the **Scala reference node** (`:9053`, mainnet,
2026-07-05), used as standing oracles so the NiPoPoW parity tests run in
CI without a live Scala node. Same discipline as the other
`test-vectors/mainnet/*` snapshots.

| File | Bytes | What it pins | Read by |
|------|-------|--------------|---------|
| `proof_m6_k10.json` | ~440 KB | The comprehensive NiPoPoW proof (m=6, k=10) as the live Scala REST JSON. Its 122-header prefix spans genesis → tip and **includes an epoch-boundary block (h=1821696)**, v1–v4 headers, and μ-levels 0–20 — i.e. every case the JSON encoders + DTOs must handle. Minified (values are what matter; tests compare `serde_json::Value`). | route/DTO/encoder parity |
| `proof_m6_k10.scala.bin` | ~168 KB | The **same proof re-emitted through Scala's own `NipopowProofSerializer`** — genuine Scala wire bytes. The JSON above is the JSON-shape oracle; this is the binary-wire oracle. | wire round-trip, `is_valid`, level sweep |
| `popowHeaderByHeight_1000.json`, `popowHeaderById_h1000.json` | ~4 KB each | Single-`PoPowHeader` REST responses (incl. `interlinksProof`). | route/DTO parity |
| `max_levels_scala.txt` | ~4 KB | `height level` for all 132 fixture headers, from Scala `NipopowAlgos.maxLevelOf`. | `max_level_of` f64 parity |
| `batch_merkle_shapes_scala.txt` | ~12 KB | 20 synthetic scrypto `BatchMerkleProof` shapes (single-leaf, all-leaf, odd trees, sparse), `n\|indices\|root\|proof_hex\|valid`. | batch-Merkle construct/verify parity |

One proof, not several: the comprehensive proof above dominates any
anchored/short proof (same `NipopowProof` structure, richer coverage),
so it is the single JSON+wire oracle. The live end-to-end differential
(prod node vs `:9053`, all endpoints/heights/anchors) is a separate,
un-committed check run against a mainnet DB copy.

## Regeneration

`.bin` from `.json` (Scala decoder → Scala serializer), and both from a
live node:

```sh
# 1. capture the REST JSON from a Scala node serving /nipopow/*
curl -s http://<scala-node>:9053/nipopow/proof/6/10 > proof_m6_k10.json

# 2. re-emit genuine Scala wire bytes (needs the ergo reference checkout's
#    src/main/resources for the mainnet ChainSettings)
scala-cli run scripts/jvm_nipopow_oracle/NipopowCapture.scala -- \
  <ergo-ref>/src/main/resources proof_m6_k10.json proof_m6_k10.scala.bin

# max_levels_scala.txt / batch_merkle_shapes_scala.txt: the LevelProbe /
# BmpShapes scala-cli snippets referenced in the NiPoPoW PR.
```

The tip proof is a point-in-time snapshot (the tip moves), so an exact
re-capture needs the same height; the `.bin` is the byte-authoritative
artifact and the `.json` is semantically pinned (key order / whitespace
are not significant — tests compare parsed values).

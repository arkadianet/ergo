# Scala-anchored batch Merkle multiproof fixtures

`fixtures.json` pins the wire bytes the scorex-utils
`BatchMerkleProofSerializer` produces against five Rust paths:
the construction algorithm in `ergo-crypto::merkle::merkle_proof_by_indices`,
the codec in `ergo-ser::batch_merkle_proof::{serialize,deserialize}_batch_merkle_proof`,
and the verifier in `ergo-validation::popow::merkle::verify_batch_merkle_proof`.

The proof carries the NiPoPoW interlinks proof embedded in each
`PoPowHeader`. Drift in any of those three Rust paths breaks
`check_popow_header_interlinks_proof` — the consumer that
validates each PoPow-prefix header during logarithmic-time
bootstrap. The PoPow path is marked optional/deferred in the
node checklist ("one mode first"), so drift here does not by
itself fork the main chain; it does invalidate NiPoPoW sync once
that mode is wired.

## Fixture contract

```jsonc
[
  {
    "label":          "<short-id>",
    "leaves":         ["<hex>", ...],      // tree input
    "indices":        [<u32>, ...],        // requested proof indices
    "expected_root":  "<64-hex>",          // Blake2b256 tree root
    "expected_bytes": "<hex>",             // BatchMerkleProofSerializer.serialize output
    "expected_proof_indices": [<u32>, ...],// sorted, deduplicated
    "expected_proof_count":  <u32>,        // sibling-entry count
    "note":           "<rationale>"
  }
]
```

**Wire format** (mirrors `scorex.crypto.authds.merkle.serialization.BatchMerkleProofSerializer`):
```text
u32 num_indices  (big-endian)
u32 num_proofs   (big-endian)
[num_indices x { u32 index_be, [u8; 32] digest }]
[num_proofs  x { [u8; 32] digest, u8 side }]
```

A 32-byte all-zero `digest` in the **proofs** section decodes as
`EmptyByteArray` (odd-trailing empty sibling). This matches Scala's
encoding and is the documented ambiguity at
`ergo-ser/src/batch_merkle_proof.rs::deserialize_batch_merkle_proof`.

## Coverage matrix

| Fixture | Shape | Edge case |
|---------|-------|-----------|
| `single_leaf_prove_all`        | 1-leaf tree, prove [0]              | Single-leaf wrap, `None` sibling on root |
| `adjacent_pair_4leaf`          | 4-leaf tree, prove [0, 1]           | Both siblings of a pair in proven set (`in_set` dedup) |
| `sparse_3_of_8`                | 8-leaf tree, prove [0, 3, 5]        | Mixed `Side::Left` + `Side::Right` non-empty siblings |
| `full_4leaf_all_indices`       | 4-leaf tree, prove [0, 1, 2, 3]     | `proofs.len() == 0` — empty proofs section |
| `odd_count_5leaf_prove_last`   | 5-leaf tree, prove [4]              | 32-zero-byte `EmptyByteArray` markers above leaf level |
| `deep_32leaf_sparse_proof`     | 32-leaf tree, prove [2, 7, 15, 30]  | 5-level reduction depth — catches level-counter drift past toy depths |
| `unsorted_dup_indices_4_of_8`  | 8-leaf tree, prove [5, 0, 3, 0, 5]  | Sort + dedup normalization parity (both sides normalize) |

## Provenance

| File | Source | Notes |
|------|--------|-------|
| `fixtures.json` | `test-vectors/scripts/scala/ExtractBatchMerkleProofs.scala` | scrypto 2.3.0 on Scala 2.13 |

### Pinning

scrypto is pinned to **2.3.0** to match
`reference/ergo/avldb/build.sbt`:
```
"org.scorexfoundation" %% "scrypto" % "2.3.0"
```
Do not bump the dep without confirming the wire format hasn't
changed across major versions. The Scala node currently used as
the parity oracle runs scrypto 2.3.0; a `BatchMerkleProof`
encoded by scrypto 3.x is a different wire artifact even if the
algorithm is identical.

## How to regenerate

```bash
scala-cli run test-vectors/scripts/scala/ExtractBatchMerkleProofs.scala \
  > test-vectors/ergo-crypto/batch-merkle/fixtures.json
```

`scala-cli` will print an upgrade hint suggesting scrypto 3.1.0;
ignore it — see Pinning above. Validate with `python -c "import
json; json.load(open('test-vectors/ergo-crypto/batch-merkle/fixtures.json'))"`.

## Oracle test

`ergo-validation/tests/batch_merkle_oracle.rs` consumes these
fixtures. The test runs in default `cargo test`, no network, no
feature flag.

Test matrix (one `#[test]` per fixture plus cross-shape checks):
* per-fixture roundtrip: `deserialize` succeeds → shape matches
  expected → `verify` returns `true` → re-`serialize` is
  byte-identical to the captured bytes.
* `merkle_proof_by_indices_matches_scala_construction`: for every
  fixture, builds the proof from leaves via the Rust constructor,
  maps `BatchProofEntry` to `ProofEntry`, serializes, and asserts
  byte-identical to the Scala fixture. This is the strong drift
  catch — a Rust builder that emits the right *semantic* proof in
  a different order or with a different `Side` byte fails this
  check.
* `flipped_sibling_byte_fails_verify`: takes the `sparse_3_of_8`
  fixture, flips a single byte in the second sibling digest, and
  asserts `verify_batch_merkle_proof` returns `false`. Pins
  cryptographic binding — a corrupted proof must not verify.

## Why this closes the gap

`audit-2.md` M8 flagged that `merkle_proof_by_indices` was
exercised only by `verify(build(set)) == true` self-oracles —
the single-proof path was already mainnet-pinned, but the batch
path was not.

These fixtures:
* Pin Rust byte output to Scala byte output via
  `serialize(deserialize(fixture)) == fixture`.
* Pin the Rust construction algorithm to Scala's via
  `serialize(merkle_proof_by_indices(leaves, indices)) ==
  fixture` — drift in pair-iteration order, `in_set` dedup, or
  `Side` tagging fails this assertion.
* Pin the verifier path via `verify(parsed, root) == true`.
* Pin cryptographic binding via the flipped-byte negative test.

## End-to-end PoPowHeader coverage

`ExtractInterlinksProofs.scala` extends this corpus with PoPow-shape
fixtures whose leaves go through `packInterlinks` + `kvToLeaf` (not
just synthetic 1-byte leaves). The companion oracle
`ergo-validation/tests/interlinks_proof_oracle.rs` constructs a
`PoPowHeader` from each and drives the production
`check_popow_header_interlinks_proof` path. Coverage in
`popow_interlinks.json`:

| Fixture | Interlinks vector | Edge case |
|---------|-------------------|-----------|
| `popow_single_interlink`           | 1 unique             | Single-leaf wrap |
| `popow_three_unique_interlinks`    | 3 unique             | 3-leaf, mixed Side |
| `popow_run_of_duplicates`          | 1+3+1 (run-of-3 dup) | dup-run encoding parity |
| `popow_eight_unique_interlinks`    | 8 unique             | Full-tree degenerate proof |
| `mainnet_h700000_interlinks`       | 21 entries, 12 unique kv-pairs | Real mainnet at h=700000 |
| `mainnet_h1500000_interlinks`      | 21 entries, 10 unique kv-pairs | Real mainnet at h=1500000 (different epoch) |

Plus a `perturbed_interlinks_fails_end_to_end_validation` negative
test that flips one byte of an interlink id and asserts the proof
no longer verifies — pins cryptographic binding at the PoPowHeader
boundary.

## Provenance corroboration

The two `mainnet_*_interlinks` fixtures' interlinks vectors are
cross-referenced against tracked extension corpora at test runtime:

| Fixture | Tracked corpus |
|---------|----------------|
| `mainnet_h700000_interlinks`  | `test-vectors/mainnet/extensions_700000_700200.json` |
| `mainnet_h1500000_interlinks` | `test-vectors/mainnet/extensions_1500000.json` |

The `assert_provenance` helper in
`ergo-validation/tests/interlinks_proof_oracle.rs` reads the
matching extension entry, unpacks the interlinks kv-fields (key
prefix `0x01`) through the dup-count run encoding, and asserts the
result is byte-identical to the fixture's `interlinks` array. A
drift between the fixture and the on-chain bytes the corpus
captured fails loudly.

## Remaining gaps

* **Live `PoPowHeader.interlinks_proof` extraction from mainnet.**
  The two `mainnet_*_interlinks` fixtures use real mainnet
  interlinks vectors (corroborated above) but the proof is
  generated synthetically by scrypto on the Scala harness side.
  The alternative — extracting the `interlinks_proof` blob from a
  serialized mainnet `PoPowHeader` — requires the Scala node's
  `/nipopow/popowHeader/byHeight/{h}` endpoint (returns
  `bad.request` on probe; needs upstream wiring). The harness
  here matches what `proofForInterlinkVector` produces byte-for-
  byte, so the gap is presentation, not parity.
* **Even larger trees.** Mainnet interlinks max around 20-40
  entries; the existing fixtures cover up to 32 unique kv-pairs.

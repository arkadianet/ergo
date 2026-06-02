//> using scala 2.13
//> using dep "org.scorexfoundation::scrypto:2.3.0"
//
// Extract Scala-anchored fixtures for end-to-end PoPowHeader
// interlinks-proof validation.
//
// Each fixture exercises the `check_popow_header_interlinks_proof`
// path (Rust) / `PoPowHeader.checkInterlinksProof` (Scala) all the
// way from a synthetic interlinks vector through `packInterlinks`,
// `kvToLeaf`, merkle-tree construction, and BatchMerkleProof
// generation.
//
// Output JSON shape per record:
//
//   {
//     "label":            short identifier,
//     "interlinks":       array of 32-byte hex strings (ModifierIds, in
//                         the SAME order the production code uses),
//     "expected_root":    hex string (Blake2b256 32-byte interlinks
//                         subtree root, what proof.valid checks against),
//     "expected_proof_bytes": hex string (full BatchMerkleProofSerializer
//                         output covering ALL interlinks kv-fields),
//     "expected_proof_indices_count": <u32>,
//     "expected_proof_entry_count":   <u32>,
//     "note":             rationale
//   }
//
// Reproducing locally:
//
//   scala-cli run test-vectors/scripts/scala/ExtractInterlinksProofs.scala \
//     > test-vectors/ergo-crypto/batch-merkle/popow_interlinks.json

import scorex.crypto.authds.LeafData
import scorex.crypto.authds.merkle.{BatchMerkleProof, MerkleTree}
import scorex.crypto.authds.merkle.serialization.BatchMerkleProofSerializer
import scorex.crypto.hash.{Blake2b256, Digest32}

object ExtractInterlinksProofs {
  type HF = Blake2b256.type
  implicit val hf: HF = Blake2b256

  // Mirror `org.ergoplatform.modifiers.history.extension.Extension.InterlinksVectorPrefix`.
  private val InterlinksVectorPrefix: Byte = 0x01

  private def hex(bs: Array[Byte]): String = bs.map("%02x".format(_)).mkString

  /** Mirror `NipopowAlgos.packInterlinks` (1:1 — same dedup-run encoding). */
  private def packInterlinks(links: Seq[Array[Byte]]): Seq[(Array[Byte], Array[Byte])] = {
    @scala.annotation.tailrec
    def loop(idx: Int, acc: Seq[(Array[Byte], Array[Byte])]): Seq[(Array[Byte], Array[Byte])] = {
      if (idx >= links.length) acc
      else {
        val head = links(idx)
        val dupQty = links.drop(idx).takeWhile(java.util.Arrays.equals(_, head)).length
        val key = Array(InterlinksVectorPrefix, idx.toByte)
        val value = (dupQty.toByte +: head)
        loop(idx + dupQty, acc :+ (key, value))
      }
    }
    loop(0, Seq.empty)
  }

  /** Mirror `Extension.kvToLeaf`. */
  private def kvToLeaf(kv: (Array[Byte], Array[Byte])): Array[Byte] =
    Array(kv._1.length.toByte) ++ kv._1 ++ kv._2

  private case class Fixture(
    label: String,
    interlinks: Seq[Array[Byte]],
    note: String,
  )

  // Synthetic 32-byte ModifierIds. Each leaf below uses
  // Array.fill(32)(b.toByte) so the hex pattern is easy to read.
  private def id(b: Int): Array[Byte] = Array.fill(32)(b.toByte)

  private val fixtures: Seq[Fixture] = Seq(
    Fixture(
      label = "popow_single_interlink",
      interlinks = Seq(id(0x11)),
      note = "Single-interlink vector. packInterlinks produces one kv-pair; " +
        "the interlinks-subtree tree has a single leaf and the proof is the " +
        "degenerate single-index form.",
    ),
    Fixture(
      label = "popow_three_unique_interlinks",
      interlinks = Seq(id(0x22), id(0x33), id(0x44)),
      note = "3-element interlinks, all unique. Each becomes its own kv-pair " +
        "with idx 0/1/2 and dup=1. Tree has 3 leaves; proves all three.",
    ),
    Fixture(
      label = "popow_run_of_duplicates",
      // Three consecutive copies of 0x55, then a unique 0x66. packInterlinks
      // collapses the run to a single kv-pair with dup=3.
      interlinks = Seq(id(0x55), id(0x55), id(0x55), id(0x66)),
      note = "Run-of-duplicates in the interlinks vector. packInterlinks " +
        "collapses the three consecutive 0x55s into one (idx=0, dup=3) " +
        "kv-pair; the 0x66 entry is a separate (idx=3, dup=1) pair. Tree " +
        "has 2 leaves, NOT 4 — exercises the dup-run encoding path.",
    ),
    Fixture(
      label = "popow_eight_unique_interlinks",
      interlinks = (0 until 8).map(i => id(0x70 + i)),
      note = "8-element interlinks, all unique. Tree has 8 leaves across 3 " +
        "internal levels; the full-tree proof is the degenerate all-indices " +
        "form with proofs.len() == 0.",
    ),
    // ----- real mainnet interlinks captures -----
    // Extracted from a live Scala node via /blocks/{id} -> extension.fields
    // filtered to keys starting with InterlinksVectorPrefix (0x01) and
    // unpacked via the dup-count run encoding. The interlinks vector at
    // these heights is exactly what `proofForInterlinkVector` would build
    // a proof over on the production path.
    Fixture(
      label = "mainnet_h700000_interlinks",
      interlinks = Seq(
        // From mainnet block 54dd49ff...d36e982a at height 700000.
        "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
        // dup x4
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "116a6c1d030c62d333df6d518e26887745e5251d6d2270e5560fe4cce85ad0a3",
        "5aad19a4b658e59ec098f06c4f0b6f3317b09e6a6fe9e49be340933e709a5a1e",
        // dup x3
        "9501b674e3e4678a659d9abf63c079558305ae1dbc3d5f97cd07195b2423ddd5",
        "9501b674e3e4678a659d9abf63c079558305ae1dbc3d5f97cd07195b2423ddd5",
        "9501b674e3e4678a659d9abf63c079558305ae1dbc3d5f97cd07195b2423ddd5",
        // dup x2
        "cd82141797d05087f80bfff6ae12bb040a5f3ec7823594cc62edc8f0fbe42102",
        "cd82141797d05087f80bfff6ae12bb040a5f3ec7823594cc62edc8f0fbe42102",
        "fd1a3fa05412b8a1e7e4c8fc75741b5023e77465f3d7141abb53df0e4ddf2088",
        "fa393b1934337166f342c869039e5f0ae37fd936a9b798300b1ee6a74917cc3f",
        // dup x2
        "38af178273007afae47846eb9a43afc3dfeb96856969767be16f7b7462cda21a",
        "38af178273007afae47846eb9a43afc3dfeb96856969767be16f7b7462cda21a",
        "877f5f8df888b31bc5af15aa2a8304127e5b2a1887c7c66100c699341b4d18fe",
        "8922c26c133a0fdb1b21bf12530a39c2767a5cea0ed902fd61259a72f62214d9",
        // dup x3
        "a527d2a714b9767bce8a7f72ad59d6e7ca6e2b2f368fa8cb58f292723a93e0f0",
        "a527d2a714b9767bce8a7f72ad59d6e7ca6e2b2f368fa8cb58f292723a93e0f0",
        "a527d2a714b9767bce8a7f72ad59d6e7ca6e2b2f368fa8cb58f292723a93e0f0",
      ).map(s => s.grouped(2).map(java.lang.Integer.parseInt(_, 16).toByte).toArray),
      note = "Real mainnet interlinks at height 700000. 21-entry vector with " +
        "12 unique ids and several dup-runs (4x, 3x, 2x, 2x, 3x); pins parity " +
        "on realistic interlinks cardinality and dup-run patterns rather than " +
        "synthetic shapes.",
    ),
    Fixture(
      label = "mainnet_h1500000_interlinks",
      interlinks = Seq(
        // From mainnet block f5f148ba...26aae6bc at height 1500000.
        "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b",
        // dup x3
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        "1155d54de65f0130fae142aa4cf5a7728b7c30f5939d33fddf077e2008040a15",
        // dup x2
        "2e9e18180392c91ace964f24aff201511e891eddeed7c8049cfbe6dc0db6e9e1",
        "2e9e18180392c91ace964f24aff201511e891eddeed7c8049cfbe6dc0db6e9e1",
        // dup x2
        "5aa5ffce026d31f1ce6c410e5fdc2642c6467b94e9c3c4893056741cf81b1d96",
        "5aa5ffce026d31f1ce6c410e5fdc2642c6467b94e9c3c4893056741cf81b1d96",
        "505afd8aae3aed665b41a96a1b204daefb9a45a7c37d77c722ec038c6c036db3",
        // dup x3
        "1d9d08fca843e5ba2eba0b5694ddc889576b3d845b2965573fb0b8b495299739",
        "1d9d08fca843e5ba2eba0b5694ddc889576b3d845b2965573fb0b8b495299739",
        "1d9d08fca843e5ba2eba0b5694ddc889576b3d845b2965573fb0b8b495299739",
        // dup x2
        "df5de713b228b496be234356fa32e7f9d4f2e3b07bebbb21e4f052f2f41382f6",
        "df5de713b228b496be234356fa32e7f9d4f2e3b07bebbb21e4f052f2f41382f6",
        // dup x3
        "1773ce43367a6730c65411dd31f0bdfa046c3bf8dac329d50bfb07dafa5b22b2",
        "1773ce43367a6730c65411dd31f0bdfa046c3bf8dac329d50bfb07dafa5b22b2",
        "1773ce43367a6730c65411dd31f0bdfa046c3bf8dac329d50bfb07dafa5b22b2",
        "66824450c0052b7d01d13d744299df72aea39ad299cd477166763097aa4abeed",
        // dup x3
        "e8ff7ce576a6172a0c957a14d7a1e850228a7c44a42befc1f7a229507c0fa0f2",
        "e8ff7ce576a6172a0c957a14d7a1e850228a7c44a42befc1f7a229507c0fa0f2",
        "e8ff7ce576a6172a0c957a14d7a1e850228a7c44a42befc1f7a229507c0fa0f2",
      ).map(s => s.grouped(2).map(java.lang.Integer.parseInt(_, 16).toByte).toArray),
      note = "Real mainnet interlinks at height 1500000 (different epoch from " +
        "h=700000). 21-entry vector with 11 unique ids and dup-runs of 3x, 2x, " +
        "2x, 3x, 2x, 3x, 3x.",
    ),
  )

  def main(args: Array[String]): Unit = {
    val ser = new BatchMerkleProofSerializer[Digest32, HF]
    val records: Seq[String] = fixtures.map { fx =>
      val packed: Seq[(Array[Byte], Array[Byte])] = packInterlinks(fx.interlinks)
      val leaves: Seq[LeafData] = packed.map(kv => LeafData @@ kvToLeaf(kv))
      val tree = MerkleTree[Digest32](leaves)
      val allIndices: Seq[Int] = packed.indices
      val proof: BatchMerkleProof[Digest32] =
        tree.proofByIndices(allIndices).getOrElse(
          throw new RuntimeException(s"proofByIndices failed for ${fx.label}")
        )
      val bytes = ser.serialize(proof)
      val proofIndexCount = proof.indices.length
      val proofEntryCount = proof.proofs.length

      s"""  {
         |    "label": "${fx.label}",
         |    "interlinks": [${fx.interlinks.map(b => "\"" + hex(b) + "\"").mkString(", ")}],
         |    "expected_root": "${hex(tree.rootHash)}",
         |    "expected_proof_bytes": "${hex(bytes)}",
         |    "expected_proof_indices_count": $proofIndexCount,
         |    "expected_proof_entry_count": $proofEntryCount,
         |    "note": "${fx.note.replace("\"", "\\\"")}"
         |  }""".stripMargin
    }
    println("[")
    println(records.mkString(",\n"))
    println("]")
  }
}

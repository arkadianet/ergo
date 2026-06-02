//> using scala 2.13
//> using dep "org.scorexfoundation::scrypto:2.3.0"
//
// Extract Scala-anchored batch Merkle multiproof fixtures.
//
// Outputs a JSON array of fixture records to stdout. Each fixture:
//
//   {
//     "label":          short identifier,
//     "leaves":         array of hex strings (the leaf bytes the tree is built over),
//     "indices":        array of u32 (leaf indices to prove),
//     "expected_root":  hex string (Blake2b256 32-byte tree root),
//     "expected_bytes": hex string (output of BatchMerkleProofSerializer.serialize),
//     "expected_proof_indices":  array of u32 (sorted, deduplicated),
//     "expected_proof_count":    number of sibling-digest proof entries,
//     "note":           rationale for what edge case this covers
//   }
//
// Reproducing locally:
//
//   scala-cli run test-vectors/scripts/scala/ExtractBatchMerkleProofs.scala \
//     > test-vectors/ergo-crypto/batch-merkle/fixtures.json
//
// Pinning: scrypto 2.3.0 matches ergo's avldb/build.sbt; do not bump
// without confirming the wire format hasn't changed.

import scorex.crypto.authds.LeafData
import scorex.crypto.authds.merkle.{BatchMerkleProof, MerkleTree}
import scorex.crypto.authds.merkle.serialization.BatchMerkleProofSerializer
import scorex.crypto.hash.{Blake2b256, Digest32}

object ExtractBatchMerkleProofs {
  type HF = Blake2b256.type
  implicit val hf: HF = Blake2b256

  private def hex(bs: Array[Byte]): String = bs.map("%02x".format(_)).mkString

  private case class Fixture(
    label: String,
    leafBytes: Seq[Array[Byte]],
    indices: Seq[Int],
    note: String,
  )

  private val fixtures: Seq[Fixture] = Seq(
    Fixture(
      label = "single_leaf_prove_all",
      leafBytes = Seq(Array(0xAA.toByte)),
      indices = Seq(0),
      note = "1-leaf tree -- exercises the always-reduce-at-least-once invariant " +
        "(single-leaf tree root is Blake2b256(0x01 ++ leaf_hash), the odd-trailing wrap).",
    ),
    Fixture(
      label = "adjacent_pair_4leaf",
      leafBytes = (0 until 4).map(i => Array(i.toByte)),
      indices = Seq(0, 1),
      note = "4-leaf tree, prove adjacent pair (shares one parent). Tests the " +
        "in_set dedup path where both siblings of a pair are in the proven set.",
    ),
    Fixture(
      label = "sparse_3_of_8",
      leafBytes = (0 until 8).map(i => Array(i.toByte)),
      indices = Seq(0, 3, 5),
      note = "8-leaf tree, prove indices 0, 3, 5. Yields both Side=Left and " +
        "Side=Right non-empty siblings -- catches a left/right inversion.",
    ),
    Fixture(
      label = "full_4leaf_all_indices",
      leafBytes = (0 until 4).map(i => Array(i.toByte)),
      indices = Seq(0, 1, 2, 3),
      note = "Full-tree proof: every leaf in the proven set, so proofs.len() == 0. " +
        "Pins the empty-proofs-section codec path.",
    ),
    Fixture(
      label = "odd_count_5leaf_prove_last",
      leafBytes = (0 until 5).map(i => Array(i.toByte)),
      indices = Seq(4),
      note = "5-leaf tree, prove the trailing single leaf. Forces an empty-sibling " +
        "(EmptyByteArray / 32-zero-byte) entry above the leaf level -- exercises " +
        "the None-digest decode ambiguity.",
    ),
    Fixture(
      label = "deep_32leaf_sparse_proof",
      // 32 leaves => 5-level tree, the deepest the test corpus exercises.
      // Each leaf is `[index]` so the bytes stay readable.
      leafBytes = (0 until 32).map(i => Array(i.toByte)),
      indices = Seq(2, 7, 15, 30),
      note = "32-leaf tree, sparse 4-leaf proof. Exercises multi-level reduction " +
        "depth beyond the toy shapes -- catches a level-counter bug that surfaces " +
        "only on trees with more than 3 internal levels.",
    ),
    Fixture(
      label = "unsorted_dup_indices_4_of_8",
      leafBytes = (0 until 8).map(i => Array(i.toByte)),
      // Indices are intentionally unsorted + contain a duplicate.
      // Scala's proofByIndices normalizes (sort + dedup); Rust's
      // merkle_proof_by_indices does the same. Pins parity on the
      // normalization edge.
      indices = Seq(5, 0, 3, 0, 5),
      note = "Unsorted + duplicate-index input. Both Scala and Rust normalize " +
        "(sort + dedup); fixture pins byte-identity after normalization.",
    ),
  )

  def main(args: Array[String]): Unit = {
    val ser = new BatchMerkleProofSerializer[Digest32, HF]
    val records: Seq[String] = fixtures.map { fx =>
      val leaves: Seq[LeafData] = fx.leafBytes.map(b => LeafData @@ b)
      val tree = MerkleTree[Digest32](leaves)
      val proof: BatchMerkleProof[Digest32] = tree.proofByIndices(fx.indices).get
      val bytes = ser.serialize(proof)
      val proofIndices = proof.indices.map(_._1)
      val proofCount = proof.proofs.length

      s"""  {
         |    "label": "${fx.label}",
         |    "leaves": [${fx.leafBytes.map(b => "\"" + hex(b) + "\"").mkString(", ")}],
         |    "indices": [${fx.indices.mkString(", ")}],
         |    "expected_root": "${hex(tree.rootHash)}",
         |    "expected_bytes": "${hex(bytes)}",
         |    "expected_proof_indices": [${proofIndices.mkString(", ")}],
         |    "expected_proof_count": $proofCount,
         |    "note": "${fx.note.replace("\"", "\\\"")}"
         |  }""".stripMargin
    }
    println("[")
    println(records.mkString(",\n"))
    println("]")
  }
}

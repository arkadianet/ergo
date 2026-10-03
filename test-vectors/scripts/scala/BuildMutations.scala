//> using scala 2.12.20
//> using dep org.ergoplatform::ergo-wallet:6.0.6
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.5

// Construct a complete mutation set from one captured source box and height.
// Input: one JSON object on stdin with height and sourceBox. No network reads.
// Output: seven JSONL rows; txJson and txHex are encoded from the same object.

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import io.circe.parser._
import io.circe.syntax._
import io.circe._
import scorex.crypto.authds.ADKey
import scorex.util.encode.Base16
import sigma.serialization.SigmaSerializer
import java.io._
import java.net._

object BuildMutations extends JsonCodecs {
  def serializeTx(tx: ErgoLikeTransaction): String = {
    val w = SigmaSerializer.startWriter()
    ErgoLikeTransactionSerializer.serialize(tx, w)
    Base16.encode(w.toBytes)
  }

  def makeInput(boxIdBytes: Array[Byte], proofBytes: Array[Byte] = Array.emptyByteArray): Input = {
    val ext = sigma.interpreter.ContextExtension.empty
    val proof = sigma.interpreter.ProverResult(proofBytes, ext)
    new Input(ADKey @@ boxIdBytes, proof)
  }

  def emit(label: String, category: String, tx: ErgoLikeTransaction, height: Int, sourceBox: ErgoBox, sourceBoxJson: Json): Unit = {
    val obj = Json.obj(
      "label" -> Json.fromString(label),
      "category" -> Json.fromString(category),
      "txHex" -> Json.fromString(serializeTx(tx)),
      "txJson" -> tx.asJson,
      "sourceBox" -> sourceBoxJson,
      "height" -> Json.fromInt(height),
      "sourceBoxId" -> Json.fromString(Base16.encode(sourceBox.id))
    )
    println(obj.noSpaces)
  }

  def main(args: Array[String]): Unit = {
    val captured = parse(scala.io.Source.stdin.mkString).getOrElse(sys.error("invalid captured context"))
    val contextSourceBox = captured.hcursor.downField("sourceBox").focus.getOrElse(sys.error("missing source box"))
    val height = captured.hcursor.get[Int]("height").getOrElse(sys.error("missing height"))
    val sourceBox = captured.hcursor.get[ErgoBox]("sourceBox")(ergoBoxDecoder)
      .getOrElse(sys.error("missing/invalid source box"))

    val boxIdBytes = sourceBox.id
    val boxValue = sourceBox.value
    val simpleTree = sigma.ast.ErgoTree.fromHex(
      "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    // --- Mutation 1: ERG inflation ---
    {
      val inflatedOut = new ErgoBoxCandidate(boxValue + 1000000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(inflatedOut))
      emit("erg_inflation", "MONETARY", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 2: Duplicate inputs ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input, input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("duplicate_inputs", "STRUCTURAL", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 3: Invalid proof (wrong bytes) ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val badProof = Array.fill(32)(0xAB.toByte)
      val input = makeInput(boxIdBytes, badProof)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("invalid_proof", "PROOF", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 4: Empty proof on non-trivial script ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("empty_proof_nontrivial", "SCRIPT", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 5: No inputs ---
    {
      val normalOut = new ErgoBoxCandidate(1000000L, simpleTree, height)
      val tx = new ErgoLikeTransaction(IndexedSeq.empty, IndexedSeq.empty, IndexedSeq(normalOut))
      emit("no_inputs", "STRUCTURAL", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 6: Missing input (reference non-existent box) ---
    {
      val fakeId = Array.fill[Byte](32)(0xFF.toByte)
      val normalOut = new ErgoBoxCandidate(1000000L, simpleTree, height)
      val input = makeInput(fakeId)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("missing_input_box", "STRUCTURAL", tx, height, sourceBox, contextSourceBox)
    }

    // --- Mutation 7: Output value too low ---
    {
      val tinyOut = new ErgoBoxCandidate(1L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(tinyOut))
      emit("output_value_too_low", "MONETARY", tx, height, sourceBox, contextSourceBox)
    }

    System.err.println(s"  Generated 7 mutations")
  }
}

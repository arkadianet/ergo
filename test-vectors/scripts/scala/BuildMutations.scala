//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

// Construct invalid transaction mutations from current UTXO boxes.
//
// Fetches recent unspent boxes from a running Ergo node, constructs
// known-invalid transactions, serializes them using Scala, and outputs
// them as JSONL for validation against the node's /transactions/check.
//
// Output format (stdout, JSONL):
//   {"label":"...","category":"...","txHex":"...","height":...,"sourceBoxId":"..."}

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
  val NODE_URL: String = sys.env.getOrElse("NODE_URL", "http://localhost:9053")

  def httpGet(path: String): String = {
    val url = new URL(s"$NODE_URL$path")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET"); conn.setConnectTimeout(10000); conn.setReadTimeout(60000)
    val reader = new BufferedReader(new InputStreamReader(conn.getInputStream))
    val sb = new StringBuilder; var line: String = null
    while ({ line = reader.readLine(); line != null }) sb.append(line)
    reader.close(); conn.disconnect(); sb.toString()
  }

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

  def emit(label: String, category: String, txHex: String, height: Int, sourceBoxId: String): Unit = {
    val obj = Json.obj(
      "label" -> Json.fromString(label),
      "category" -> Json.fromString(category),
      "txHex" -> Json.fromString(txHex),
      "height" -> Json.fromInt(height),
      "sourceBoxId" -> Json.fromString(sourceBoxId)
    )
    println(obj.noSpaces)
  }

  def main(args: Array[String]): Unit = {
    // Accept source box ID as argument to ensure deterministic box selection
    val sourceBoxId = if (args.nonEmpty) args(0) else ""

    val infoJson = parse(httpGet("/info")).getOrElse(sys.error("no info"))
    val height = infoJson.hcursor.get[Int]("fullHeight").getOrElse(sys.error("no height"))
    System.err.println(s"  Node at height $height")

    var sourceBox: ErgoBox = null

    if (sourceBoxId.nonEmpty) {
      // Use the provided box ID
      val fullBoxJson = httpGet(s"/blockchain/box/byId/$sourceBoxId")
      sourceBox = decode[ErgoBox](fullBoxJson)(ergoBoxDecoder).getOrElse(sys.error(s"failed to parse box $sourceBoxId"))
      System.err.println(s"  Using provided box: $sourceBoxId (value=${sourceBox.value})")
    } else {
      // Find a recent unspent box
      var testHeight = height
      while (sourceBox == null && testHeight > height - 100) {
        try {
          val headerIds = parse(httpGet(s"/blocks/at/$testHeight")).getOrElse(Json.arr())
          val headerId = headerIds.as[Seq[String]].getOrElse(Seq.empty).headOption.getOrElse("")
          if (headerId.nonEmpty) {
            val blockTxs = parse(httpGet(s"/blocks/$headerId/transactions")).getOrElse(Json.obj())
            val outputs = blockTxs.hcursor.downField("transactions").downN(0)
              .downField("outputs").focus
            outputs.foreach { arr =>
              arr.asArray.getOrElse(Vector.empty).foreach { outJson =>
                if (sourceBox == null) {
                  val bid = outJson.hcursor.get[String]("boxId").getOrElse("")
                  if (bid.nonEmpty) {
                    try {
                      val utxoResp = httpGet(s"/utxo/byId/$bid")
                      if (utxoResp.nonEmpty) {
                        val fullBoxJson = httpGet(s"/blockchain/box/byId/$bid")
                        sourceBox = decode[ErgoBox](fullBoxJson)(ergoBoxDecoder).getOrElse(null)
                        System.err.println(s"  Found unspent box at height $testHeight: $bid (value=${sourceBox.value})")
                      }
                    } catch { case _: Exception => }
                  }
                }
              }
            }
          }
        } catch { case _: Exception => }
        testHeight -= 1
      }
    }

    if (sourceBox == null) sys.error("Could not find an unspent box")

    val boxIdBytes = sourceBox.id
    val boxValue = sourceBox.value
    val simpleTree = sigma.ast.ErgoTree.fromHex(
      "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    // --- Mutation 1: ERG inflation ---
    {
      val inflatedOut = new ErgoBoxCandidate(boxValue + 1000000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(inflatedOut))
      emit("erg_inflation", "MONETARY", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 2: Duplicate inputs ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input, input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("duplicate_inputs", "STRUCTURAL", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 3: Invalid proof (wrong bytes) ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val badProof = Array.fill(32)(0xAB.toByte)
      val input = makeInput(boxIdBytes, badProof)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("invalid_proof", "PROOF", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 4: Empty proof on non-trivial script ---
    {
      val normalOut = new ErgoBoxCandidate(boxValue - 1000000L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("empty_proof_nontrivial", "SCRIPT", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 5: No inputs ---
    {
      val normalOut = new ErgoBoxCandidate(1000000L, simpleTree, height)
      val tx = new ErgoLikeTransaction(IndexedSeq.empty, IndexedSeq.empty, IndexedSeq(normalOut))
      emit("no_inputs", "STRUCTURAL", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 6: Missing input (reference non-existent box) ---
    {
      val fakeId = Array.fill[Byte](32)(0xFF.toByte)
      val normalOut = new ErgoBoxCandidate(1000000L, simpleTree, height)
      val input = makeInput(fakeId)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(normalOut))
      emit("missing_input_box", "STRUCTURAL", serializeTx(tx), height, sourceBoxId)
    }

    // --- Mutation 7: Output value too low ---
    {
      val tinyOut = new ErgoBoxCandidate(1L, simpleTree, height)
      val input = makeInput(boxIdBytes)
      val tx = new ErgoLikeTransaction(IndexedSeq(input), IndexedSeq.empty, IndexedSeq(tinyOut))
      emit("output_value_too_low", "MONETARY", serializeTx(tx), height, sourceBoxId)
    }

    System.err.println(s"  Generated 7 mutations")
  }
}

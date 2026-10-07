//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
//> using repository "ivy2Local"
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
// Run from the repository root with the SANTA parse-acceptance JSON files.
// Prints received proposition bytes, canonical wire bytes, transaction message,
// IDs and output UTXO serialization, independently of expected_bytes_hex.
import io.circe.Json
import io.circe.parser.parse
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.serialization.SigmaSerializer
import org.ergoplatform.ErgoBox
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.wallet.boxes.ErgoBoxSerializer
object CanonicalizationOracle {
  def h(b: Array[Byte]): Json = Json.fromString(Base16.encode(b))
  def main(args: Array[String]): Unit = args.foreach { file =>
    val json = parse(scala.io.Source.fromFile(file).mkString).fold(throw _, identity)
    json.hcursor.downField("entries").values.get.foreach { e =>
      val c = e.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      val bytes = Base16.decode(c.get[String]("bytes_hex").fold(throw _, identity)).get
      val activated = c.downField("version").get[Int]("activated").fold(throw _, identity).toByte
      val version = c.downField("version").get[Int]("ergoTree").fold(throw _, identity).toByte
      val kind = c.get[String]("kind").fold(throw _, identity)
      val fields = try VersionContext.withVersions(activated, version) {
        kind match {
          case "Box" =>
            val box = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(bytes))
            Seq("canonical_hex" -> h(ErgoBox.sigmaSerializer.toBytes(box)),
                "received_box_hex" -> h(box.bytes), "box_id" -> h(box.id),
                "proposition_hex" -> h(box.propositionBytes))
          case "Transaction" =>
            val tx = ErgoTransactionSerializer.parseBytes(bytes)
            val canonical = ErgoTransactionSerializer.toBytes(tx)
            val message = tx.messageToSign
            val id = tx.id.toString
            val output = VersionContext.withVersions(1.toByte, 1.toByte) {
              val box = tx.outputs.head
              Seq("output_bytes_hex" -> h(box.bytes), "output_box_id" -> h(box.id),
                  "stored_output_hex" -> h(ErgoBoxSerializer.toBytes(box)),
                  "proposition_hex" -> h(box.propositionBytes))
            }
            Seq("canonical_hex" -> h(canonical), "message_hex" -> h(message),
                "transaction_id" -> Json.fromString(id)) ++ output
        }
      } catch { case e: Throwable => Seq("reject" -> Json.fromString(e.getClass.getSimpleName)) }
      println(Json.obj((Seq("name" -> Json.fromString(name), "kind" -> Json.fromString(kind),
        "bytes_hex" -> h(bytes), "version" -> c.downField("version").focus.get) ++ fields): _*).noSpaces)
    }
  }
}

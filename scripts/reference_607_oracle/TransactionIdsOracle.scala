// Independent ergo-core 6.0.7 transaction, witness, and output box ids.
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
import io.circe.parser.parse
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.modifiers.history.header.Header
import scorex.util.encode.Base16
import sigma.VersionContext
object TransactionIdsOracle {
  def main(args: Array[String]): Unit = {
    val source = scala.io.Source.fromFile(args(0))
    val json = try parse(source.mkString).fold(throw _, identity) finally source.close()
    json.hcursor.get[Vector[io.circe.Json]]("entries").fold(throw _, identity).foreach { entry =>
      val c = entry.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      val bytes = Base16.decode(c.get[String]("tx_bytes_hex").fold(throw _, identity)).get
      val version = c.downField("parameters").get[Int]("blockVersion").getOrElse(
        c.downField("preHeader").get[Int]("version").fold(throw _, identity)).toByte
      val versions = Header.scriptAndTreeFromBlockVersions(version)
      val tx = VersionContext.withVersions(versions.activatedVersion, versions.ergoTreeVersion) {
        ErgoTransactionSerializer.parseBytes(bytes)
      }
      println(s"$name\t${tx.id}\t${Base16.encode(tx.witnessSerializedId)}\t${tx.outputs.map(o => Base16.encode(o.id)).mkString(",")}")
    }
  }
}

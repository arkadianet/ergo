// Print the Scala node's tx id, messageToSign and output box ids/bytes for fixture entries.
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
import io.circe.parser.parse
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.modifiers.history.header.Header
import org.ergoplatform.modifiers.history.BlockTransactions
import org.ergoplatform.modifiers.history.BlockTransactionsSerializer
import sigma.serialization.SigmaSerializer
import scorex.util.encode.Base16
import sigma.VersionContext
import scala.util.{Try, Success, Failure}
object TransactionIdsOracle {
  def main(args: Array[String]): Unit = {
    val only = if (args.length > 1) args(1).split(",").toSet else Set.empty[String]
    val json = parse(scala.io.Source.fromFile(args(0)).mkString).fold(throw _, identity)
    json.hcursor.get[Vector[io.circe.Json]]("entries").fold(throw _, identity).foreach { entry =>
      val c = entry.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      if (only.isEmpty || only.contains(name)) {
        val txBytes = Base16.decode(c.get[String]("tx_bytes_hex").fold(throw _, identity)).get
        val blockVersion = c.downField("preHeader").get[Int]("version").fold(throw _, identity)
        val res = Try {
          val versions = Header.scriptAndTreeFromBlockVersions(blockVersion.toByte)
          val tx = VersionContext.withVersions(versions.activatedVersion, versions.ergoTreeVersion) {
            ErgoTransactionSerializer.parseBytes(txBytes)
          }
          val outs = tx.outputs.zipWithIndex.map { case (o, i) =>
            val ob = Try(Base16.encode(o.bytes)).getOrElse("ERR")
            s"out$i.id=${Try(Base16.encode(o.id)).getOrElse("ERR")} out$i.bytes=$ob out$i.proposition=${Base16.encode(o.propositionBytes)}"
          }
          val sections = Seq(1, 4).map { v =>
            val w = SigmaSerializer.startWriter()
            w.putBytes(Array.fill[Byte](32)(0x11))
            if (v > 1) w.putUInt(10000000L + v)
            w.putUInt(1); w.putBytes(txBytes)
            val raw = w.toBytes
            val bt = BlockTransactionsSerializer.parseBytes(raw)
            s"section$v.bytes=${Base16.encode(raw)} section$v.canonical=${Base16.encode(BlockTransactionsSerializer.toBytes(bt))} section$v.root=${Base16.encode(bt.digest)} section$v.id=${bt.id}"
          }
          s"txid=${tx.id} msg=${Base16.encode(tx.messageToSign)} ${outs.mkString(" ")} ${sections.mkString(" ")}"
        }
        res match {
          case Success(s) => println(s"$name\tOK\t$s")
          case Failure(e) => println(s"$name\tEXC\t${e.getClass.getName}: ${e.getMessage}")
        }
      }
    }
  }
}

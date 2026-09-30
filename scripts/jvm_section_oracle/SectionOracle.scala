// Compile against the unmodified Ergo 6.0.7 assembly (Scala 2.12.20).
// Exercises production history insertion and the byte lookup used by
// ErgoNodeViewSynchronizer.modifiersReq, including a database reopen.
import java.nio.file.Files
import scala.concurrent.duration._
import scala.io.Source
import io.circe.Json
import io.circe.syntax._
import org.ergoplatform.modifiers.BlockSection
import org.ergoplatform.modifiers.history.{BlockTransactions, BlockTransactionsSerializer}
import org.ergoplatform.nodeView.history.storage.HistoryStorage
import org.ergoplatform.settings.{CacheSettings, HistoryCacheSettings, MempoolCacheSettings, NetworkCacheSettings}
import scorex.db.{ByteArrayWrapper, LDBFactory}
import scorex.util.encode.Base16

object SectionOracle {
  def main(args: Array[String]): Unit = {
    val directory = Files.createTempDirectory("ergo-section-oracle-").toFile
    val settings = CacheSettings(HistoryCacheSettings(8, 8, 8, 8),
      NetworkCacheSettings(8, 1.minute), MempoolCacheSettings(8, 1.minute))
    def open(): HistoryStorage = new HistoryStorage(
      LDBFactory.createKvDb(directory + "/index"),
      LDBFactory.createKvDb(directory + "/objects"),
      LDBFactory.createKvDb(directory + "/extra"), settings)
    var storage = open()
    try {
      Source.stdin.getLines().foreach { line =>
        val Array(label, wireHex) = line.split(" ", 2)
        val wire = Base16.decode(wireHex).get
        val parsed = BlockTransactionsSerializer.parseBytesTry(wire)
        val result = parsed.map { section =>
          val canonical = BlockTransactionsSerializer.toBytes(section)
          storage.insert(Array.empty[(ByteArrayWrapper, Array[Byte])], Array[BlockSection](section)).get
          val stored = storage.modifierBytesById(section.id).get
          val served = storage.modifierTypeAndBytesById(section.id).get
          require(served._1 == BlockTransactions.modifierTypeId)
          val rest = storage.modifierById(section.id).get.asInstanceOf[BlockTransactions]
            .asJson(BlockTransactions.jsonEncoder)
          storage.close()
          storage = open()
          require(storage.modifierBytesById(section.id).get.sameElements(stored))
          val reopenedRest = storage.modifierById(section.id).get.asInstanceOf[BlockTransactions]
            .asJson(BlockTransactions.jsonEncoder)
          Json.obj("label" -> label.asJson, "accepted" -> true.asJson,
            "wire_hex" -> wireHex.asJson, "canonical_hex" -> Base16.encode(canonical).asJson,
            "stored_hex" -> Base16.encode(stored).asJson,
            "served_hex" -> Base16.encode(served._2).asJson,
            "header_id" -> section.headerId.toString.asJson, "block_version" -> section.blockVersion.toInt.asJson,
            "tx_ids" -> section.txs.map(_.id.toString).asJson,
            "transactions_root" -> Base16.encode(section.digest).asJson,
            "section_id" -> section.id.toString.asJson, "rest_json_cached" -> rest, "rest_json_reopened" -> reopenedRest)
        }.recover { case error => Json.obj("label" -> label.asJson,
          "accepted" -> false.asJson, "wire_hex" -> wireHex.asJson,
          "error" -> error.toString.asJson) }.get
        println(result.noSpaces)
      }
    } finally {
      storage.close()
      import scala.collection.JavaConverters._
      val files = Files.walk(directory.toPath)
      try files.iterator().asScala.toSeq.reverse.foreach(Files.delete)
      finally files.close()
    }
  }
}

//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.ergoplatform::ergo-wallet:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.15
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.io.File
import com.typesafe.config.ConfigFactory
import io.circe.Json
import io.circe.parser.parse
import org.ergoplatform.ErgoBox
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.nodeView.state.{ErgoState, ErgoStateContext, VotingData}
import org.ergoplatform.settings.{CheckpointSettings, ErgoSettingsReader, Parameters}
import org.ergoplatform.settings.{ChainSettings, ErgoValidationSettings, ErgoValidationSettingsUpdate}
import scorex.util.encode.Base16
import sigma.serialization.SigmaSerializer
import scala.util.Try

object CheckpointOracle {
  def read(path: String): Json = {
    val input = new java.io.FileInputStream(path)
    val stream = if (path.endsWith(".gz")) {
      try new java.util.zip.GZIPInputStream(input)
      catch { case error: Throwable => input.close(); throw error }
    } else input
    val source = scala.io.Source.fromInputStream(stream, "UTF-8")
    try parse(source.mkString).right.get finally source.close()
  }
  def bytes(value: String): Array[Byte] = Base16.decode(value).get
  def main(args: Array[String]): Unit = {
    require(args.length == 1, "Usage: CheckpointOracle output.json")
    val fixturePath = "test-vectors/ergo-sigma/cost-total/breakdown_700000_700001.json"
    val fixture = read(fixturePath).hcursor
    val resources = new File("scripts/jvm_block_oracle/.work/source/src/main/resources")
    val config = ConfigFactory.parseString("scorex.logging.level = ERROR\nergo.node.stateType = utxo")
      .withFallback(ConfigFactory.parseFile(new File(resources, "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(resources, "application.conf")))
      .withFallback(ConfigFactory.defaultReference()).resolve()
    val settings = ErgoSettingsReader.fromConfig(config)
    implicit val chainSettings: ChainSettings = settings.chainSettings
    val headers = fixture.get[Vector[Json]]("headers").right.get.map { row =>
      val h = HeaderSerializer.parseBytesTry(bytes(row.hcursor.get[String]("bytes").right.get)).get
      h.height -> h
    }.toMap
    val boxes = fixture.get[Vector[Json]]("boxes").right.get.map { row =>
      val b = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(bytes(row.hcursor.get[String]("bytes").right.get)))
      Base16.encode(b.id) -> b
    }.toMap
    val epochs = read("test-vectors/ergo-sigma/cost-total/mainnet-epochs.json.gz").hcursor.get[Vector[Json]]("epochs").right.get
    val observations = fixture.get[Vector[Json]]("transactions").right.get.flatMap { row =>
      val c = row.hcursor
      val height = c.get[Int]("height").right.get
      val epoch = epochs.find(_.hcursor.get[Int]("height").right.get == height / 1024 * 1024).get
      val table = epoch.hcursor.get[Vector[Vector[String]]]("fields").right.get.collect {
        case Vector(key, value) if key.startsWith("00") && value.length == 8 =>
          bytes(key)(1) -> java.nio.ByteBuffer.wrap(bytes(value)).getInt
      }.toMap
      val p = new Parameters(height, table, ErgoValidationSettingsUpdate.empty)
      val context = new ErgoStateContext((height to height - 9 by -1).map(headers), None,
        settings.chainSettings.genesisStateDigest, p, ErgoValidationSettings.initial, VotingData.empty)
      val tx = ErgoTransactionSerializer.parseBytes(bytes(c.get[String]("tx_bytes").right.get))
      Vector(None, Some(height - 1), Some(height), Some(height + 1)).map { checkpoint =>
        var boxReads = 0
        val node = settings.nodeSettings.copy(checkpoint = checkpoint.map(h => CheckpointSettings(h, headers(height).id)))
        val cost = ErgoState.execTransactions(Seq(tx), context, node) { id =>
          boxReads += 1
          Try(boxes(Base16.encode(id)))
        }.toTry.get
        Json.obj("tx_id" -> Json.fromString(tx.id), "height" -> Json.fromInt(height),
          "checkpoint_height" -> checkpoint.map(Json.fromInt).getOrElse(Json.Null),
          "block_cost" -> Json.fromLong(cost), "box_reads" -> Json.fromInt(boxReads))
      }
    }
    val result = Json.obj("oracle" -> Json.fromString("Ergo 6.0.5 ErgoState.execTransactions"),
      "fixture" -> Json.fromString(fixturePath), "observations" -> Json.arr(observations: _*))
    val writer = new java.io.PrintWriter(args(0), "UTF-8")
    try writer.println(result.spaces2) finally writer.close()
  }
}

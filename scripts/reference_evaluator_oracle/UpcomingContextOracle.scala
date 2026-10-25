// What scripts see when ergo-core 6.0.7 validates a transaction for the block
// after a tip: its mempool context (`ErgoStateContext.simplifiedUpcoming()`)
// and a mining candidate's (`ErgoStateContext.upcoming(...)`).
// Run from the repository root:
// scala-cli run scripts/reference_evaluator_oracle/UpcomingContextOracle.scala \
//   --server=false --jvm system -- test-vectors/reference-6.0.7/upcoming-context/cases.json
// Input: {"cases": [{"name", "headers_hex" (newest first, the tip first)}]}.
// Output: one JSON object per case, in input order. Diagnostics go to stderr.
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7

import io.circe.Json
import io.circe.parser.parse
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings.{ChainSettings, ChainSettingsReader, ErgoValidationSettings,
  ErgoValidationSettingsUpdate, Parameters, TestnetLaunchParameters}
import scorex.util.encode.Base16
import sigma.data.CGroupElement

object UpcomingContextOracle {
  private implicit lazy val chainSettings: ChainSettings =
    ChainSettingsReader.read("scripts/santa_tx_oracle/chain-testnet.conf").get

  private def hex(bytes: Array[Byte]): String = Base16.encode(bytes)

  private def context(upcoming: ErgoStateContext): Json = {
    val pre = upcoming.sigmaPreHeader
    Json.obj(
      "last_header_heights" -> Json.fromValues(
        upcoming.sigmaLastHeaders.toArray.map(h => Json.fromInt(h.height))),
      "height" -> Json.fromInt(pre.height),
      "parent_id" -> Json.fromString(hex(pre.parentId.toArray)),
      "timestamp" -> Json.fromLong(pre.timestamp),
      "n_bits" -> Json.fromLong(pre.nBits),
      "version" -> Json.fromInt(pre.version.toInt),
      "votes" -> Json.fromString(hex(pre.votes.toArray)),
      "miner_pk" -> Json.fromString(hex(pre.minerPk.getEncoded.toArray)))
  }

  def main(args: Array[String]): Unit = {
    System.setProperty("logback.configurationFile", "scripts/santa_tx_oracle/logback.xml")
    val source = scala.io.Source.fromFile(args(0))
    val json = try parse(source.mkString).fold(throw _, identity) finally source.close()
    json.hcursor.get[Vector[Json]]("cases").fold(throw _, identity).foreach { entry =>
      val c = entry.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      val headers = c.get[Vector[String]]("headers_hex").fold(throw _, identity)
        .map(h => HeaderSerializer.parseBytes(Base16.decode(h).get))
      val tip = headers.head
      val params = new Parameters(tip.height, TestnetLaunchParameters.parametersTable,
        ErgoValidationSettingsUpdate.empty)
      val committed = new ErgoStateContext(headers, None, chainSettings.genesisStateDigest,
        params, ErgoValidationSettings.initial, VotingData.empty)
      // A candidate mined by 2*G at tip + 7 ms with votes 01 02 03.
      val candidateMiner = CGroupElement(org.ergoplatform.mining.group.generator)
        .multiply(CGroupElement(org.ergoplatform.mining.group.generator)).asInstanceOf[CGroupElement].wrappedValue
      val candidate = committed.upcoming(candidateMiner, tip.timestamp + 7, tip.nBits,
        Array[Byte](1, 2, 3), ErgoValidationSettingsUpdate.empty, tip.version)
      println(Json.obj(
        "name" -> Json.fromString(name),
        "tip_id" -> Json.fromString(tip.id.toString),
        "committed_last_header_heights" -> Json.fromValues(
          committed.sigmaLastHeaders.toArray.map(h => Json.fromInt(h.height))),
        "mempool" -> context(committed.simplifiedUpcoming()),
        "candidate" -> context(candidate)).noSpaces)
    }
  }
}

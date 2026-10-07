// Independent JVM verdicts for santa-transaction/v1. Run from the repository root:
// scala-cli run -q scripts/santa_tx_oracle/SantaTxOracle.scala -- <vector.json>
// Emits <entry> TAB <valid> TAB <cost or null>. Never reads `expected`.
// Recipe: SANTA's TxEngine / provided-context contract at a7a128bb (MIT):
// https://github.com/mwaddip/santa/blob/a7a128bb/docs/contract/runner-contract-transaction.md
// Malformed serialization and validateStateful failures become rejection
// verdicts. Positive controls pin successful parsing, validation and cost.
// ergo-core 6.0.7 is available in the GitLab Maven repository below or via
// publishLocal from ergoplatform/ergo v6.0.7, as for SantaWireOracle.
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7

import io.circe.Json
import io.circe.parser.parse
import org.ergoplatform.modifiers.history.CPreHeader
import org.ergoplatform.modifiers.history.header.{Header, HeaderSerializer}
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.nodeView.state.{UpcomingStateContext, VotingData}
import org.ergoplatform.settings.{ChainSettings, ChainSettingsReader, ErgoValidationSettings,
  ErgoValidationSettingsUpdate, Parameters, TestnetLaunchParameters}
import org.ergoplatform.wallet.boxes.ErgoBoxSerializer
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import scala.util.{Failure, Success, Try}

object TransactionSerializationOracle {
  private implicit lazy val chainSettings: ChainSettings =
    ChainSettingsReader.read("scripts/santa_tx_oracle/chain-testnet.conf").get

  private def validate(entry: Json): (Boolean, Option[Long]) = {
    val c = entry.hcursor
    val ph = c.downField("preHeader")
    val pc = c.downField("parameters")
    def p(k: String): Int = pc.get[Int](k).fold(throw _, identity)
    def phInt(k: String): Int = ph.get[Int](k).fold(throw _, identity)
    def phString(k: String): String = ph.get[String](k).fold(throw _, identity)
    def hex(s: String): Array[Byte] = Base16.decode(s).get
    def hexes(k: String): Vector[String] = c.get[Vector[String]](k).fold(throw _, identity)
    val preVersion = phInt("version").toByte
    val blockVersion = pc.get[Int]("blockVersion").getOrElse(preVersion.toInt)
    val height = phInt("height")
    require(c.downField("context").get[Int]("height").fold(throw _, identity) == height,
      "context.height differs from preHeader.height")
    val overrides = Seq(
      Parameters.BlockVersion -> blockVersion,
      Parameters.MaxBlockCostIncrease -> p("maxBlockCost"),
      Parameters.StorageFeeFactorIncrease -> p("storageFeeFactor"),
      Parameters.MinValuePerByteIncrease -> p("minValuePerByte"),
      Parameters.InputCostIncrease -> p("inputCost"),
      Parameters.DataInputCostIncrease -> p("dataInputCost"),
      Parameters.OutputCostIncrease -> p("outputCost"),
      Parameters.TokenAccessCostIncrease -> p("tokenAccessCost"))
    val params = new Parameters(height, TestnetLaunchParameters.parametersTable ++ overrides,
      ErgoValidationSettingsUpdate.empty)
    val headers = hexes("headers_hex").map(h => HeaderSerializer.parseBytes(hex(h)))
    val parentId = if (headers.nonEmpty) headers.head.id else Header.GenesisParentId
    require(parentId.toString == phString("parentId").toLowerCase,
      "preHeader.parentId differs from the provided header tip")
    val timestamp = ph.get[String]("timestamp").toOption.map(_.toLong)
      .orElse(ph.get[Long]("timestamp").toOption).getOrElse(sys.error("preHeader.timestamp"))
    val preHeader = CPreHeader(preVersion, parentId, timestamp,
      ph.get[Long]("nBits").fold(throw _, identity), height, hex(phString("votes")),
      GroupElementSerializer.parse(SigmaSerializer.startReader(hex(phString("minerPk")))))
    val context = UpcomingStateContext(headers, None, preHeader, chainSettings.genesisStateDigest,
      params, ErgoValidationSettings.initial, VotingData.empty)
    val txBytes = hex(c.get[String]("tx_bytes_hex").fold(throw _, identity))
    val tx = if (blockVersion >= Header.Interpreter60Version) {
      val versions = Header.scriptAndTreeFromBlockVersions(blockVersion.toByte)
      VersionContext.withVersions(versions.activatedVersion, versions.ergoTreeVersion) {
        ErgoTransactionSerializer.parseBytes(txBytes)
      }
    } else ErgoTransactionSerializer.parseBytes(txBytes)
    // UTXO boxes and validation run in the ambient default (1, 1) context.
    val inputs = hexes("input_boxes_hex").map(h => ErgoBoxSerializer.parseBytes(hex(h)))
    val dataInputs = hexes("data_input_boxes_hex").map(h => ErgoBoxSerializer.parseBytes(hex(h)))
    implicit val verifier: ErgoInterpreter = ErgoInterpreter(params)
    Try(tx.validateStateful(inputs, dataInputs, context, 0L).result.toTry).flatten match {
      case Success(cost) => (true, Some(cost.toLong))
      case Failure(error) =>
        System.err.println(s"${c.get[String]("name").getOrElse("?")}: ${error.getClass.getName}: ${error.getMessage}")
        if (sys.env.get("SANTA_TX_ORACLE_TRACE").contains("1")) error.printStackTrace(System.err)
        (false, None)
    }
  }

  def main(args: Array[String]): Unit = {
    System.setProperty("logback.configurationFile", "scripts/santa_tx_oracle/logback.xml")
    args.foreach { path =>
      val source = scala.io.Source.fromFile(path)
      val json = try parse(source.mkString).fold(throw _, identity) finally source.close()
      require(json.hcursor.get[String]("schema").getOrElse("") == "santa-transaction/v1")
      json.hcursor.get[Vector[Json]]("entries").fold(throw _, identity).foreach { entry =>
        val name = entry.hcursor.get[String]("name").fold(throw _, identity)
        // Sigma proof parsing also writes diagnostics with println. Keep all
        // library output off TSV stdout, including direct System.out writes.
        val stdout = System.out
        val (valid, cost) = try {
          System.setOut(System.err)
          Console.withOut(System.err) {
            Try(validate(entry)) match {
              case Success(v) => v
              case Failure(error) =>
                System.err.println(s"$name: ${error.getClass.getName}: ${error.getMessage}")
                (false, None)
            }
          }
        } finally System.setOut(stdout)
        stdout.println(s"$name\t$valid\t${cost.map(_.toString).getOrElse("null")}")
      }
    }
  }
}

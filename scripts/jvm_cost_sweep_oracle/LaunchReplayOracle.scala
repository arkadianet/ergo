//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.ergoplatform::ergo-wallet:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.13.0
//> using file ../../test-vectors/scripts/scala/ComputeTransactionCosts.scala
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.io.File
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import io.circe.Json
import io.circe.parser._
import org.ergoplatform._
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import org.ergoplatform.wallet.boxes.ErgoBoxAssetExtractor
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.encode.Base16
import scala.collection.mutable

/** Offline replay of frozen mainnet launch bytes through production validateStateful. */
object LaunchReplayOracle extends org.ergoplatform.sdk.JsonCodecs
    with PowSchemeReaders with ModifierIdReader with SettingsReaders {
  private def read(path: String): Json = parse(new String(Files.readAllBytes(Paths.get(path)), "UTF-8")).right.get
  private def sha(path: String): String = MessageDigest.getInstance("SHA-256")
    .digest(Files.readAllBytes(Paths.get(path))).map(b => f"${b & 255}%02x").mkString

  def main(args: Array[String]): Unit = {
    require(args.sameElements(Array("replay")) || args.sameElements(Array("replay_self_test")))
    val reference = sys.env.getOrElse("ERGO_REFERENCE",
      s"${sys.props("user.home")}/coding/development/arkadianet/ergo-scala")
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(reference, "src/main/resources/mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(reference, "src/main/resources/application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val source = "test-vectors/mainnet/"
    val headerRecords = read(source + "headers_1_10.json").asArray.get.take(5)
    val headers = headerRecords.map(j => HeaderSerializer.parseBytes(Base16.decode(j.hcursor.get[String]("bytes").right.get).get))
    val boxes = mutable.Map[String, ErgoBox]()
    read(source + "genesis_boxes.json").asArray.get.foreach { j =>
      val b = j.as[ErgoBox](ergoBoxDecoder).right.get
      boxes(Base16.encode(b.id)) = b
    }
    val p = Parameters(0, Parameters.DefaultParameters, ErgoValidationSettingsUpdate.empty)
    val params = Json.obj("storage_fee_factor" -> Json.fromInt(p.storageFeeFactor),
      "min_value_per_byte" -> Json.fromInt(p.minValuePerByte),
      "max_block_cost" -> Json.fromInt(p.maxBlockCost), "input_cost" -> Json.fromInt(p.inputCost),
      "data_input_cost" -> Json.fromInt(p.dataInputCost), "output_cost" -> Json.fromInt(p.outputCost),
      "token_access_cost" -> Json.fromInt(p.tokenAccessCost), "block_version" -> Json.fromInt(p.blockVersion))
    val transactions = mutable.ArrayBuffer[Json]()
    val blocks = read(source + "blocks_1_5.json").asArray.get
    blocks.foreach { block =>
      val height = block.hcursor.get[Int]("height").right.get
      val current = headers(height - 1)
      require(current.id == block.hcursor.get[String]("headerId").right.get)
      val state = new ErgoStateContext(headers.take(height).reverse, None, chain.genesisStateDigest,
        p, ErgoValidationSettings.initial, VotingData.empty)
      block.hcursor.downField("transactions").focus.get.asArray.get.foreach { j =>
        val tx = ErgoTransactionSerializer.parseBytes(Base16.decode(j.hcursor.get[String]("bytes").right.get).get)
        require(tx.id == j.hcursor.get[String]("id").right.get)
        val inputs = tx.inputs.map(i => boxes(Base16.encode(i.boxId))).toIndexedSeq
        val data = tx.dataInputs.map(i => boxes(Base16.encode(i.boxId))).toIndexedSeq
        val recorder = new ComputeTransactionCosts.RecordingInterpreter(p)
        val total = tx.validateStateful(inputs, data, state, 0L)(recorder).result.toTry.get
        val init = ErgoInterpreter.interpreterInitCost.toLong + inputs.size.toLong * p.inputCost +
          data.size.toLong * p.dataInputCost + tx.outputCandidates.size.toLong * p.outputCost
        val (inAssets, inCount) = ErgoBoxAssetExtractor.extractAssets(inputs).get
        val (outAssets, outCount) = tx.outAssetsTry.get
        val token = ErgoBoxAssetExtractor.totalAssetsAccessCost(inCount, inAssets.size,
          outCount, outAssets.size, p.tokenAccessCost).toLong
        require(recorder.inputs.map(_.index) == tx.inputs.indices)
        require(init + token + recorder.inputs.map(i => i.eval + i.crypto + i.rent).sum == total)
        transactions += Json.obj("tx_id" -> Json.fromString(tx.id), "height" -> Json.fromInt(height),
          "block_cost" -> Json.fromLong(total), "init_block_cost" -> Json.fromLong(init),
          "token_block_cost" -> Json.fromLong(token), "inputs" -> Json.arr(recorder.inputs.map(_.json): _*),
          "tx_bytes" -> Json.fromString(Base16.encode(tx.bytes)))
        tx.outputs.foreach(b => boxes(Base16.encode(b.id)) = b)
      }
    }
    require(blocks.size == 5 && transactions.size == 5)
    require(transactions.forall(_.hcursor.get[Long]("block_cost").right.get == 12344L))
    val script = "scripts/jvm_cost_sweep_oracle/LaunchReplayOracle.scala"
    val revision = scala.sys.process.Process(Seq("git", "rev-parse", "HEAD")).!!.trim
    val command = s"scala-cli run $script --server=false --main-class LaunchReplayOracle -- replay"
    val timestamp = java.time.Instant.now().toString
    val fixture = Json.obj("manifest" -> Json.obj(
      "ergo_core_version" -> Json.fromString("6.0.5"), "ergo_wallet_version" -> Json.fromString("6.0.5"),
      "sigma_state_version" -> Json.fromString("6.0.6"), "node_app_version" -> Json.Null,
      "source" -> Json.fromString("frozen mainnet blocks 1-5 and genesis boxes; offline replay"),
      "scala" -> Json.obj("ergo_version" -> Json.fromString("6.0.5"),
        "sigmastate_version" -> Json.fromString("6.0.6"), "node_app_version" -> Json.Null),
      "rust" -> Json.obj("git_sha" -> Json.fromString(revision),
        "toolchain" -> Json.fromString(scala.sys.process.Process(Seq("rustc", "--version")).!!.trim),
        "features" -> Json.arr()),
      "context" -> Json.obj("network" -> Json.fromString("mainnet"),
        "height_range" -> Json.arr(Json.fromInt(1), Json.fromInt(5)),
        "activated_script_version" -> Json.fromInt(0), "block_version" -> Json.fromInt(p.blockVersion),
        "voted_params" -> params),
      "tool" -> Json.obj("script" -> Json.fromString(script), "git_sha" -> Json.fromString(revision),
        "script_sha256" -> Json.fromString(sha(script)), "recorder_sha256" -> Json.fromString(sha("test-vectors/scripts/scala/ComputeTransactionCosts.scala")),
        "scala_cli_version" -> Json.fromString(scala.sys.process.Process(Seq("scala-cli", "version", "--cli-version")).!!.trim),
        "jvm_version" -> Json.fromString(System.getProperty("java.runtime.version"))),
      "run" -> Json.obj("command" -> Json.fromString(command), "timestamp" -> Json.fromString(timestamp),
        "seeds" -> Json.arr(), "selected" -> Json.fromInt(transactions.size), "executed" -> Json.fromInt(transactions.size),
        "skipped" -> Json.fromInt(0), "failed" -> Json.fromInt(0)),
      "inputs" -> Json.obj(Seq("headers_1_10.json", "blocks_1_5.json", "genesis_boxes.json")
        .map(f => f -> Json.fromString(sha(source + f))): _*)),
      "parameters" -> Json.obj((1 to 5).map(h => h.toString -> params): _*),
      "headers" -> Json.arr(headerRecords: _*),
      "boxes" -> Json.arr(boxes.toSeq.sortBy(_._1).map { case (id, b) =>
        Json.obj("box_id" -> Json.fromString(id), "bytes" -> Json.fromString(Base16.encode(b.bytes)))
      }: _*), "transactions" -> Json.arr(transactions: _*))
    if (args(0) == "replay_self_test") println(s"replay_self_test: ${transactions.size} accepted, reconciled; 5 launch blocks")
    else {
      val payload = Json.fromJsonObject(fixture.asObject.get.remove("manifest")).spaces2
      val digest = MessageDigest.getInstance("SHA-256").digest(payload.getBytes("UTF-8"))
        .map(b => f"${b & 255}%02x").mkString
      println(fixture.deepMerge(Json.obj("manifest" -> Json.obj("evidence" -> Json.obj(
        "payload_sha256" -> Json.fromString(digest),
        "hash_scope" -> Json.fromString("UTF-8 Circe spaces2 excluding manifest and final newline"))))).spaces2)
    }
  }
}

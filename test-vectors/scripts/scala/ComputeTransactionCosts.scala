//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.ergoplatform::ergo-wallet:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.13.0
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

// Usage: scala-cli run ComputeTransactionCosts.scala --server=false -- <start> <end>
// Requires an extraIndex node (NODE_URL) and the v6.0.5 source configuration
// (ERGO_REFERENCE). Stdout is the transaction array; stderr includes a manifest.
// Any missing input, validation failure, or reconciliation mismatch aborts extraction.

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import org.ergoplatform.modifiers.mempool.ErgoTransaction
import org.ergoplatform.wallet.boxes.ErgoBoxAssetExtractor
import org.ergoplatform.modifiers.history.header.{Header, HeaderSerializer}
import org.ergoplatform.modifiers.history.extension.ExtensionCandidate
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import io.circe.parser._
import io.circe._
import scorex.util.encode.Base16
import sigma.ast.ErgoTree
import sigmastate.interpreter.Interpreter.{ScriptEnv, VerificationResult, ReductionResult}
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import java.io._
import java.net._
import java.nio.ByteBuffer
import scala.collection.mutable
import scala.util.Try

object ComputeTransactionCosts extends JsonCodecs with PowSchemeReaders
    with ModifierIdReader with SettingsReaders {
  val NODE_URL: String = sys.env.getOrElse("NODE_URL", "http://localhost:9053")
  // Mainnet voting epoch length (Parameters.votingLength in chainSettings)
  val VOTING_EPOCH_LENGTH = 1024


  // Parameter byte IDs matching Scala Parameters.scala constants.
  // System params are stored in extension fields with 2-byte keys: 0x00 ++ paramId
  val PARAM_STORAGE_FEE_FACTOR: Byte = 1
  val PARAM_MIN_VALUE_PER_BYTE: Byte  = 2
  val PARAM_MAX_BLOCK_SIZE: Byte      = 3
  val PARAM_MAX_BLOCK_COST: Byte      = 4
  val PARAM_TOKEN_ACCESS_COST: Byte   = 5
  val PARAM_INPUT_COST: Byte          = 6
  val PARAM_DATA_INPUT_COST: Byte     = 7
  val PARAM_OUTPUT_COST: Byte         = 8
  val PARAM_BLOCK_VERSION: Byte       = 123.toByte // 0x7b

  // Active voted parameters — defaults match mainnet initial state.
  // activatedScriptVersion = blockVersion - 1 (JIT cost model since EIP-37 ~h417792)
  case class ActiveParams(
    storageFeeFactor: Int = 1250000,
    minValuePerByte:  Int = 360,
    maxBlockSize:     Int = 524288,
    tokenAccessCost:  Int = 100,
    inputCost:        Int = 2000,
    dataInputCost:    Int = 100,
    outputCost:       Int = 100,
    maxBlockCost:    Long = 1000000L,
    blockVersion:     Int = 2
  )

  // Parse system parameters from extension fields.
  // Returns Some(updated) if the extension contains a BlockVersion field (epoch start),
  // None if this is a non-epoch block (no system params present).
  def parseParamsFromExtension(
      fields: Vector[(String, String)],
      prev: ActiveParams
  ): Option[ActiveParams] = {
    val paramMap = mutable.Map[Byte, Int]()
    for ((keyHex, valHex) <- fields) {
      val keyBytes = Base16.decode(keyHex).getOrElse(Array.empty[Byte])
      val valBytes = Base16.decode(valHex).getOrElse(Array.empty[Byte])
      if (keyBytes.length == 2 && valBytes.length == 4 && keyBytes(0) == 0.toByte) {
        paramMap(keyBytes(1)) = ByteBuffer.wrap(valBytes).getInt()
      }
    }
    if (!paramMap.contains(PARAM_BLOCK_VERSION)) None
    else Some(ActiveParams(
      storageFeeFactor = paramMap.getOrElse(PARAM_STORAGE_FEE_FACTOR, prev.storageFeeFactor),
      minValuePerByte  = paramMap.getOrElse(PARAM_MIN_VALUE_PER_BYTE,  prev.minValuePerByte),
      maxBlockSize     = paramMap.getOrElse(PARAM_MAX_BLOCK_SIZE,      prev.maxBlockSize),
      tokenAccessCost  = paramMap.getOrElse(PARAM_TOKEN_ACCESS_COST,   prev.tokenAccessCost),
      inputCost        = paramMap.getOrElse(PARAM_INPUT_COST,          prev.inputCost),
      dataInputCost    = paramMap.getOrElse(PARAM_DATA_INPUT_COST,     prev.dataInputCost),
      outputCost       = paramMap.getOrElse(PARAM_OUTPUT_COST,         prev.outputCost),
      maxBlockCost     = paramMap.getOrElse(PARAM_MAX_BLOCK_COST,      prev.maxBlockCost.toInt).toLong,
      blockVersion     = paramMap(PARAM_BLOCK_VERSION)
    ))
  }


  def parameters(p: ActiveParams, height: Int): Parameters = new Parameters(height, Map(
    PARAM_STORAGE_FEE_FACTOR -> p.storageFeeFactor,
    PARAM_MIN_VALUE_PER_BYTE -> p.minValuePerByte,
    PARAM_MAX_BLOCK_SIZE -> p.maxBlockSize,
    PARAM_MAX_BLOCK_COST -> p.maxBlockCost.toInt,
    PARAM_TOKEN_ACCESS_COST -> p.tokenAccessCost,
    PARAM_INPUT_COST -> p.inputCost,
    PARAM_DATA_INPUT_COST -> p.dataInputCost,
    PARAM_OUTPUT_COST -> p.outputCost,
    PARAM_BLOCK_VERSION -> p.blockVersion
  ), ErgoValidationSettingsUpdate.empty)

  case class InputCost(index: Int, eval: Long, crypto: Long, rent: Long) {
    def json: Json = Json.obj(
      "index" -> Json.fromInt(index), "eval_block_cost" -> Json.fromLong(eval),
      "crypto_block_cost" -> Json.fromLong(crypto), "rent" -> Json.fromLong(rent))
  }

  // Overrides observe return values from the production calls without changing
  // execution, budget, version context, or rounding. No input is re-evaluated.
  class RecordingInterpreter(p: Parameters) extends ErgoInterpreter(p) {
    val inputs = mutable.ArrayBuffer[InputCost]()
    private var reductionCost: Option[Long] = None
    private var rentSucceeded = false

    override def fullReduction(tree: ErgoTree, ctx: CTX, env: ScriptEnv): ReductionResult = {
      val result = super.fullReduction(tree, ctx, env)
      reductionCost = Some(result.cost)
      result
    }

    override protected def checkExpiredBox(box: ErgoBox, output: ErgoBoxCandidate,
                                          height: Int): Boolean = {
      val result = super.checkExpiredBox(box, output, height)
      rentSucceeded = result
      result
    }

    override def verify(env: ScriptEnv, tree: ErgoTree, ctx: CTX,
                        proof: Array[Byte], message: Array[Byte]): Try[VerificationResult] = {
      reductionCost = None
      rentSucceeded = false
      require(ctx.initCost == 0L, s"unexpected input initCost: ${ctx.initCost}")
      val result = super.verify(env, tree, ctx, proof, message)
      result.foreach { case (valid, total) =>
        if (valid) {
          val rent = if (rentSucceeded) 50L else 0L
          // Soft-fork acceptance can bypass fullReduction and return initCost.
          val eval = reductionCost.getOrElse(0L)
          val crypto = total - eval - rent
          require(crypto >= 0 && (!rentSucceeded || total == 50L),
            s"invalid input breakdown: total=$total eval=$eval rent=$rent")
          inputs += InputCost(ctx.selfIndex, eval, crypto, rent)
        }
      }
      result
    }
  }

  // Extract extension fields as (keyHex, valueHex) pairs from a block JSON cursor.
  def extensionFields(cursor: HCursor): Vector[(String, String)] =
    cursor.downField("extension").downField("fields").focus
      .flatMap(_.asArray)
      .getOrElse(Vector.empty)
      .flatMap(_.asArray.flatMap {
        case v if v.size == 2 =>
          for { k <- v(0).asString; vv <- v(1).asString } yield (k, vv)
        case _ => None
      })

  def httpGet(path: String): String = {
    val url  = new URL(s"$NODE_URL$path")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    conn.setConnectTimeout(10000)
    conn.setReadTimeout(60000)
    conn.setRequestProperty("Accept", "application/json")
    val code = conn.getResponseCode
    if (code != 200) throw new RuntimeException(s"HTTP $code for $path")
    val reader = new BufferedReader(new InputStreamReader(conn.getInputStream))
    val sb = new StringBuilder
    var line: String = null
    while ({ line = reader.readLine(); line != null }) sb.append(line)
    reader.close()
    conn.disconnect()
    sb.toString()
  }

  def main(args: Array[String]): Unit = {
    require(args.length == 2, "Usage: ComputeTransactionCosts <start_height> <end_height>")
    val startHeight = args(0).toInt
    val endHeight = args(1).toInt
    require(startHeight > 10 && endHeight >= startHeight)
    val sigmaJar = classOf[sigma.VersionContext].getProtectionDomain.getCodeSource.getLocation.toString
    val version = "6.0.6"
    require(sigmaJar.endsWith(s"sigma-state_2.12-$version.jar"),
      s"Expected resolved sigma-state $version, found $sigmaJar")
    val reference = sys.env.getOrElse("ERGO_REFERENCE",
      s"${sys.props("user.home")}/coding/development/arkadianet/ergo-scala")
    val config = ConfigFactory.defaultOverrides().withFallback(ConfigFactory.parseFile(new File(s"$reference/src/main/resources/mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(s"$reference/src/main/resources/application.conf")))
      .resolve()
    implicit val chainSettings: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val nodeVersion = parse(httpGet("/info")).right.get.hcursor.get[String]("appVersion").right.get
    require(nodeVersion == "6.0.5", s"Expected oracle node 6.0.5, found $nodeVersion")
    val manifest = Json.obj(
      "node_app_version" -> Json.fromString(nodeVersion),
      "headers_source" -> Json.fromString(sys.env.getOrElse("COST_HEADERS", "node block headers")),
      "ergo_core_version" -> Json.fromString("6.0.5"),
      "ergo_wallet_version" -> Json.fromString("6.0.5"),
      "sigma_state_version" -> Json.fromString(version),
      "sigma_state_jar" -> Json.fromString(sigmaJar),
      "node_url" -> Json.fromString(NODE_URL),
      "start_height" -> Json.fromInt(startHeight), "end_height" -> Json.fromInt(endHeight)
    )
    System.err.println(Json.obj("manifest" -> manifest).noSpaces)

    def block(height: Int): Json = {
      val ids = parse(httpGet(s"/blocks/at/$height")).right.get.asArray.get
      require(ids.nonEmpty, s"No block at height $height")
      parse(httpGet(s"/blocks/${ids.head.asString.get}")).right.get
    }
    def header(json: Json): Header = json.hcursor.downField("header").as[Header](Header.jsonDecoder).right.get

    // Both replay engines can consume the same canonical extracted header bytes.
    val extractedHeaders = sys.env.get("COST_HEADERS").map { path =>
      val source = scala.io.Source.fromFile(path, "UTF-8")
      val rows = try parse(source.mkString).right.get.asArray.get finally source.close()
      rows.map { row =>
        val c = row.hcursor
        val h = c.get[Int]("height").right.get
        val hdr = HeaderSerializer.parseBytesTry(Base16.decode(c.get[String]("bytes").right.get).get).get
        require(hdr.height == h, s"Header height mismatch at $h")
        h -> hdr
      }.toMap
    }
    def contextHeader(height: Int): Header = extractedHeaders match {
      case Some(headers) => headers.getOrElse(height,
        throw new IllegalArgumentException(s"Missing context header $height"))
      case None => header(block(height))
    }

    var active = ActiveParams()
    val epoch = (startHeight / VOTING_EPOCH_LENGTH) * VOTING_EPOCH_LENGTH
    val epochBlock = block(epoch)
    def validationSettings(json: Json): ErgoValidationSettings =
      ErgoValidationSettings.parseExtension(ExtensionCandidate(extensionFields(json.hcursor).map {
        case (key, value) => Base16.decode(key).get -> Base16.decode(value).get
      })).get
    var settings = validationSettings(epochBlock)
    active = parseParamsFromExtension(extensionFields(epochBlock.hcursor), active)
      .getOrElse(throw new IllegalStateException(s"Missing epoch parameters at $epoch"))
    // Current header plus nine ancestors is the node's full-block context.
    var ancestors = (startHeight - 1 to startHeight - 9 by -1).map(contextHeader)
    val cache = mutable.Map[String, ErgoBox]()
    def box(id: Array[Byte]): ErgoBox = {
      val hex = Base16.encode(id)
      cache.getOrElseUpdate(hex, decode[ErgoBox](httpGet(s"/blockchain/box/byId/$hex"))(ergoBoxDecoder).right.get)
    }
    val results = mutable.ArrayBuffer[Json]()
    val fixtureTransactions = mutable.ArrayBuffer[Json]()
    val fixtureHeaders = mutable.Map[Int, Header](ancestors.map(h => h.height -> h): _*)
    val fixtureParameters = mutable.Map[String, Json]()
    val fixtureContexts = mutable.Map[String, Json]()
    for (height <- startHeight to endHeight) {
      val json = block(height)
      val current = contextHeader(height)
      require(current.id == header(json).id, s"Extracted header differs from node at $height")
      (current +: ancestors).sliding(2).foreach { pair =>
        require(pair.head.parentId == pair.last.id, s"Disconnected context at ${pair.head.height}")
      }
      fixtureHeaders(height) = current
      parseParamsFromExtension(extensionFields(json.hcursor), active).foreach { p =>
        active = p
        settings = validationSettings(json)
      }
      val p = parameters(active, height)
      fixtureParameters(height.toString) = Json.obj(
        "storage_fee_factor" -> Json.fromInt(p.storageFeeFactor),
        "min_value_per_byte" -> Json.fromInt(p.minValuePerByte),
        "max_block_cost" -> Json.fromInt(p.maxBlockCost),
        "input_cost" -> Json.fromInt(p.inputCost), "data_input_cost" -> Json.fromInt(p.dataInputCost),
        "output_cost" -> Json.fromInt(p.outputCost), "token_access_cost" -> Json.fromInt(p.tokenAccessCost),
        "block_version" -> Json.fromInt(p.blockVersion))
      val state = new ErgoStateContext(current +: ancestors, None, chainSettings.genesisStateDigest,
        p, settings, VotingData.empty)
      require(state.sigmaLastHeaders.length == 9, "Expected nine script-visible ancestors")
      require(Base16.encode(state.previousStateDigest.toArray) == Base16.encode(ancestors.head.stateRoot),
        s"Previous state digest differs from parent at $height")
      fixtureContexts(height.toString) = Json.obj(
        "header_heights" -> Json.arr(ancestors.map(h => Json.fromInt(h.height)): _*),
        "header_ids" -> Json.arr(ancestors.map(h => Json.fromString(h.id)): _*),
        "previous_state_digest" -> Json.fromString(Base16.encode(state.previousStateDigest.toArray)))
      val txs = json.hcursor.downField("blockTransactions").downField("transactions").as[Vector[Json]].right.get
      for (txJson <- txs) {
        val tx = ErgoTransaction(txJson.as[ErgoLikeTransaction](ergoLikeTransactionDecoder).right.get)
        val boxes = tx.inputs.map(i => box(i.boxId)).toIndexedSeq
        val data = tx.dataInputs.map(i => box(i.boxId)).toIndexedSeq
        val recorder = new RecordingInterpreter(p)
        val total = tx.validateStateful(boxes, data, state, 0L)(recorder).result.toTry.get
        val init = ErgoInterpreter.interpreterInitCost.toLong + boxes.size.toLong * p.inputCost +
          data.size.toLong * p.dataInputCost + tx.outputCandidates.size.toLong * p.outputCost
        val (inAssets, inCount) = ErgoBoxAssetExtractor.extractAssets(boxes).get
        val (outAssets, outCount) = tx.outAssetsTry.get
        val token = ErgoBoxAssetExtractor.totalAssetsAccessCost(
          inCount, inAssets.size, outCount, outAssets.size, p.tokenAccessCost).toLong
        require(recorder.inputs.map(_.index) == tx.inputs.indices,
          s"Missing/reordered input observations for ${tx.id}")
        val reconciled = init + token + recorder.inputs.map(i => i.eval + i.crypto + i.rent).sum
        require(reconciled == total,
          s"Reconciliation failed for ${tx.id}: $reconciled != validateStateful $total")
        results += Json.obj("tx_id" -> Json.fromString(tx.id), "height" -> Json.fromInt(height),
          "block_cost" -> Json.fromLong(total), "init_block_cost" -> Json.fromLong(init),
          "token_block_cost" -> Json.fromLong(token),
          "inputs" -> Json.arr(recorder.inputs.map(_.json): _*))
        fixtureTransactions += results.last.deepMerge(Json.obj("tx_bytes" -> Json.fromString(Base16.encode(tx.bytes))))
        tx.outputs.foreach(b => cache(Base16.encode(b.id)) = b)
      }
      System.err.println(s"h=$height: ${txs.size} accepted and reconciled")
      ancestors = (current +: ancestors).take(9)
    }
    System.err.println(s"Done: ${results.size} accepted and reconciled, 0 dropped")
    sys.env.get("COST_FIXTURE").foreach { path =>
      val fixture = Json.obj("manifest" -> manifest,
        "headers" -> Json.arr(fixtureHeaders.toSeq.sortBy(_._1).map { case (h, hdr) =>
          Json.obj("height" -> Json.fromInt(h), "bytes" -> Json.fromString(Base16.encode(hdr.bytes)))
        }: _*),
        "parameters" -> Json.obj(fixtureParameters.toSeq: _*),
        "contexts" -> Json.obj(fixtureContexts.toSeq: _*),
        "boxes" -> Json.arr(cache.toSeq.sortBy(_._1).map { case (id, b) =>
          Json.obj("box_id" -> Json.fromString(id), "bytes" -> Json.fromString(Base16.encode(b.bytes)))
        }: _*),
        "transactions" -> Json.arr(fixtureTransactions: _*))
      val writer = new PrintWriter(new File(path), "UTF-8")
      try writer.println(fixture.spaces2) finally writer.close()
    }
    println(Json.arr(results: _*).spaces2)
  }
}

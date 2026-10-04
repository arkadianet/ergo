// Offline finite replay against the SHA-256 pinned Ergo6.0.5 release assembly.
// Compile with Scala2.12.20 compiler, assembly-only dependency classpath;
// run with classes + assembly, passing capture directory and run-spec JSON.
// No HTTP calls or whole-node startup. Exact commands/hashes in provenance.json.
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

object OfflineHistoricalCosts extends JsonCodecs with PowSchemeReaders
    with ModifierIdReader with SettingsReaders {
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


  def main(args: Array[String]): Unit = {
    require(args.length == 2, "Usage: OfflineHistoricalCosts <capture_directory> <run-spec.json>")
    val dir = new File(args(0))
    val bundleSource = scala.io.Source.fromFile(new File(dir, "capture-inputs.json"), "UTF-8")
    val bundle = try parse(bundleSource.mkString).right.get finally bundleSource.close()
    def read(name: String): Json = parse(bundle.hcursor.get[String](name).right.get).right.get
    require(org.ergoplatform.Version.VersionString == "6.0.5")
    val reference = sys.env("ERGO_REFERENCE")
    val config = ConfigFactory.parseFile(new File(s"$reference/src/main/resources/mainnet.conf"))
      .withFallback(ConfigFactory.parseFile(new File(s"$reference/src/main/resources/application.conf")))
      .withValue("user.home", com.typesafe.config.ConfigValueFactory.fromAnyRef(dir.getAbsolutePath))
      .withValue("user.dir", com.typesafe.config.ConfigValueFactory.fromAnyRef(dir.getAbsolutePath)).resolve()
    implicit val chainSettings: ChainSettings = config.as[ChainSettings]("ergo.chain")
    def block(h: Int): Json = read(s"block-$h.json")
    def hdr(j: Json): Header = j.hcursor.downField("header").as[Header](Header.jsonDecoder).right.get
    val canonicalHeaders = read("canonical-headers-all.json").asArray.get.map { j =>
      val c = j.hcursor
      val bytes = Base16.decode(c.get[String]("bytes").right.get).get
      val h = HeaderSerializer.parseBytesTry(bytes).get
      require(h.id == c.get[String]("id").right.get && h.height == c.get[Int]("height").right.get)
      require(java.util.Arrays.equals(h.bytes, bytes), "canonical header bytes changed")
      h.height -> h
    }.toMap
    def contextHeader(h: Int): Header = canonicalHeaders.getOrElse(h, hdr(block(h)))
    def validationSettings(j: Json): ErgoValidationSettings =
      ErgoValidationSettings.parseExtension(ExtensionCandidate(extensionFields(j.hcursor).map {
        case (key, value) => Base16.decode(key).get -> Base16.decode(value).get
      })).get
    val spec = read(args(1))
    val selectedHeights = spec.hcursor.get[Vector[Int]]("heights").right.get
    val previousEpoch = block(spec.hcursor.get[Int]("preceding_epoch").right.get)
    def parametersFromBlock(j: Json): Parameters = {
      val header = hdr(j)
      require(header.id == j.hcursor.downField("header").get[String]("id").right.get)
      val extension = ExtensionCandidate(extensionFields(j.hcursor).map {
        case (key, value) => Base16.decode(key).get -> Base16.decode(value).get
      }).toExtension(header.id)
      require(java.util.Arrays.equals(extension.digest, header.extensionRoot), "epoch extension root mismatch")
      Parameters.parseExtension(header.height, extension).get
    }
    var currentParameters = parametersFromBlock(previousEpoch)
    var settings = validationSettings(previousEpoch)
    val capture = read(spec.hcursor.get[String]("prerequisite_file").right.get)
    val externalIds = capture.hcursor.get[Vector[String]]("needed_external_box_ids").right.get
    val cache = mutable.Map[String, ErgoBox]()
    externalIds.foreach { id =>
      val raw = read(spec.hcursor.get[String]("box_prefix").right.get + s"$id.json")
      // Explorer registers wrap the same serialized value with human-readable metadata.
      val registers = raw.hcursor.downField("additionalRegisters").focus.get.asObject.get.toMap.map {
        case (k, v) => k -> (if (v.isString) v else v.hcursor.downField("serializedValue").focus.get)
      }
      val normalized = raw.mapObject(_.add("additionalRegisters", Json.obj(registers.toSeq: _*)))
      val b = normalized.as[ErgoBox](ergoBoxDecoder).right.get
      require(Base16.encode(b.id) == id, s"archived input identity mismatch: $id")
      cache(id) = b
    }
    val initialBoxes = cache.toVector.sortBy(_._1)
    val results = mutable.ArrayBuffer[Json]()
    val fixtureHeaders = mutable.Map[Int, Header]()
    val fixtureParameters = mutable.Map[String, Json]()
    val fixtureContexts = mutable.Map[String, Json]()
    fixtureHeaders(hdr(previousEpoch).height) = hdr(previousEpoch)
    for (height <- selectedHeights) {
      val json = block(height)
      val current = contextHeader(height)
      require(current.id == hdr(json).id, s"captured header differs from canonical header at $height")
      require(current.id == json.hcursor.downField("header").get[String]("id").right.get,
        s"reference codec ID differs from advertised captured ID at $height")
      val ancestors = (height - 1 to height - 9 by -1).map(contextHeader)
      (current +: ancestors).sliding(2).foreach { pair =>
        require(pair.head.parentId == pair.last.id, s"disconnected context at ${pair.head.height}")
      }
      (current +: ancestors).foreach(h => fixtureHeaders(h.height) = h)
      if (extensionFields(json.hcursor).exists(_._1 == "007b")) {
        currentParameters = parametersFromBlock(json)
        // Prefix0x02 encodes the complete updateFromInitial, not an epoch delta.
        // The reference decoder reconstructs initial.updated(fullUpdate).
        settings = validationSettings(json)
      }
      val p = currentParameters
      val state = new ErgoStateContext(current +: ancestors, None, chainSettings.genesisStateDigest,
        p, settings, VotingData.empty)
      require(state.sigmaLastHeaders.length == 9)
      require(java.util.Arrays.equals(state.previousStateDigest.toArray, ancestors.head.stateRoot))
      fixtureParameters(height.toString) = Json.obj(
        "storage_fee_factor" -> Json.fromInt(p.storageFeeFactor),
        "min_value_per_byte" -> Json.fromInt(p.minValuePerByte),
        "max_block_size" -> Json.fromInt(p.maxBlockSize),
        "max_block_cost" -> Json.fromInt(p.maxBlockCost),
        "input_cost" -> Json.fromInt(p.inputCost), "data_input_cost" -> Json.fromInt(p.dataInputCost),
        "output_cost" -> Json.fromInt(p.outputCost), "token_access_cost" -> Json.fromInt(p.tokenAccessCost),
        "block_version" -> Json.fromInt(p.blockVersion),
        "validation_settings_bytes" -> Json.fromString(Base16.encode(settings.bytes)),
        "epoch_height" -> Json.fromInt(p.height),
        "parameter_table" -> Json.obj(p.parametersTable.toSeq.sortBy(_._1).map {
          case (id, v) => id.toString -> Json.fromInt(v)
        }: _*),
        "sigma_rule_statuses" -> Json.obj(Seq(1007, 1008, 1017, 1018).map { id =>
          id.toString -> Json.fromString(settings.sigmaSettings.getStatus(id.toShort).toString)
        }: _*),
        "rule_215_active" -> Json.fromBoolean(settings.isActive(215)),
        "rule_409_active" -> Json.fromBoolean(settings.isActive(409)))
      fixtureContexts(height.toString) = Json.obj(
        "header_heights" -> Json.arr(ancestors.map(h => Json.fromInt(h.height)): _*),
        "header_ids" -> Json.arr(ancestors.map(h => Json.fromString(h.id)): _*),
        "previous_state_digest" -> Json.fromString(Base16.encode(state.previousStateDigest.toArray)))
      val txs = json.hcursor.downField("blockTransactions").downField("transactions").as[Vector[Json]].right.get
      var blockCost = 0L
      for (txJson <- txs) {
        val tx = ErgoTransaction(txJson.as[ErgoLikeTransaction](ergoLikeTransactionDecoder).right.get)
        tx.validateStateless().result.toTry.get
        val boxes = tx.inputs.map(i => cache(Base16.encode(i.boxId))).toIndexedSeq
        val data = tx.dataInputs.map(i => cache(Base16.encode(i.boxId))).toIndexedSeq
        val recorder = new RecordingInterpreter(p)
        // Match production cumulative budget accounting; per-tx cost is the delta.
        val cumulative = tx.validateStateful(boxes, data, state, blockCost)(recorder).result.toTry.get
        val total = cumulative - blockCost
        blockCost = cumulative
        val init = ErgoInterpreter.interpreterInitCost.toLong + boxes.size.toLong * p.inputCost +
          data.size.toLong * p.dataInputCost + tx.outputCandidates.size.toLong * p.outputCost
        val (inAssets, inCount) = ErgoBoxAssetExtractor.extractAssets(boxes).get
        val (outAssets, outCount) = tx.outAssetsTry.get
        val token = ErgoBoxAssetExtractor.totalAssetsAccessCost(
          inCount, inAssets.size, outCount, outAssets.size, p.tokenAccessCost).toLong
        require(recorder.inputs.map(_.index) == tx.inputs.indices)
        val reconciled = init + token + recorder.inputs.map(i => i.eval + i.crypto + i.rent).sum
        require(reconciled == total, s"cost mismatch ${tx.id}: $reconciled != $total")
        results += Json.obj("tx_id" -> Json.fromString(tx.id), "height" -> Json.fromInt(height),
          "block_cost" -> Json.fromLong(total), "init_block_cost" -> Json.fromLong(init),
          "token_block_cost" -> Json.fromLong(token),
          "inputs" -> Json.arr(recorder.inputs.map(_.json): _*),
          "tx_bytes" -> Json.fromString(Base16.encode(tx.bytes)),
          "bytes_to_sign" -> Json.fromString(Base16.encode(tx.messageToSign)))
        tx.outputs.foreach(b => cache(Base16.encode(b.id)) = b)
      }
      System.err.println(s"h=$height version=${p.blockVersion} txs=${txs.size} cost=$blockCost")
    }
    require(results.size == selectedHeights.map(h =>
      block(h).hcursor.downField("blockTransactions").downField("transactions").as[Vector[Json]].right.get.size).sum,
      "every advertised transaction must be recorded")
    val fixture = Json.obj(
      "manifest" -> Json.obj("ergo_version" -> Json.fromString(org.ergoplatform.Version.VersionString),
        "scope" -> Json.fromString("offline fixed historical transactions with archived subset; no global UTXO reconstruction or full-node admission")),
      "headers" -> Json.arr(fixtureHeaders.toSeq.sortBy(_._1).map { case (h, hdr) =>
        Json.obj("height" -> Json.fromInt(h), "bytes" -> Json.fromString(Base16.encode(hdr.bytes)))
      }: _*),
      "parameters" -> Json.obj(fixtureParameters.toSeq: _*),
      "contexts" -> Json.obj(fixtureContexts.toSeq: _*),
      "initial_boxes" -> Json.arr(initialBoxes.map { case (id, b) =>
        Json.obj("box_id" -> Json.fromString(id), "bytes" -> Json.fromString(Base16.encode(b.bytes)))
      }: _*),
      "transactions" -> Json.arr(results: _*))
    println(fixture.spaces2)
  }
}

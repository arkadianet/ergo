//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2
//> using dep org.ergoplatform::ergo-wallet:6.0.2

// Usage: scripts/gen-cost-sweep.sh
// Fresh secrets and prover randomness are deliberately regenerated; captured bytes are the replay inputs.
import java.io.File
import java.nio.file.{Files, Paths}
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import io.circe.Json
import org.ergoplatform._
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import org.ergoplatform.sdk.wallet.secrets.DlogSecretKey
import org.ergoplatform.wallet.interpreter.{ErgoInterpreter, ErgoProvingInterpreter}
import scorex.util.{bytesToId}
import scorex.util.encode.Base16
import sigma.exceptions.CostLimitException
import sigma.Colls
import sigma.ast.{ErgoTree, SigmaPropConstant}
import sigma.serialization.GroupElementSerializer
import sigma.data.{CAND, CTHRESHOLD, SigmaBoolean, CGroupElement}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.Interpreter
import sigmastate.interpreter.Interpreter.{ScriptEnv, VerificationResult}
import scala.util.{Success, Failure, Try}

object CostSweepOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val keys = Vector.fill(3)(DlogSecretKey(DLogProverInput.random()))
    val pubs = keys.map(_.privateInput.publicImage)
    def params(limit: Int) = Parameters(1000000, Map[Byte, Int](
      1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288,
      4.toByte -> limit, 5.toByte -> 100, 6.toByte -> 2000,
      7.toByte -> 100, 8.toByte -> 100, 123.toByte -> 3), ErgoValidationSettingsUpdate.empty)
    def context(limit: Int) = new ErgoStateContext(Seq.empty, None, chain.genesisStateDigest,
      params(limit), ErgoValidationSettings.initial, VotingData.empty) {
      override def sigmaPreHeader: sigma.PreHeader = CPreHeader(3.toByte,
        Colls.fromArray(Array.fill(32)(0.toByte)), 0L, 0L, 1051200,
        CGroupElement(pubs.head.value), Colls.fromArray(Array.fill(3)(0.toByte)))
    }
    val prover = new ErgoProvingInterpreter(keys, params(1000000))
    val outTree = ErgoTree.fromProposition(SigmaPropConstant(pubs.head))
    def makeCase(name: String, n: Int, prop: SigmaBoolean, token: Boolean = false): Json = {
      val rent = name == "rent-success"
      val tree = if (name == "eval-remainders") sigma.serialization.ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(Base16.decode("00d1dad90101017201010101").get) else ErgoTree.fromProposition(SigmaPropConstant(prop))
      val tokens = if (token) Colls.fromArray(Array((sigma.data.Digest32Coll @@ Colls.fromArray(Array.fill(32)(42.toByte)), 1L))) else Colls.emptyColl[(sigma.data.Digest32Coll, Long)]
      val boxes = (0 until n).map(i => new ErgoBox(1000000000L, tree, tokens,
        Map.empty, bytesToId(Array.fill(32)((i + 1).toByte)), i.toShort, if (rent) 0 else 1000000)).toIndexedSeq
      val unsigned = new UnsignedErgoLikeTransaction(boxes.map(b => new UnsignedInput(b.id)),
        IndexedSeq.empty, IndexedSeq(new ErgoBoxCandidate(n * 1000000000L, if (rent) tree else outTree, if (rent) 1051200 else 1000000, if (token) Colls.fromArray(Array((sigma.data.Digest32Coll @@ Colls.fromArray(Array.fill(32)(42.toByte)), n.toLong))) else tokens)))
      val signed = if (rent) new ErgoLikeTransaction(boxes.map(b => Input(b.id,
        sigma.interpreter.ProverResult(Array.emptyByteArray,
          sigma.interpreter.ContextExtension(Map(127.toByte -> sigma.ast.ShortConstant(0.toShort)))))),
        IndexedSeq.empty, unsigned.outputCandidates)
      else prover.sign(unsigned, boxes, IndexedSeq.empty, context(1000000)).get
      val original = io.circe.parser.parse(new String(Files.readAllBytes(Paths.get(args(2))), "UTF-8")).right.get
      val stored = original.hcursor.downField("cases").as[Vector[Json]].right.get.find(_.hcursor.get[String]("name").right.get == name)
      val tx = stored.map(c => ErgoTransactionSerializer.parseBytes(Base16.decode(c.hcursor.get[String]("tx_bytes").right.get).get)).getOrElse(ErgoTransaction(signed.inputs, signed.dataInputs, signed.outputCandidates))
      val actualBoxes = stored.map(c => c.hcursor.get[Vector[Json]]("input_boxes").right.get.map(b => ErgoBox.sigmaSerializer.parse(sigma.serialization.SigmaSerializer.startReader(Base16.decode(b.hcursor.get[String]("bytes").right.get).get)))).getOrElse(boxes)
      val accumulated = 1000L
      def isCostLimit(error: Throwable): Boolean =
        Iterator.iterate(error)(_.getCause).takeWhile(_ != null)
          .exists(_.isInstanceOf[CostLimitException])
      def validate(limit: Int) = {
        var interpreterCostFailure = false
        implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params(limit)) {
          override def verify(env: ScriptEnv, exp: ErgoTree, context: CTX,
                              proof: Array[Byte], message: Array[Byte]): Try[VerificationResult] = {
            val result = super.verify(env, exp, context, proof, message)
            // Transaction validation embeds this failure in text and drops its cause chain.
            result.failed.foreach(error => interpreterCostFailure ||= isCostLimit(error))
            result
          }
        }
        val result = tx.validateStateful(actualBoxes, IndexedSeq.empty, context(limit), accumulatedCost = accumulated).result.toTry
        (result, interpreterCostFailure)
      }
      val cost = validate(1000000)._1.get
      val sweep = (if (token) (accumulated to cost + 1) else Seq(cost - 1, cost, cost + 1, accumulated + 2000L * n + 10099L, accumulated + 2000L * n + 10100L)).distinct.sorted.map { limit =>
        val (result, interpreterCostFailure) = validate(limit.toInt)
        val (verdict, detail) = result match {
          case Success(_) => ("Accept", "")
          case Failure(e) =>
            val detail = e.toString
            require(interpreterCostFailure || isCostLimit(e) || detail.contains("initial cost") || detail.contains("cost exceeds limit") || detail.contains("assets cost"), detail)
            ("RejectCost", detail)
        }
        Json.obj("limit" -> Json.fromLong(limit), "verdict" -> Json.fromString(verdict),
          "detail" -> Json.fromString(detail), "total" -> result.map(Json.fromLong).getOrElse(Json.fromString("unavailable")))
      }
      Json.obj("name" -> Json.fromString(name),
        "tx_bytes" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx))),
        "accumulated_block_cost" -> Json.fromLong(accumulated),
        "input_boxes" -> Json.arr(actualBoxes.map(b => Json.obj("box_id" -> Json.fromString(Base16.encode(b.id)),
          "bytes" -> Json.fromString(Base16.encode(b.bytes)))): _*),
        "crypto_jit_per_input" -> Json.fromInt(Interpreter.estimateCryptoVerifyCost(prop).value),
        "block_cost" -> Json.fromLong(cost), "verdict" -> Json.fromString("Accept"),
        "sweep" -> Json.arr(sweep: _*))
    }
    val p = params(1000000)
    def artifact(cls: Class[_]): Json = {
      val path = Paths.get(cls.getProtectionDomain.getCodeSource.getLocation.toURI)
      val digest = java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))
      Json.obj("file" -> Json.fromString(path.getFileName.toString), "sha256" -> Json.fromString(Base16.encode(digest)))
    }
    val result = Json.obj(
      "jvm" -> Json.fromString(System.getProperty("java.runtime.version")),
      "artifacts" -> Json.arr(artifact(classOf[ErgoTransaction]), artifact(classOf[ErgoProvingInterpreter]), artifact(classOf[ErgoTree])),
      "context" -> Json.obj("height" -> Json.fromInt(1051200),
        "activated_script_version" -> Json.fromInt(2), "block_version" -> Json.fromInt(3),
        "ergo_tree_version" -> Json.fromInt(0), "timestamp" -> Json.fromLong(0), "n_bits" -> Json.fromLong(0),
        "miner_pk_hex" -> Json.fromString(Base16.encode(GroupElementSerializer.toBytes(pubs.head.value))),
        "voted_params" -> Json.obj(p.parametersTable.toSeq.sortBy(_._1).map { case (id, value) => id.toString -> Json.fromInt(value) }: _*)),
      "cases" -> Json.arr(
      makeCase("TX-A", 2, CAND(pubs.take(2))),
      makeCase("TX-B", 4, CTHRESHOLD(2, pubs)),
      makeCase("token-exhaustion", 1, sigma.data.TrivialProp.TrueProp, token = true),
      makeCase("eval-remainders", 4, sigma.data.TrivialProp.TrueProp),
      makeCase("rent-success", 1, pubs.head)))
    Files.write(Paths.get(args(1)), result.spaces2.getBytes("UTF-8"))
  }
}

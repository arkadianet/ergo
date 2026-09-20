//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2
//> using dep org.ergoplatform::ergo-wallet:6.0.2

// Usage: scripts/gen-cost-sweep.sh --verifier-throws-only
// Deterministic missing-variable script; the wallet interpreter returns Failure.
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
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.{bytesToId}
import scorex.util.encode.Base16
import sigma.Colls
import sigma.ast.{ErgoTree, SigmaPropConstant}
import sigma.serialization.GroupElementSerializer
import sigma.data.CGroupElement
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.Interpreter.{ScriptEnv, VerificationResult}
import scala.util.{Success, Try}

// The diagnostic runs disable transaction checks only to expose the local sentinel.
// Normal validation always uses the initial rules and never returns an accepted cost.
object VerifierFailureOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    require(args.length == 3 && Set("verifier_throws", "verifier_throws_self_test").contains(args(0)))
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(1), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(1), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    import sigma.ast._
    val pub = DLogProverInput(java.math.BigInteger.ONE).publicImage
    val tree = ErgoTree.fromProposition(BoolToSigmaProp(EQ(
      OptionGet(GetVar(1.toByte, SInt)), IntConstant(0))))
    val box = new ErgoBox(1000000000L, tree, Colls.emptyColl,
      Map.empty, bytesToId(Array.fill(32)(1.toByte)), 0.toShort, 1000000)
    val tx = ErgoTransaction(IndexedSeq(Input(box.id,
      sigma.interpreter.ProverResult(Array.emptyByteArray, sigma.interpreter.ContextExtension.empty))),
      IndexedSeq.empty, IndexedSeq(new ErgoBoxCandidate(1000000000L,
        ErgoTree.fromProposition(SigmaPropConstant(pub)), 1000000)))
    def params(limit: Int) = Parameters(1000000, Map[Byte, Int](
      1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288,
      4.toByte -> limit, 5.toByte -> 100, 6.toByte -> 2000,
      7.toByte -> 100, 8.toByte -> 100, 123.toByte -> 3), ErgoValidationSettingsUpdate.empty)
    def context(limit: Int, disabled: Seq[Short]) = new ErgoStateContext(Seq.empty, None,
      chain.genesisStateDigest, params(limit), ErgoValidationSettings.initial.updated(
        ErgoValidationSettingsUpdate(disabled, Seq.empty)), VotingData.empty) {
      override def sigmaPreHeader: sigma.PreHeader = CPreHeader(3.toByte,
        Colls.fromArray(Array.fill(32)(0.toByte)), 0L, 0L, 1051200,
        CGroupElement(pub.value), Colls.fromArray(Array.fill(3)(0.toByte)))
    }
    val scriptRule = ValidationRules.txScriptValidation
    val costRule = ValidationRules.bsBlockTransactionsCost
    val points = for (accumulated <- Seq(0L, 1000L); limit <- Seq(20000, 20001, 1000000)) yield {
      var observed: Option[Try[VerificationResult]] = None
      def run(disabled: Seq[Short], zeroCostControl: Boolean = false): Try[Long] = {
        observed = None
        implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params(limit)) {
          override def verify(env: ScriptEnv, exp: ErgoTree, ctx: CTX,
                              proof: Array[Byte], message: Array[Byte]): Try[VerificationResult] = {
            if (zeroCostControl) Success((true, 0L))
            else {
              val result = super.verify(env, exp, ctx, proof, message)
              observed = Some(result)
              result
            }
          }
        }
        val result = tx.validateStateful(IndexedSeq(box), IndexedSeq.empty, context(limit, disabled),
          accumulatedCost = accumulated).result.toTry
        if (!zeroCostControl) require(observed.exists(_.isFailure), "verifier must return Failure")
        result
      }
      val normal = run(Seq.empty)
      require(observed.exists(_.isFailure), "must exercise Failure, not Success(false,cost)")
      val exception = observed.get.failed.get.getClass.getName
      require(exception == "java.util.NoSuchElementException")
      val detail = normal.failed.get.toString
      require(detail.contains("Scripts of all transaction inputs should pass verification"), detail)
      val costOnly = run(Seq(scriptRule))
      require(costOnly.failed.get.toString.contains("cost exceeds limit after input #0"))
      val before = run(Seq.empty, zeroCostControl = true).get
      val unchecked = run(Seq(scriptRule, costRule)).get
      val sentinel = unchecked - before
      require(sentinel == limit.toLong + 1)
      Json.obj("limit" -> Json.fromInt(limit), "accumulated_block_cost" -> Json.fromLong(accumulated),
        "verdict" -> Json.fromString("RejectScript"), "total" -> Json.fromString("unavailable"),
        "verifier_result" -> Json.fromString("Failure"), "exception" -> Json.fromString(exception),
        "detail" -> Json.fromString(detail), "sentinel_block_cost" -> Json.fromLong(sentinel),
        "diagnostic_zero_script_total" -> Json.fromLong(before),
        "diagnostic_unchecked_total" -> Json.fromLong(unchecked),
        "diagnostic_cost_rejection" -> Json.fromString(costOnly.failed.get.toString))
    }
    def artifact(cls: Class[_]): Json = {
      val path = Paths.get(cls.getProtectionDomain.getCodeSource.getLocation.toURI)
      Json.obj("file" -> Json.fromString(path.getFileName.toString), "sha256" -> Json.fromString(
        Base16.encode(java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)))))
    }
    val result = Json.obj("points" -> Json.arr(points: _*),
      "artifacts" -> Json.arr(artifact(classOf[ErgoTransaction]), artifact(classOf[ErgoInterpreter]), artifact(classOf[ErgoTree])),
      "context" -> Json.obj("height" -> Json.fromInt(1051200), "activated_script_version" -> Json.fromInt(2),
        "block_version" -> Json.fromInt(3), "timestamp" -> Json.fromLong(0), "n_bits" -> Json.fromLong(0),
        "miner_pk_hex" -> Json.fromString(Base16.encode(GroupElementSerializer.toBytes(pub.value))),
        "voted_params" -> Json.obj(params(1000000).parametersTable.toSeq.sortBy(_._1).map {
          case (id, value) => id.toString -> Json.fromInt(value) }: _*)),
      "case" -> Json.obj("name" -> Json.fromString("verifier-throws"),
        "tx_bytes" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx))),
        "input_boxes" -> Json.arr(Json.obj("box_id" -> Json.fromString(Base16.encode(box.id)),
          "bytes" -> Json.fromString(Base16.encode(box.bytes)))),
        "verdict" -> Json.fromString("RejectScript"), "block_cost" -> Json.fromString("unavailable")))
    Files.write(Paths.get(args(2)), result.spaces2.getBytes("UTF-8"))
    if (args(0) == "verifier_throws_self_test") println("verifier_throws_self_test: 6 passed, 0 failed")
  }
}

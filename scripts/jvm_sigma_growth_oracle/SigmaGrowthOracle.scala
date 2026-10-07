//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository ivy2Local
//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep org.ergoplatform::ergo-core:6.0.6

// Generate independently compiled fold/reduction/verification fixtures.
// scala-cli run scripts/jvm_sigma_growth_oracle/SigmaGrowthOracle.scala --server=false -- <output.json>
import java.math.BigInteger
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import io.circe.Json
import org.ergoplatform.{ErgoBox, ErgoLikeContext, ErgoLikeInterpreter, ErgoLikeTransaction}
import org.ergoplatform.validation.ValidationRules
import scorex.util.bytesToId
import scorex.util.encode.Base16
import sigma.{Colls, Header, VersionContext}
import sigma.ast.{ErgoTree, JitCost, SSigmaProp, Value, SigmaPropBytes}
import sigma.compiler.ir.CompiletimeIRContext
import sigma.compiler.SigmaCompiler
import sigma.crypto.CryptoConstants
import sigma.data.{AvlTreeData, CSigmaProp, SigmaBoolean, CAND, COR, CTHRESHOLD}
import sigma.interpreter.ContextExtension
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer}
import sigma.util.Extensions.EcpOps
import sigma.eval.Extensions.SigmaBooleanOps
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{CErgoTreeEvaluator, CostAccumulator, Interpreter}
import sigmastate.interpreter.CErgoTreeEvaluator.DefaultEvalSettings
import scala.util.{Failure, Success}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.interpreter.ProverInterpreter
import sigmastate.interpreter.HintsBag

object SigmaGrowthOracle {
  def main(args: Array[String]): Unit = {
    val compiler = new SigmaCompiler(0.toByte)
    val interpreter = new ErgoLikeInterpreter { override type CTX = ErgoLikeContext }
    val generator = CryptoConstants.dlogGroup.generator
    val point = GroupElementSerializer.parse(SigmaSerializer.startReader(
      GroupElementSerializer.toBytes(generator))).toGroupElement
    val cases = Seq(1, 5, 10, 16).map { n =>
      val source = s"Coll(${Seq.fill(n)("0").mkString(",")}).fold(proveDlog(groupGenerator), { (a: SigmaProp, i: Int) => a && a })"
      VersionContext.withVersions(3.toByte, 3.toByte) {
        val result = compiler.compile(Map.empty, source)(new CompiletimeIRContext)
        val proposition = result.buildTree.asInstanceOf[Value[SSigmaProp.type]]
        val tree = ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(3.toByte), proposition)
        val self = new ErgoBox(1000000L, tree,
          transactionId = bytesToId(Array.fill(32)(0.toByte)), index = 0.toShort, creationHeight = 0)
        val ctx = new ErgoLikeContext(
          lastBlockUtxoRoot = AvlTreeData.dummy,
          headers = Colls.emptyColl[Header],
          preHeader = CPreHeader(4.toByte, Colls.fromArray(Array.fill(32)(0.toByte)),
            3L, 0L, 0, point, Colls.fromArray(Array.fill(3)(0.toByte))),
          dataBoxes = IndexedSeq.empty,
          boxesToSpend = IndexedSeq(self),
          spendingTransaction = ErgoLikeTransaction(IndexedSeq(), IndexedSeq()),
          selfIndex = 0, extension = ContextExtension.empty,
          validationSettings = ValidationRules.currentSettings,
          costLimit = 100000L, initCost = 0L, activatedScriptVersion = 3.toByte
        ).withErgoTreeVersion(3.toByte)
        val accumulator = new CostAccumulator(JitCost.fromBlockCost(0), Some(JitCost.fromBlockCost(100000)))
        val (value, _) = CErgoTreeEvaluator.eval(ctx.toSigmaContext(), accumulator,
          tree.constants, tree.toProposition(tree.isConstantSegregation && tree.hasDeserialize), DefaultEvalSettings)
        val sigma = value.asInstanceOf[CSigmaProp].sigmaTree
        val bytes = SigmaBoolean.serializer.toBytes(sigma)
        val verification = interpreter.verify(Interpreter.emptyEnv, tree, ctx, Array.emptyByteArray, Array.emptyByteArray)
        val (verdict, cost, failure) = verification match {
          case Success((valid, cost)) => (if (valid) "Accept" else "RejectProof", Json.fromLong(cost), Json.Null)
          case Failure(error) =>
            val isCost = Iterator.iterate(error)(_.getCause).takeWhile(_ != null)
              .exists(_.isInstanceOf[_root_.sigma.exceptions.CostLimitException])
            (if (isCost) "RejectCost" else "RejectOther", Json.Null, Json.fromString(error.getClass.getName))
        }
        Json.obj("iterations" -> Json.fromInt(n), "source" -> Json.fromString(source),
          "tree_hex" -> Json.fromString(Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(tree))),
          "sigma_sha256" -> Json.fromString(Base16.encode(MessageDigest.getInstance("SHA-256").digest(bytes))),
          "sigma_bytes" -> Json.fromInt(bytes.length), "sigma_size" -> Json.fromInt(sigma.size),
          "eval_jit" -> Json.fromInt(accumulator.totalCost.value),
          "crypto_jit" -> Json.fromInt(Interpreter.estimateCryptoVerifyCost(sigma).value),
          "limit_block" -> Json.fromLong(ctx.costLimit), "verify_verdict" -> Json.fromString(verdict),
          "verify_cost_block" -> cost, "failure_class" -> failure)
      }
    }
    val secretInputs = (1 to 4).map(n => DLogProverInput(BigInteger.valueOf(n)))
    val prover = new ErgoLikeInterpreter with ProverInterpreter {
      override type CTX = ErgoLikeContext
      override def secrets = secretInputs
    }
    val p = secretInputs.map(_.publicImage)
    val proofCases = Seq(
      "and" -> CAND(Seq(p(0), p(1))),
      "or_of_and" -> COR(Seq(CAND(Seq(p(0), p(1))), p(2))),
      "threshold_2_of_3" -> CTHRESHOLD(2, Seq(p(0), p(1), p(2))),
      "threshold_of_or_and" -> CTHRESHOLD(2, Seq(COR(Seq(p(0), p(1))), CAND(Seq(p(1), p(2))), p(3))),
      "or_of_threshold" -> COR(Seq(CTHRESHOLD(2, Seq(p(0), p(1), p(2))), p(3)))
    ).map { case (name, prop) =>
      VersionContext.withVersions(3.toByte, 3.toByte) {
        val tree = ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(3.toByte), prop.toSigmaPropValue)
        val message = "independent Scala proof traversal".getBytes("UTF-8")
        val proof = prover.generateProof(prop, message, HintsBag.empty)
        val self = new ErgoBox(1000000L, tree,
          transactionId = bytesToId(Array.fill(32)(0.toByte)), index = 0.toShort, creationHeight = 0)
        val ctx = new ErgoLikeContext(
          lastBlockUtxoRoot = AvlTreeData.dummy,
          headers = Colls.emptyColl[Header],
          preHeader = CPreHeader(4.toByte, Colls.fromArray(Array.fill(32)(0.toByte)),
            3L, 0L, 0, point, Colls.fromArray(Array.fill(3)(0.toByte))),
          dataBoxes = IndexedSeq.empty,
          boxesToSpend = IndexedSeq(self),
          spendingTransaction = ErgoLikeTransaction(IndexedSeq(), IndexedSeq()),
          selfIndex = 0, extension = ContextExtension.empty,
          validationSettings = ValidationRules.currentSettings,
          costLimit = 100000L, initCost = 0L, activatedScriptVersion = 3.toByte
        ).withErgoTreeVersion(3.toByte)
        def accepted(bytes: Array[Byte], msg: Array[Byte]): Boolean =
          interpreter.verify(Interpreter.emptyEnv, tree, ctx, bytes, msg).map(_._1).getOrElse(false)
        val valid = accepted(proof, message)
        require(valid, s"Scala-generated $name proof must verify in Scala")
        Json.obj("name" -> Json.fromString(name),
          "tree_hex" -> Json.fromString(Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(tree))),
          "proof_hex" -> Json.fromString(Base16.encode(proof)), "message_hex" -> Json.fromString(Base16.encode(message)),
          "valid" -> Json.fromBoolean(valid),
          "wrong_message_valid" -> Json.fromBoolean(accepted(proof, Array(1.toByte))),
          "truncated_valid" -> Json.fromBoolean(accepted(proof.take(23), message)),
          "prefix_valid" -> Json.arr((0 until proof.length).map(n => Json.fromBoolean(accepted(proof.take(n), message))): _*),
          "flipped_byte_valid" -> Json.arr(proof.indices.map { n =>
            val changed = proof.clone(); changed(n) = (changed(n) ^ 1).toByte
            Json.fromBoolean(accepted(changed, message))
          }: _*))
      }
    }
    // Read the reference's cached Int and cost arithmetic only: serializing
    // these expanded graphs would require many GiB and is intentionally omitted.
    val overflowCases = Seq(30, 31, 32, 63, 64).map { n =>
      var prop: SigmaBoolean = p(0)
      (0 until n).foreach(_ => prop = CAND(Seq(prop, prop)))
      val cost = scala.util.Try(SigmaPropBytes.costKind.cost(prop.size).value)
      Json.obj("iterations" -> Json.fromInt(n), "scala_wrapped_size" -> Json.fromInt(prop.size),
        "wrapped_propbytes_jit" -> cost.map(Json.fromInt).getOrElse(Json.Null),
        "cost_failure" -> cost.failed.map(e => Json.fromString(e.getClass.getName)).getOrElse(Json.Null))
    }
    def artifact(cls: Class[_]): Json = {
      val path = Paths.get(cls.getProtectionDomain.getCodeSource.getLocation.toURI)
      Json.obj("file" -> Json.fromString(path.getFileName.toString),
        "sha256" -> Json.fromString(Base16.encode(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)))))
    }
    val fixture = Json.obj("oracle" -> Json.fromString("Scala sigma-state 6.0.6 / ergo-core 6.0.6"),
      "sigma_artifact" -> artifact(classOf[SigmaCompiler]), "node_artifact" -> artifact(classOf[ErgoLikeContext]),
      "cases" -> Json.arr(cases: _*), "proof_cases" -> Json.arr(proofCases: _*), "size_overflow_cases" -> Json.arr(overflowCases: _*))
    Files.write(Paths.get(args(0)), (fixture.spaces2 + "\n").getBytes("UTF-8"))
  }
}

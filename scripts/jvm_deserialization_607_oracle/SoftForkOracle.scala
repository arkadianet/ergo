//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
// Verifies the real Interpreter catch boundaries and block costs.
import io.circe.Json
import io.circe.parser.parse
import scorex.util.{bytesToId}
import scorex.util.encode.Base16
import sigma.{Colls, Header, VersionContext}
import sigma.crypto.CryptoConstants
import sigma.util.Extensions.EcpOps
import sigma.data.AvlTreeData
import sigma.interpreter.ContextExtension
import sigma.ast.{ErgoTree, DeserializationSigmaBuilder}
import sigma.serialization.{ConstantSerializer, ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer}
import sigma.validation.{EnabledRule, DisabledRule, ReplacedRule, ChangedRule}
import org.ergoplatform.{ErgoBox, ErgoLikeContext, ErgoLikeInterpreter, ErgoLikeTransaction}
import org.ergoplatform.validation.ValidationRules
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.Interpreter
object SoftForkOracle {
  def main(args: Array[String]): Unit = args.foreach { path =>
    val input = parse(scala.io.Source.fromFile(path).mkString).fold(throw _, identity)
    input.hcursor.downField("entries").values.get.foreach { e =>
      val c = e.hcursor
      val activation = c.get[Int]("activated").fold(throw _, identity).toByte
      val status = c.get[String]("status").fold(throw _, identity) match {
        case "enabled" => EnabledRule
        case "disabled" => DisabledRule
        case "replaced" => ReplacedRule(1021.toShort)
        case "changed" => ChangedRule(Array(0.toByte))
      }
      val settings = ValidationRules.currentSettings
      val (coreSoftFork, nodeSoftFork) = VersionContext.withVersions(activation, 0.toByte) {
        val core = sigma.validation.ValidationRules.coreSettings.updated(1020.toShort, status)
        try {
          ConstantSerializer(DeserializationSigmaBuilder).deserialize(SigmaSerializer.startReader(Base16.decode("0c6200").get))
          (false, false)
        } catch { case ve: sigma.validation.ValidationException => (core.isSoftFork(ve), settings.isSoftFork(ve)) }
      }
      val t = VersionContext.withVersions(activation, 0.toByte) {
        ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(Base16.decode(c.get[String]("tree_hex").fold(throw _,identity)).get)
      }
      val payload = c.get[String]("payload_hex").fold(throw _,identity)
      val value = if (payload.nonEmpty) Some(ConstantSerializer(DeserializationSigmaBuilder).deserialize(
        SigmaSerializer.startReader(Base16.decode("0e" + f"${payload.length / 2}%02x" + payload).get))) else None
      val carrier = c.get[String]("carrier").fold(throw _,identity)
      val registers: ErgoBox.AdditionalRegisters = if (carrier == "register") Map(ErgoBox.R4 -> value.get) else Map.empty[ErgoBox.NonMandatoryRegisterId,sigma.ast.EvaluatedValue[_ <: sigma.ast.SType]]
      val box = new ErgoBox(value = 1000000L, ergoTree = t, additionalRegisters = registers, transactionId = bytesToId(Array.fill(32)(0.toByte)), index = 0.toShort, creationHeight = 0)
      val extension = if (carrier == "extension") ContextExtension(Map(0.toByte -> value.get)) else ContextExtension.empty
      val pre = CPreHeader((activation+1).toByte, Colls.fromArray(Array.fill(32)(0.toByte)), 3L, 0L, 0,
        CryptoConstants.dlogGroup.generator.toGroupElement, Colls.fromArray(Array.fill(3)(0.toByte)))
      val ctx = new ErgoLikeContext(AvlTreeData.dummy, Colls.emptyColl[Header], pre,
        IndexedSeq.empty, IndexedSeq(box), ErgoLikeTransaction(IndexedSeq(),IndexedSeq()), 0,
        extension, settings, 1000000L, 0L, activation).withErgoTreeVersion(t.version)
      val interpreter = new ErgoLikeInterpreter { override type CTX = ErgoLikeContext }
      val result = interpreter.verify(Interpreter.emptyEnv,t,ctx,Array.emptyByteArray,Array.emptyByteArray)
      val (verdict,cost) = result match {
        case scala.util.Success((ok,n)) => (ok.toString,Some(n))
        case scala.util.Failure(err) => (err.getClass.getSimpleName,None)
      }
      println(e.deepMerge(Json.obj("result" -> Json.fromString(verdict), "cost" -> cost.map(Json.fromLong).getOrElse(Json.Null), "core_soft_fork" -> Json.fromBoolean(coreSoftFork), "node_soft_fork" -> Json.fromBoolean(nodeSoftFork))).noSpaces)
    }
  }
}

//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
// Records evaluator verdict and accumulated JIT cost, including failed evaluation.
import scala.util.{Try, Success, Failure}
import scorex.util.bytesToId
import scorex.util.encode.Base16
import sigma.{Colls, Coll, Header, VersionContext}
import sigma.crypto.CryptoConstants
import sigma.util.Extensions.EcpOps
import sigma.data.{AvlTreeData, SigmaBoolean, CSigmaProp}
import sigma.interpreter.ContextExtension
import sigma.ast._
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer, ValueSerializer}
import org.ergoplatform._
import org.ergoplatform.validation.ValidationRules
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{Interpreter, CErgoTreeEvaluator, CostAccumulator}
import sigmastate.interpreter.CErgoTreeEvaluator.DefaultEvalSettings

object EvaluationOrderOracle {
  val trueTree: ErgoTree = ErgoTree.fromProposition(TrueLeaf.toSigmaProp)

  def mkCtx(tree: ErgoTree, ext: ContextExtension, regs: Map[ErgoBox.NonMandatoryRegisterId, EvaluatedValue[_ <: SType]],
            activated: Byte, height: Int): ErgoLikeContext = {
    val selfBox = new ErgoBox(1000000L, tree, Colls.emptyColl, regs, bytesToId(Array.fill(32)(0: Byte)), 0.toShort, 0)
    val pre = CPreHeader((activated + 1).toByte, Colls.fromArray(Array.fill(32)(0.toByte)), 3L, 0L, height,
      CryptoConstants.dlogGroup.generator.toGroupElement, Colls.fromArray(Array.fill(3)(0.toByte)))
    new ErgoLikeContext(AvlTreeData.dummy, Colls.emptyColl[Header], pre,
      IndexedSeq.empty, IndexedSeq(selfBox), ErgoLikeTransaction(IndexedSeq(), IndexedSeq()), 0,
      ext, ValidationRules.currentSettings, 1000000L, 0L, activated).withErgoTreeVersion(tree.version)
  }


  def main(args: Array[String]): Unit = {
    scala.io.Source.fromFile(args(0)).getLines().filter(l => l.nonEmpty && !l.startsWith("#")).foreach { line =>
      val p = line.split("\\t")
      val tv = p(1).toByte
      val accu = new CostAccumulator(JitCost(0), Some(JitCost(p(3).toInt)))
      val result = try VersionContext.withVersions(3.toByte, tv) {
        val exp = ValueSerializer.deserialize(Base16.decode(p(2)).get)
        val ctx = mkCtx(trueTree, ContextExtension.empty, Map.empty, 3.toByte, 1000000).withErgoTreeVersion(tv)
        val (v, _) = CErgoTreeEvaluator.eval(ctx.toSigmaContext(), accu, Seq.empty, exp, DefaultEvalSettings)
        v match {
          case sp: CSigmaProp => if (sp.wrappedValue == sigma.data.TrivialProp.TrueProp) "true" else "false"
          case b: Boolean => b.toString
          case _ => "value"
        }
      } catch { case e: Throwable => "error" }
      println(p(0) + "\t" + result + "\t" + accu.totalCost.value)
    }
  }
}

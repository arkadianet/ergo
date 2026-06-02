//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import io.circe.parser._
import scorex.util.encode.Base16
import sigma.Colls
import sigma.ast.JitCost
import sigma.data.{AvlTreeData, CGroupElement}
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import org.ergoplatform.validation.ValidationRules
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{CostAccumulator, CErgoTreeEvaluator}
import sigma.VersionContext
import java.io._
import java.net._

object DumpJitCost extends JsonCodecs {
  val NODE_URL: String = sys.env.getOrElse("NODE_URL", "http://localhost:9053")
  def httpGet(path: String): String = {
    val url = new URL(s"$NODE_URL$path")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET"); conn.setConnectTimeout(10000); conn.setReadTimeout(60000)
    val reader = new BufferedReader(new InputStreamReader(conn.getInputStream))
    val sb = new StringBuilder; var line: String = null
    while ({ line = reader.readLine(); line != null }) sb.append(line)
    reader.close(); conn.disconnect(); sb.toString()
  }
  def main(args: Array[String]): Unit = {
    val boxId = args(0)
    val box = decode[ErgoBox](httpGet(s"/blockchain/box/byId/$boxId"))(ergoBoxDecoder).getOrElse(sys.error("fail"))
    val minerPkEcp = GroupElementSerializer.parse(SigmaSerializer.startReader(
      Base16.decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").get))
    val preHeader = CPreHeader(2.toByte, Colls.fromArray(Array.fill(32)(0.toByte)),
      1600000000000L, 0L, 700000, CGroupElement(minerPkEcp), Colls.fromArray(Array.fill(3)(0.toByte)))
    val unsignedInput = new UnsignedInput(box.id, sigma.interpreter.ContextExtension.empty)
    val outCandidate = new ErgoBoxCandidate(box.value, box.ergoTree, 700000)
    val unsignedTx = new UnsignedErgoLikeTransaction(
      IndexedSeq(unsignedInput), IndexedSeq.empty, IndexedSeq(outCandidate))
    val ctx = new ErgoLikeContext(AvlTreeData.dummy, Colls.emptyColl, preHeader,
      IndexedSeq.empty[ErgoBox], IndexedSeq(box), unsignedTx,
      0, sigma.interpreter.ContextExtension.empty,
      ValidationRules.currentSettings, 1000000L, 0L, 2.toByte)
    val ergoTree = box.ergoTree
    val ctxV = ctx.withErgoTreeVersion(ergoTree.version).asInstanceOf[ErgoLikeContext]
    VersionContext.withVersions(ctxV.activatedScriptVersion, ergoTree.version) {
      val costAcc = new CostAccumulator(JitCost.fromBlockCost(0), Some(JitCost.fromBlockCost(1000000)))
      val settings = CErgoTreeEvaluator.DefaultEvalSettings.copy(costTracingEnabled = true)
      val evaluator = new CErgoTreeEvaluator(ctxV.toSigmaContext(),
        ergoTree.constants.asInstanceOf[IndexedSeq[sigma.ast.Constant[sigma.ast.SType]]],
        costAcc, null, settings)
      val prop = ergoTree.toProposition(ergoTree.isConstantSegregation)
      evaluator.eval(CErgoTreeEvaluator.EmptyDataEnv, prop)
      println(s"Total JitCost: ${costAcc.totalCost.value}")
      println(s"Block cost: ${costAcc.totalCost.toBlockCost}")
      // Access costTrace via reflection (it's a debox.Buffer)
      val field = classOf[CErgoTreeEvaluator].getDeclaredField("costTrace")
      field.setAccessible(true)
      val traceObj = field.get(evaluator)
      val toArrayMethod = traceObj.getClass.getMethod("toArray")
      val arr = toArrayMethod.invoke(traceObj).asInstanceOf[Array[AnyRef]]
      println(s"\n=== SCALA COST TRACE (${arr.length} entries) ===")
      var total = 0L
      for (item <- arr) {
        
        val cost = item.getClass.getMethod("cost").invoke(item) match {
          case i: java.lang.Integer => i.toLong
          case other => other.toString.toLong
        }
        val name = item.getClass.getMethod("opName").invoke(item).asInstanceOf[String]
        total += cost
        println(f"  $name%-35s += $cost%5d jit  (total: $total%d)")
      }
    }
  }
}

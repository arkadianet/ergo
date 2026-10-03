// Audit-only ordinary compiler/parser/reducer comparison. No node/services.
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.6
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.serialization.ErgoTreeSerializer
import org.ergoplatform.ErgoAddressEncoder.TestnetNetworkPrefix

object AuditCollectionProbe {
  def main(args: Array[String]): Unit = {
    val compiler = new SigmaCompiler(TestnetNetworkPrefix)
    val cases = Seq(
      "flatmap-byte-bool" -> "sigmaProp(Coll(HEIGHT).flatMap{(x: Int) => Coll((Coll[Byte](x.toByte), true))}.size == 1)",
      "flatmap-short-byte-long" -> "sigmaProp(Coll(HEIGHT).flatMap{(x: Int) => Coll((Coll[Byte](x.toByte), 1L))}.size == 1)",
      "flatmap-byte-int" -> "sigmaProp(Coll(HEIGHT).flatMap{(x: Int) => Coll((Coll[Byte](x.toByte), 1))}.size == 1)",
      "reverse-sigmaprop-threshold" -> "atLeast(1, Coll(sigmaProp(HEIGHT >= 0), sigmaProp(HEIGHT >= 1)).reverse)",
      "reverse-sigmaprop-equality" -> "sigmaProp(Coll(sigmaProp(HEIGHT >= 0)).reverse == Coll(sigmaProp(HEIGHT >= 0)))",
      "reverse-group-equality" -> "sigmaProp(Coll(groupGenerator.exp(HEIGHT.toBigInt)).reverse == Coll(groupGenerator.exp(HEIGHT.toBigInt)))",
      "empty-flatmap-bound-long" -> "{ val ys = Coll[Long](); sigmaProp(Coll[Int]().flatMap{(x: Int) => ys} == ys) }"
    )
    cases.foreach { case (id, source) =>
      try {
        val bytes = VersionContext.withVersions(3.toByte, 3.toByte) {
          val built = compiler.compile(Map.empty[String, Any], source)(new CompiletimeIRContext).buildTree
          val tree = built match {
            case s: Value[SSigmaProp.type @unchecked] if s.tpe == SSigmaProp => ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(3.toByte), s)
            case b: Value[SBoolean.type @unchecked] if b.tpe == SBoolean => ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(3.toByte), b.toSigmaProp)
            case other => throw new IllegalArgumentException("root " + other.tpe)
          }
          ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(tree)
        }
        val hex = Base16.encode(bytes)
        println(id + "|" + Base16.encode(source.getBytes("UTF-8")) + "|" + hex + "|" + ErgoSerdeOracle.handle("reduce@3", hex) + "|" + ErgoSerdeOracle.handle("verify@3", hex))
      } catch { case e: Throwable => println(id + "|COMPILE_ERROR|" + e.getClass.getName + "|" + e.getMessage.replace('\n', ' ')) }
    }
  }
}

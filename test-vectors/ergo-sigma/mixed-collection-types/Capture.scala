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

object AuditMixedCollectionProbe {
  def main(args: Array[String]): Unit = {
    val compiler = new SigmaCompiler(TestnetNetworkPrefix)
    val cases = Seq(
      "flatmap-mixed-width-token-first" -> "{ val ys = Coll(HEIGHT, HEIGHT + 1).flatMap{(x: Int) => Coll((if (x == HEIGHT) Coll[Byte](1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte) else Coll[Byte](x.toByte), x.toLong))}; sigmaProp(ys.size == 2 && ys(0)._1.size == 32 && ys(1)._1.size == 1) }",
      "flatmap-mixed-width-generic-first" -> "{ val ys = Coll(HEIGHT + 1, HEIGHT).flatMap{(x: Int) => Coll((if (x == HEIGHT) Coll[Byte](1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte,1.toByte) else Coll[Byte](x.toByte), x.toLong))}; sigmaProp(ys.size == 2 && ys(0)._1.size == 1 && ys(1)._1.size == 32) }",
      "flatmap-mixed-box-generic-first" -> "sigmaProp(Coll(HEIGHT, HEIGHT + 1).flatMap{(x: Int) => if (x == HEIGHT) Coll(SELF).reverse else Coll(SELF)}.size == 2)",
      "flatmap-mixed-box-specialized-first" -> "sigmaProp(Coll(HEIGHT + 1, HEIGHT).flatMap{(x: Int) => if (x == HEIGHT) Coll(SELF).reverse else Coll(SELF)}.size == 2)",
      "flatmap-box-input-lazy-first" -> "sigmaProp(Coll(HEIGHT, HEIGHT + 1).flatMap{(x: Int) => if (x == HEIGHT) INPUTS else Coll(SELF)}.size == 2)",
      "flatmap-box-input-materialized-first" -> "sigmaProp(Coll(HEIGHT + 1, HEIGHT).flatMap{(x: Int) => if (x == HEIGHT) INPUTS else Coll(SELF)}.size == 2)"
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

//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.6
import sigma.VersionContext
import sigma.serialization.{ErgoTreeSerializer,SigmaSerializer}
import scorex.util.encode.Base16
object AuditTreeProbe {
 def main(args: Array[String]): Unit = {
  Seq(("activation-existing", "1000d1e6c6a70409"), ("normalization-existing-generator-count0", "1000d17f"), ("opaque-existing-unit-fixture", "0b01fd")).foreach { case (label,hex) =>
   Seq(1,2,3).foreach { av =>
    try { VersionContext.withVersions(av.toByte,0.toByte) {
     val r=SigmaSerializer.startReader(Base16.decode(hex).get)
     val t=ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(r,4096)
     val serialized=Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(t))
     val template=Base16.encode(t.template)
     println(s"$label activation=$av ACCEPT consumed=${r.position} cached=${t.bytesHex} serialized=$serialized template=$template root=${t.root.isRight}")
    }} catch {case e: Throwable => println(s"$label activation=$av REJECT ${e.getClass.getName} ${e.getMessage}")}
   }
  }
 }
}

//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.6

import sigma.VersionContext
import sigma.ast.DeserializationSigmaBuilder
import sigma.serialization.{ConstantSerializer, ErgoTreeSerializer, SigmaSerializer}
import scorex.util.encode.Base16

object ReviewOracle {
  def main(args: Array[String]): Unit = {
    scala.io.Source.fromFile(args(0)).getLines().filterNot(_.startsWith("#")).filter(_.nonEmpty).foreach { line =>
      val Array(name, surface, hex) = line.split("\\s+", 3)
      val result = try {
        VersionContext.withVersions(3.toByte, 3.toByte) {
          val r = SigmaSerializer.startReader(Base16.decode(hex).get)
          surface match {
            case "tree" => ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(r, 4096)
            case "constant" => ConstantSerializer(DeserializationSigmaBuilder).deserialize(r)
            case "expr" => r.getValue()
            case "candidate" => org.ergoplatform.ErgoBoxCandidate.serializer.parse(r)
            case "tx" => org.ergoplatform.ErgoLikeTransactionSerializer.parse(r)
          }
          "ACCEPT " + r.position
        }
      } catch { case e: Throwable => "REJECT " + e.getClass.getSimpleName }
      println(name + " " + result)
    }
  }
}

// Restored ordinary folded-output control; real compiler and real parser.
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12.21
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep org.ergoplatform::ergo-core:6.0.6
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.serialization.{ErgoTreeSerializer,SigmaSerializer}
import org.ergoplatform.ErgoAddressEncoder.TestnetNetworkPrefix
import io.circe.Json

object CompilerFoldedControl {
  def main(args: Array[String]): Unit = {
    val source = "{ val u = Coll[UnsignedBigInt](); sigmaProp(u.size.toLong == SELF.value) }"
    val ser = ErgoTreeSerializer.DefaultSerializer
    val bytes = VersionContext.withVersions(3.toByte,3.toByte) {
      val root = new SigmaCompiler(TestnetNetworkPrefix)
        .compile(Map.empty[String,Any],source)(new CompiletimeIRContext).buildTree
        .asInstanceOf[Value[SSigmaProp.type]]
      ser.serializeErgoTree(ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(0.toByte),root))
    }
    val reads = (1 to 3).map { activation =>
      val reader = SigmaSerializer.startReader(bytes)
      val parsed = VersionContext.withVersions(activation.toByte,activation.toByte) {
        ser.deserializeErgoTree(reader,SigmaSerializer.MaxPropositionSize)
      }
      require(parsed.isRightParsed && reader.position == bytes.length)
      Json.obj("activated_version" -> Json.fromInt(activation),
        "outcome" -> Json.fromString("READ_RIGHT"),"consumed" -> Json.fromInt(reader.position))
    }
    println(Json.obj("source" -> Json.fromString(source),"frontend_version" -> Json.fromInt(3),
      "tree_hex" -> Json.fromString(Base16.encode(bytes)),
      "reader_results" -> Json.arr(reads: _*)).spaces2)
  }
}

// Ordinary existing compiler cases: compile output and independent parser scope.
//> using scala 2.12.21
//> using dep org.scorexfoundation::sigma-state:6.0.6
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.serialization.{ErgoTreeSerializer,SigmaSerializer}
import org.ergoplatform.ErgoAddressEncoder.TestnetNetworkPrefix
import io.circe.Json

object CompilerReaderCapture {
  val ser = ErgoTreeSerializer.DefaultSerializer
  def read(bytes: Array[Byte], activation: Byte): Json = {
    val r = SigmaSerializer.startReader(bytes)
    try {
      val t = VersionContext.withVersions(activation, activation) {
        ser.deserializeErgoTree(r, SigmaSerializer.MaxPropositionSize)
      }
      Json.obj("activated_version" -> Json.fromInt(activation),
        "outcome" -> Json.fromString(if (t.isRightParsed) "READ_RIGHT" else "READ_WRAPPED"),
        "consumed" -> Json.fromInt(r.position))
    } catch { case e: Throwable => Json.obj("activated_version" -> Json.fromInt(activation),
        "outcome" -> Json.fromString("READ_ERROR"),
        "exception_class" -> Json.fromString(e.getClass.getName),
        "message" -> Json.fromString(String.valueOf(e.getMessage)),
        "consumed" -> Json.fromInt(r.position)) }
  }
  def main(args: Array[String]): Unit = {
    val compiler = new SigmaCompiler(TestnetNetworkPrefix)
    val cases = Seq(
      ("self-unsigned","sigmaProp(SELF.R4[UnsignedBigInt].isDefined)","1000d1e6c6a70409"),
      ("var-unsigned","sigmaProp(getVar[UnsignedBigInt](1).isDefined)","1000d1e6e30109"),
      ("self-coll-unsigned","sigmaProp(SELF.R4[Coll[UnsignedBigInt]].isDefined)","1000d1e6c6a70415"),
      ("self-tuple-unsigned-int","sigmaProp(SELF.R4[(UnsignedBigInt,Int)].isDefined)","1000d1e6c6a7044504"),
      ("self-option-unsigned","sigmaProp(SELF.R4[Option[UnsignedBigInt]].isDefined)","1000d1e6c6a7042d"),
      ("var-coll-unsigned","sigmaProp(getVar[Coll[UnsignedBigInt]](1).isDefined)","1000d1e6e30115"),
      ("self-tuple-int-unsigned","sigmaProp(SELF.R4[(Int,UnsignedBigInt)].isDefined)","1000d1e6c6a7044009")
    )
    val captured = cases.map { case (id,source,expected) =>
      VersionContext.withVersions(3.toByte,3.toByte) {
        val built = compiler.compile(Map.empty[String,Any],source)(new CompiletimeIRContext).buildTree
        val proposition = built match {
          case s: Value[SSigmaProp.type @unchecked] if s.tpe == SSigmaProp => s
          case b: Value[SBoolean.type @unchecked] if b.tpe == SBoolean => b.toSigmaProp
          case other => throw new IllegalArgumentException("root " + other.tpe)
        }
        val zero = ser.serializeErgoTree(ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(0.toByte),proposition))
        val three = ser.serializeErgoTree(ErgoTree.fromProposition(ErgoTree.defaultHeaderWithVersion(3.toByte),proposition))
        require(Base16.encode(zero) == expected, id + " differs from existing emitted fixture")
        Json.obj("id" -> Json.fromString(id),"source" -> Json.fromString(source),
          "frontend_version" -> Json.fromInt(3), "compile_outcome" -> Json.fromString("COMPILE_ACCEPT"),
          "tree_hex" -> Json.fromString(Base16.encode(zero)),
          "reader_results" -> Json.arr((1 to 3).map(v => read(zero,v.toByte)): _*),
          "header3_control_hex" -> Json.fromString(Base16.encode(three)),
          "header3_control_result" -> read(three,3.toByte))
      }
    }
    println(Json.obj("cases" -> Json.arr(captured: _*)).spaces2)
  }
}

//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.6

// Capture the actual JVM writer at the signed count-byte boundary.
// Run: scala-cli run scripts/jvm_serde_oracle/ContextExtensionBoundaryOracle.scala --server=false --jvm 17
import sigma.ast.{EvaluatedValue, IntConstant, SType}
import sigma.interpreter.ContextExtension
import sigma.serialization.SigmaSerializer
import scorex.util.encode.Base16

object ContextExtensionBoundaryOracle {
  private def quote(s: String): String = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

  def main(args: Array[String]): Unit = {
    val rows = Seq(0, 1, 127, 128, 255, 256).map { count =>
      val values: Map[Byte, EvaluatedValue[_ <: SType]] = (0 until count)
        .map(i => i.toByte -> IntConstant(0)).toMap
      val result = try {
        val writer = SigmaSerializer.startWriter()
        ContextExtension.serializer.serialize(ContextExtension(values), writer)
        "\"verdict\":\"ACCEPT\",\"hex\":" + quote(Base16.encode(writer.toBytes))
      } catch {
        case error: Exception => "\"verdict\":\"REJECT\",\"exception\":" + quote(error.getClass.getName) + ",\"message\":" + quote(error.getMessage)
      }
      "{\"count\":" + count + "," + result + "}"
    }
    println("{\"provenance\":{\"source\":\"scripts/jvm_serde_oracle/ContextExtensionBoundaryOracle.scala\",\"sigma_state\":\"6.0.6\",\"scala\":\"2.12.20\",\"java\":" + quote(System.getProperty("java.version")) + "},\"cases\":[" + rows.mkString(",") + "]}")
  }
}

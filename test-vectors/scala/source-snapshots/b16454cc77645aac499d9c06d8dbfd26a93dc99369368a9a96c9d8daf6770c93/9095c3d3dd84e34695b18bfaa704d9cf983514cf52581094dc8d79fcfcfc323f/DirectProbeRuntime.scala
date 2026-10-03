// Runtime provenance only; delegate to the unchanged pinned reference probe.
import io.circe.Json
object DirectProbeRuntime {
  def main(args: Array[String]): Unit = {
    val properties = Seq("java.class.path", "java.runtime.version", "java.vm.name", "java.vendor", "java.home")
    val metadata = Json.obj(properties.map(key => key -> Json.fromString(System.getProperty(key, ""))): _*)
    System.err.println("DIRECT_PROBE_RUNTIME_JSON=" + metadata.noSpaces)
    EvaluatedValueOracle.main(args)
  }
}

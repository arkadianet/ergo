//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
// Deserialization verdicts for arithmetic operands whose type read fails.
// stdin: name TAB surface TAB version-or-header TAB hex
//   body: ValueSerializer.deserialize at tree version <version>, then .tpe
//         (TYPE / TYPE_FAIL / DECODE_FAIL with the exception class)
//   tree: ErgoTreeSerializer.deserializeErgoTree, activated version 3
//         (ACCEPT parsed / ACCEPT unparsed / REJECT with the exception class)
// stdout: name TAB surface TAB version-or-header TAB hex TAB phase TAB result
import sigma.VersionContext
import sigma.serialization.{ErgoTreeSerializer, SigmaSerializer, ValueSerializer}
import scorex.util.encode.Base16
object ArithUpcastOracle {
  def main(args: Array[String]): Unit = {
    scala.io.Source.stdin.getLines().filter(_.nonEmpty).foreach { line =>
      val Array(name, surface, version, hex) = line.split("\\t")
      val bytes = Base16.decode(hex).get
      val (phase, result) = surface match {
        case "body" =>
          VersionContext.withVersions(3.toByte, version.toByte) {
            try {
              val value = ValueSerializer.deserialize(SigmaSerializer.startReader(bytes))
              try { ("TYPE", value.tpe.toString) }
              catch { case e: Throwable => ("TYPE_FAIL", e.getClass.getSimpleName) }
            } catch { case e: Throwable => ("DECODE_FAIL", e.getClass.getSimpleName) }
          }
        case "tree" =>
          VersionContext.withVersions(3.toByte, 0.toByte) {
            try {
              val tree = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(bytes)
              ("ACCEPT", if (tree.root.isLeft) "unparsed" else "parsed")
            } catch { case e: Throwable => ("REJECT", e.getClass.getSimpleName) }
          }
      }
      println(s"$name\t$surface\t$version\t$hex\t$phase\t$result")
    }
  }
}

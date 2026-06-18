// JVM reference serde oracle for the ergo-difftest differential fuzzer.
//
// Reads `<surface> <hex>` lines on stdin and, for each, runs the REAL Scala
// reference deserializer (the versions the consensus node runs) and prints:
//   ACCEPT <canonical-hex>   parsed; canonical re-serialization is <canonical-hex>
//   ACCEPT                   parsed, but canonical re-serialization unavailable
//   REJECT <ExceptionName>   reference refused these bytes
//   ERR    <message>         oracle could not handle the line
//
// The Rust harness (ergo-difftest) feeds the same bytes to its own decoder and
// diffs the verdicts. An ACCEPT/REJECT mismatch is a consensus divergence — the
// class the UTF-8 STypeVar and off-curve-GroupElement findings belong to.
//
// Dependencies are pinned to the node's versions (see `/info` appVersion = 6.0.2).
// `ergo-core` (transaction/header) is not on Maven Central — publish it locally:
//   cd <ergo reference>; sbt "avldb/publishLocal" "ergoWallet/publishLocal" "ergoCore/publishLocal"
// avldb pulls leveldbjni-all from the GitLab repo declared below.
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2

import scala.io.StdIn
import scorex.util.encode.Base16
import sigma.serialization.{ConstantSerializer, ErgoTreeSerializer, SigmaSerializer, TypeSerializer}
import sigma.ast.DeserializationSigmaBuilder
import org.ergoplatform.ErgoBoxCandidate
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.modifiers.history.header.HeaderSerializer

object ErgoSerdeOracle {
  private val tree = ErgoTreeSerializer.DefaultSerializer
  private val constant = ConstantSerializer(DeserializationSigmaBuilder)

  private def hex(b: Array[Byte]): String = Base16.encode(b)

  // The DESERIALIZE step decides ACCEPT vs REJECT. Canonical re-serialization
  // is separate: if it throws on an otherwise-parsed value we still report
  // ACCEPT (no canonical), matching the Rust side which treats a write refusal
  // as accept-at-parse. Mixing the two would flag a false accept/reject diff.
  private def acc(canon: => String): String =
    try "ACCEPT " + canon
    catch { case _: Throwable => "ACCEPT" }

  def handle(surface: String, hexStr: String): String =
    Base16.decode(hexStr) match {
      case scala.util.Failure(_) => "ERR not-hex"
      case scala.util.Success(bytes) =>
        try
          surface match {
            case "ergo_tree" =>
              val t = tree.deserializeErgoTree(bytes)
              acc(t.bytesHex)
            case "sigma_type" =>
              val tpe = TypeSerializer.deserialize(SigmaSerializer.startReader(bytes))
              acc {
                val w = SigmaSerializer.startWriter()
                TypeSerializer.serialize(tpe, w)
                hex(w.toBytes)
              }
            case "constant" =>
              // type + data — the consensus-meaningful unit (a bare type strips
              // the value/version context the node's type codec defers to)
              val c = constant.deserialize(SigmaSerializer.startReader(bytes))
              acc(hex(constant.toBytes(c)))
            case "ergo_box_candidate" =>
              // standalone box (full token ids) — matches node read_ergo_box_candidate
              val box = ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(bytes))
              acc(hex(ErgoBoxCandidate.serializer.toBytes(box)))
            case "transaction" =>
              val tx = ErgoTransactionSerializer.parseBytes(bytes)
              acc(hex(ErgoTransactionSerializer.toBytes(tx)))
            case "header" =>
              val h = HeaderSerializer.parseBytes(bytes)
              acc(hex(HeaderSerializer.toBytes(h)))
            case other => "ERR unsupported-surface:" + other
          }
        catch {
          case e: Throwable => "REJECT " + e.getClass.getSimpleName
        }
    }

  def main(args: Array[String]): Unit = {
    var line = StdIn.readLine()
    while (line != null) {
      val t = line.trim
      if (t.nonEmpty) {
        val parts = t.split("\\s+", 2)
        println(if (parts.length == 2) handle(parts(0), parts(1)) else "ERR bad-line")
      }
      line = StdIn.readLine()
    }
  }
}

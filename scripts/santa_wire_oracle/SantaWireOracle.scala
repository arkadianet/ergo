// JVM verdicts for vendored SANTA wire vectors (test-vectors/santa/wire/**).
//
// SANTA (https://github.com/mwaddip/santa, MIT) blesses each wire vector with
// the JVM; this script re-derives every verdict independently, so a vendored
// expectation is never trusted on its own. For each entry it parses
// `bytes_hex` as the entry's `kind` inside
// `VersionContext.withVersions(version.activated, version.ergoTree)` and
// prints one TSV line:
//
//   <name> TAB ACCEPT <re-serialized hex>
//   <name> TAB REJECT <exception class>
//
// Each kind goes through the serializer the Scala node itself uses for it:
// transactions through `ErgoTransactionSerializer` (a fresh reader per
// transaction), block sections through `BlockTransactionsSerializer`.
//
// Usage (writes the companion `.jvm.tsv` next to each vector file):
//   for f in test-vectors/santa/wire/v6/authored/*.json; do
//     scala-cli run scripts/santa_wire_oracle/SantaWireOracle.scala -- "$f" > "${f%.json}.jvm.tsv"
//   done
//
// ergo-core is not on Maven Central; publish it locally from the v6.0.7 tag of
// https://github.com/ergoplatform/ergo (see scripts/jvm_serde_oracle/ErgoSerdeOracle.scala).
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7

import io.circe.parser.parse
import org.ergoplatform.ErgoBox
import org.ergoplatform.modifiers.history.BlockTransactionsSerializer
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast.DeserializationSigmaBuilder
import sigma.data.SigmaBoolean
import sigma.serialization.{ConstantSerializer, ErgoTreeSerializer, SigmaSerializer}

object SantaWireOracle {
  private def verdict(f: => Array[Byte]): String =
    try "ACCEPT " + Base16.encode(f)
    catch { case e: Throwable => "REJECT " + e.getClass.getSimpleName }

  private def roundTrip(kind: String, bytes: Array[Byte]): Array[Byte] = kind match {
    case "Transaction" =>
      ErgoTransactionSerializer.toBytes(ErgoTransactionSerializer.parseBytes(bytes))
    case "BlockTransactions" =>
      BlockTransactionsSerializer.toBytes(BlockTransactionsSerializer.parseBytes(bytes))
    case "Box" =>
      ErgoBox.sigmaSerializer.toBytes(ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(bytes)))
    case "Constant" =>
      val cs = ConstantSerializer(DeserializationSigmaBuilder)
      val c = cs.deserialize(SigmaSerializer.startReader(bytes))
      val w = SigmaSerializer.startWriter()
      cs.serialize(c, w)
      w.toBytes
    case "SigmaBoolean" =>
      SigmaBoolean.serializer.toBytes(SigmaBoolean.serializer.parse(SigmaSerializer.startReader(bytes)))
    case "ErgoTree" =>
      val t = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(bytes)
      ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(t)
    case other => throw new IllegalArgumentException("unsupported kind " + other)
  }

  def main(args: Array[String]): Unit = args.foreach { path =>
    val json = parse(scala.io.Source.fromFile(path).mkString).fold(throw _, identity)
    json.hcursor.downField("entries").values.getOrElse(Nil).foreach { e =>
      val c = e.hcursor
      def str(k: String): String = c.downField(k).as[String].fold(throw _, identity)
      def ver(k: String): Byte = c.downField("version").downField(k).as[Int].fold(throw _, identity).toByte
      val bytes = Base16.decode(str("bytes_hex")).get
      val out = VersionContext.withVersions(ver("activated"), ver("ergoTree")) {
        verdict(roundTrip(str("kind"), bytes))
      }
      println(s"${str("name")}\t$out")
    }
  }
}

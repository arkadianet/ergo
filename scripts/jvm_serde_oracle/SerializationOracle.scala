//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
// Reference serialization verdicts and canonical bytes (sigma-state 6.0.7).
// Extra modes: registers, context_extension, box, box-candidate (canonical), transaction.
// Entry fields: name, mode, bytes_hex, version (tree version, default 3), activated (default 3).
import io.circe.Json
import io.circe.parser.parse
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast.{DeserializationSigmaBuilder, EvaluatedValue, SType}
import sigma.serialization.{SigmaSerializer, TypeSerializer, ValueSerializer, ConstantSerializer, ErgoTreeSerializer}
import sigma.validation.ValidationException
import org.ergoplatform.validation.ValidationRules.CheckV6Type
import org.ergoplatform.{ErgoBox, ErgoBoxCandidate, ErgoLikeTransactionSerializer, ErgoLikeTransaction}
import sigma.interpreter.ContextExtension
object SiblingsOracle {
  def main(args: Array[String]): Unit = args.foreach { file =>
    val input = parse(scala.io.Source.fromFile(file).mkString).fold(throw _, identity)
    input.hcursor.downField("entries").values.get.foreach { e =>
      val c = e.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      val mode = c.get[String]("mode").fold(throw _, identity)
      val bytes = Base16.decode(c.get[String]("bytes_hex").fold(throw _, identity)).get
      val version = c.get[Int]("version").getOrElse(3).toByte
      val activated = c.get[Int]("activated").getOrElse(3).toByte
      VersionContext.withVersions(activated, version) {
        val r = SigmaSerializer.startReader(bytes)
        var rule: Option[Int] = None
        var canonical: Option[String] = None
        var extra: Option[String] = None
        val result = try {
          mode match {
            case "box-candidate" =>
              val b = ErgoBoxCandidate.serializer.parse(r)
              canonical = Some(Base16.encode(ErgoBoxCandidate.serializer.toBytes(b)))
            case "box" =>
              val b = ErgoBox.sigmaSerializer.parse(r)
              canonical = Some(Base16.encode(ErgoBox.sigmaSerializer.toBytes(b)))
              extra = Some("box_id=" + Base16.encode(b.id) + " bytes_is_received=" + java.util.Arrays.equals(b.bytes, bytes))
            case "registers" =>
              val n = r.getUByte()
              val w = SigmaSerializer.startWriter(); w.putUByte(n)
              (0 until n).foreach { _ =>
                val v = r.getValue().asInstanceOf[EvaluatedValue[SType]]
                CheckV6Type(v)
                w.putValue(v)
              }
              canonical = Some(Base16.encode(w.toBytes))
            case "context_extension" =>
              val ce = ContextExtension.serializer.parse(r)
              canonical = Some(Base16.encode(ContextExtension.serializer.toBytes(ce)))
            case "transaction" =>
              val tx = ErgoLikeTransactionSerializer.parse(r)
              val bts = ErgoLikeTransaction.bytesToSign(tx)
              canonical = Some(Base16.encode(ErgoLikeTransactionSerializer.toBytes(tx)))
              extra = Some("tx_id=" + tx.id + " bytes_to_sign=" + Base16.encode(bts))
            case "type" =>
              val t = TypeSerializer.deserialize(r)
              val w = SigmaSerializer.startWriter(); TypeSerializer.serialize(t, w)
              canonical = Some(Base16.encode(w.toBytes))
              extra = Some(t.toString)
            case "constant" =>
              val cs = ConstantSerializer(DeserializationSigmaBuilder)
              val v = cs.deserialize(r)
              val w = SigmaSerializer.startWriter(); cs.serialize(v, w)
              canonical = Some(Base16.encode(w.toBytes))
              extra = Some(v.tpe.toString)
            case "expression" => ValueSerializer.deserialize(r)
            case "tree" =>
              val t = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(r, 4096)
              if (!t.isRightParsed) {
                try t.toProposition(false) catch { case ve: ValidationException => rule = Some(ve.rule.id.toInt) }
              } else {
                canonical = Some(Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(t)))
              }
          }
          if (rule.isDefined) "WRAPPED" else "ACCEPT"
        } catch {
          case ve: ValidationException => rule = Some(ve.rule.id.toInt); "ValidationException"
          case err: Throwable => err.getClass.getSimpleName + ":" + Option(err.getMessage).getOrElse("").take(120).replace('\n', ' ')
        }
        println(Json.obj("name" -> Json.fromString(name), "mode" -> Json.fromString(mode),
          "bytes_hex" -> Json.fromString(Base16.encode(bytes)), "version" -> Json.fromInt(version.toInt),
          "activated" -> Json.fromInt(activated.toInt),
          "result" -> Json.fromString(result), "position" -> Json.fromInt(r.position),
          "rule_id" -> rule.map(Json.fromInt).getOrElse(Json.Null),
          "canonical_hex" -> canonical.map(Json.fromString).getOrElse(Json.Null),
          "extra" -> extra.map(Json.fromString).getOrElse(Json.Null)).noSpaces)
      }
    }
  }
}

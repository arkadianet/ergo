//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
// Exact type-call depth, read position, validation-rule identity and tree wraps.
import io.circe.Json
import io.circe.parser.parse
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast.DeserializationSigmaBuilder
import sigma.serialization.{SigmaSerializer, TypeSerializer, ValueSerializer, ConstantSerializer, ErgoTreeSerializer}
import sigma.validation.ValidationException
object DeserializationOracle {
  def main(args: Array[String]): Unit = args.foreach { file =>
    val input = parse(scala.io.Source.fromFile(file).mkString).fold(throw _, identity)
    input.hcursor.downField("entries").values.get.foreach { e =>
      val c = e.hcursor
      val name = c.get[String]("name").fold(throw _, identity)
      val mode = c.get[String]("mode").fold(throw _, identity)
      val bytes = Base16.decode(c.get[String]("bytes_hex").fold(throw _, identity)).get
      val version = c.get[Int]("version").fold(throw _, identity).toByte
      VersionContext.withVersions(3.toByte, version) {
        val r = SigmaSerializer.startReader(bytes)
        var rule: Option[Int] = None
        var canonical: Option[String] = None
        val result = try {
          mode match {
            case "box-candidate" => org.ergoplatform.ErgoBoxCandidate.serializer.parse(r)
            case "type" =>
              val t = TypeSerializer.deserialize(r)
              val w = SigmaSerializer.startWriter(); TypeSerializer.serialize(t, w)
              canonical = Some(Base16.encode(w.toBytes))
            case "write-zero-coll" =>
              val t = TypeSerializer.deserialize(r)
              sigma.serialization.CoreDataSerializer.serialize[sigma.ast.SType](null.asInstanceOf[sigma.ast.SType#WrappedType], t, SigmaSerializer.startWriter())
            case "constant" =>
              val cs = ConstantSerializer(DeserializationSigmaBuilder)
              val v = cs.deserialize(r)
              val w = SigmaSerializer.startWriter(); cs.serialize(v, w)
              canonical = Some(Base16.encode(w.toBytes))
            case "expression" => ValueSerializer.deserialize(r)
            case "tree" =>
              val t = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(r, 4096)
              if (!t.isRightParsed) {
                try t.toProposition(false) catch { case ve: ValidationException => rule = Some(ve.rule.id.toInt) }
              }
          }
          if (rule.isDefined) "WRAPPED" else "ACCEPT"
        } catch {
          case ve: ValidationException => rule = Some(ve.rule.id.toInt); "ValidationException"
          case err: Throwable => err.getClass.getSimpleName
        }
        println(Json.obj("name" -> Json.fromString(name), "mode" -> Json.fromString(mode),
          "bytes_hex" -> Json.fromString(Base16.encode(bytes)), "version" -> Json.fromInt(version.toInt),
          "result" -> Json.fromString(result), "position" -> Json.fromInt(r.position),
          "rule_id" -> rule.map(Json.fromInt).getOrElse(Json.Null),
          "canonical_hex" -> canonical.map(Json.fromString).getOrElse(Json.Null)).noSpaces)
      }
    }
  }
}

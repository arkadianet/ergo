//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
import io.circe.parser.parse
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import org.ergoplatform.mining.AutolykosPowScheme
import sigma.serialization.SigmaSerializer
import scorex.util.encode.Base16
import scala.util.{Try, Success, Failure}

object NodeHeaderOracle {
  def main(args: Array[String]): Unit = args.foreach { file =>
    val input = parse(scala.io.Source.fromFile(file).mkString).fold(throw _, identity)
    input.hcursor.downField("entries").values.get.foreach { e =>
      val name = e.hcursor.get[String]("name").fold(throw _, identity)
      val bytes = Base16.decode(e.hcursor.get[String]("bytes_hex").fold(throw _, identity)).get
      val r = SigmaSerializer.startReader(bytes)
      Try {
        val h = HeaderSerializer.parse(r)
        val pow = new AutolykosPowScheme(32, 26).validate(h).isSuccess
        s"$name\ttrue\t${r.position}\t${h.id}\t${Base16.encode(h.bytes)}\t$pow"
      } match {
        case Success(row) => println(row)
        case Failure(error) =>
          println(s"$name\tfalse\t${r.position}\t-\t-\tfalse")
          System.err.println(s"$name: ${error.getClass.getName}: ${error.getMessage}")
      }
    }
  }
}

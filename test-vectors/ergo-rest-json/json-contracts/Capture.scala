//> using scala "2.12.20"
//> using dep "org.scorexfoundation::sigma-state:6.0.6"
//> using dep "io.circe::circe-parser:0.14.5"
import io.circe.{Json, Decoder}
import io.circe.parser.decode
import org.ergoplatform.sdk.JsonCodecs
import sigma.ast.{EvaluatedValue, SType}
import sigma.serialization.ValueSerializer

object Capture extends App with JsonCodecs {
  System.err.println("ORACLE_CLASSPATH=" + System.getProperty("java.class.path"))
  System.err.println("ORACLE_JAVA=" + System.getProperty("java.version"))
  val numeric = Seq("100", "1e2", "100.0", "1.000000", "100e-2", "1000e-2", "1e-2", "1.5",
    "9007199254740993", "9007199254740993.0", "9223372036854775806", "9223372036854775807",
    "9223372036854775808", "18446744073709551615", "1e80", "0", "-0", "-0.0", "0e100",
    "0e-100", "-1", "\"100\"", "\"+100\"", "\"100.0\"", "\"1e2\"", "\"-0\"", "\"00100\"", "\" 100\"", "\"100 \"", "\"1E+2\"", "\"1.\"", "\"01.0\"", "\"1e+002\"")
  def observation[A](input: String)(implicit decoder: Decoder[A]): Json =
    decode[A](input).fold(_ => Json.Null, value => Json.fromString(value.toString))
  for (input <- numeric) println(Json.obj("kind" -> Json.fromString("number"), "input" -> Json.fromString(input),
    "bigint" -> observation[BigInt](input), "long" -> observation[Long](input)).noSpaces)
  for (input <- Seq("1e262143", "1e262144", "0e999999999999999999999", "1e999999999999999999999", "1e-999999999999999999999")) {
    val result = decode[BigInt](input)
    println(Json.obj("kind" -> Json.fromString("boundary"), "input" -> Json.fromString(input),
      "digits" -> result.fold(_ => Json.Null, n => Json.fromInt(n.toString.length))).noSpaces)
  }
  val values = Seq("0101", "0100", "0105", "010101", "01", "0402", "040201",
    "860201010402", "86020101040201", "86020101", "9800")
  for (hex <- values) {
    val decoded = decode[EvaluatedValue[_ <: SType]]("\"" + hex + "\"")
    val canonical = decoded.fold(_ => Json.Null, value => Json.fromString(
      ValueSerializer.serialize(value).map(b => f"${b & 255}%02x").mkString))
    println(Json.obj("kind" -> Json.fromString("value"), "input" -> Json.fromString(hex),
      "canonical" -> canonical).noSpaces)
  }
}

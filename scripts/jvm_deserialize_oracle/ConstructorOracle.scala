//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
import sigma.VersionContext
import sigma.serialization.{SigmaSerializer, ValueSerializer}
import scorex.util.encode.Base16
object ConstructorOracle {
  def main(args: Array[String]): Unit = {
    scala.io.Source.stdin.getLines().foreach { line =>
      val Array(name, version, hex) = line.split("\\t")
      VersionContext.withVersions(3.toByte, version.toByte) {
        try {
          val value = ValueSerializer.deserialize(SigmaSerializer.startReader(Base16.decode(hex).get))
          try { println(s"$name\tTYPE\t${value.tpe}") }
          catch { case e: Throwable => println(s"$name\tTYPE_FAIL\t${e.getClass.getSimpleName}") }
        } catch { case e: Throwable => println(s"$name\tDECODE_FAIL\t${e.getClass.getSimpleName}") }
      }
    }
  }
}

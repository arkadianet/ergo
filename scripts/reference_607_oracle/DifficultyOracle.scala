// Independent ergo-core 6.0.7 decoded difficulty comparisons.
//> using scala 2.12
//> using dep org.ergoplatform::ergo-core:6.0.7
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using repository ivy2Local
import org.ergoplatform.mining.difficulty.DifficultySerializer
import sigma.util.NBitsUtils
object DifficultyOracle {
  def main(args: Array[String]): Unit = {
    val source = scala.io.Source.fromFile(args(0))
    try source.getLines().foreach { line =>
      val fields = line.split("\t")
      val expected = java.lang.Long.parseLong(fields(1), 16)
      val actual = java.lang.Long.parseLong(fields(2), 16)
      val decoded = DifficultySerializer.decodeCompactBits(actual)
      require(decoded == NBitsUtils.decodeCompactBits(actual))
      println(s"${fields(0)}\t$decoded\t${decoded == DifficultySerializer.decodeCompactBits(expected)}")
    } finally source.close()
  }
}

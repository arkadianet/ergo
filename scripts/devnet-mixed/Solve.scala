//> using scala 2.12
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.15
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
package org.ergoplatform.mining

import io.circe.parser.parse
import scorex.util.encode.Base16

/** External CPU worker; candidate construction and validation stay in each node. */
object Solve {
  def main(args: Array[String]): Unit = {
    val pow = new AutolykosPowScheme(32, 26)
    scala.io.Source.stdin.getLines().foreach { line =>
      val c = parse(line).right.get.hcursor
      val height = c.get[Int]("h").getOrElse(1)
      val version: Byte = if (c.downField("h").succeeded) 4 else 1
      val msg = Base16.decode(c.get[String]("msg").right.get).get
      val b = BigInt(c.downField("b").focus.get.noSpaces.replace("\"", ""))
      val solution = pow.checkNonces(version, java.nio.ByteBuffer.allocate(4).putInt(height).array(),
        msg, BigInt(1), BigInt(2), b, pow.calcN(version, height), 0L, 10000L).get
      println("SOLUTION " + io.circe.Json.obj(
        "pk" -> io.circe.Json.fromString(Base16.encode(groupElemToBytes(solution.pk))),
        "w" -> io.circe.Json.fromString(Base16.encode(groupElemToBytes(solution.w))),
        "n" -> io.circe.Json.fromString(Base16.encode(solution.n)),
        "d" -> io.circe.Json.fromBigInt(solution.d)).noSpaces)
    }
  }
}

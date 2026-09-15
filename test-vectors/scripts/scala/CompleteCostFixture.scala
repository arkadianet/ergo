//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.ergoplatform::ergo-wallet:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import scorex.util.encode.Base16

/** Supplement a completed cost capture with the JVM's signing bytes. */
object CompleteCostFixture {
  def main(args: Array[String]): Unit = {
    require(args.length == 2, "Usage: CompleteCostFixture input.hex output.hex")
    val source = scala.io.Source.fromFile(args(0), "UTF-8")
    val writer = new java.io.PrintWriter(args(1), "UTF-8")
    try source.getLines().foreach { line =>
      val pair = line.split(" ")
      require(pair.length == 2)
      val tx = ErgoTransactionSerializer.parseBytes(Base16.decode(pair(1)).get)
      require(tx.id == pair(0), s"Transaction identity changed for ${pair(0)}")
      writer.println(s"${tx.id} ${Base16.encode(tx.messageToSign)}")
    } finally {
      source.close()
      writer.close()
    }
  }
}

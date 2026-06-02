//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

// Batch version: reads one transaction JSON per line from stdin.
// Prints one output line per tx: <tx_bytes_hex> <bytes_to_sign_hex>
// Lines that fail to parse print: ERROR <message>

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import io.circe.parser.decode
import scorex.util.encode.Base16

object BatchPrintTransactionBytes extends JsonCodecs {
  private def processTx(line: String): String = {
    try {
      val tx = decode[ErgoLikeTransaction](line)(ergoLikeTransactionDecoder)
        .fold(e => sys.error(s"TX decode: $e"), identity)

      val txBytes = ErgoLikeTransactionSerializer.toBytes(tx)
      val txHex = Base16.encode(txBytes)

      val unsignedInputs = tx.inputs.map(i =>
        new UnsignedInput(i.boxId, i.spendingProof.extension)
      )
      val unsignedTx = new UnsignedErgoLikeTransaction(
        unsignedInputs, tx.dataInputs, tx.outputCandidates
      )
      val btsHex = Base16.encode(unsignedTx.messageToSign)

      s"$txHex $btsHex"
    } catch {
      case e: Exception => s"ERROR ${e.getMessage.take(200)}"
    }
  }

  def main(args: Array[String]): Unit = {
    val lines = scala.io.Source.stdin.getLines()
    for (line <- lines if line.trim.nonEmpty) {
      println(processTx(line))
      System.out.flush()
    }
  }
}

//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0

// Reads canonical signed transaction hex from stdin.
// Deserializes it and prints the bytes_to_sign (unsigned message) as hex.
//
// Usage: echo '<tx_hex>' | scala-cli run PrintBytesToSign.scala

import org.ergoplatform._
import sigma.serialization.SigmaSerializer
import scorex.util.encode.Base16
import scala.io.StdIn

object PrintBytesToSign {
  def main(args: Array[String]): Unit = {
    val hexInput = StdIn.readLine().trim
    val txBytes = Base16.decode(hexInput).get

    val tx = ErgoLikeTransactionSerializer.parse(
      SigmaSerializer.startReader(txBytes)
    )

    val unsignedTx = new UnsignedErgoLikeTransaction(
      tx.inputs.map(i => new UnsignedInput(i.boxId, i.spendingProof.extension)),
      tx.dataInputs,
      tx.outputCandidates
    )

    println(Base16.encode(unsignedTx.messageToSign))
  }
}

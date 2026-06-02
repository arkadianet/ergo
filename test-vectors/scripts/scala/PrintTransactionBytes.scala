//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

// Reads transaction JSON (from Ergo node API) on stdin.
// Prints one line: <tx_bytes_hex> <bytes_to_sign_hex>
//
// tx_bytes_hex     = ErgoLikeTransactionSerializer.toBytes (signed tx, includes proofs)
// bytes_to_sign_hex = UnsignedErgoLikeTransaction.messageToSign (what was signed)
//
// Usage:
//   curl -s http://localhost:9053/blocks/{id}/transactions | jq '.transactions[0]' \
//     | scala-cli run PrintTransactionBytes.scala

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import io.circe.parser.decode
import scorex.util.encode.Base16

object PrintTransactionBytes extends JsonCodecs {
  def main(args: Array[String]): Unit = {
    val input = scala.io.Source.stdin.mkString

    val tx = decode[ErgoLikeTransaction](input)(ergoLikeTransactionDecoder)
      .fold(e => sys.error(s"TX decode failed: $e"), identity)

    val txBytes = ErgoLikeTransactionSerializer.toBytes(tx)
    val txHex = Base16.encode(txBytes)

    val unsignedInputs = tx.inputs.map(i =>
      new UnsignedInput(i.boxId, i.spendingProof.extension)
    )
    val unsignedTx = new UnsignedErgoLikeTransaction(
      unsignedInputs, tx.dataInputs, tx.outputCandidates
    )
    val btsHex = Base16.encode(unsignedTx.messageToSign)

    println(s"$txHex $btsHex")
  }
}

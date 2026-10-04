// Reproduce: scala-cli run scripts/jvm_wallet_builder_oracle/NativeMintBurnOracle.scala --server=false
// Scala reference TransactionBuilder computes issuance and authorized burning,
// then prints the input and final candidates consumed by native wallet tests.
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep org.ergoplatform::ergo-core:6.0.6
//> using dep org.ergoplatform::ergo-wallet:6.0.6

import org.ergoplatform._
import org.ergoplatform.wallet.transactions.TransactionBuilder
import scorex.util.{bytesToId, ModifierId}
import scorex.util.encode.Base16
import sigma.Colls
import sigma.Extensions.{ArrayOps, CollBytesOps}
import sigmastate.eval.Extensions._
import sigma.ast.ByteArrayConstant
import sigma.crypto.CryptoConstants
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer}
import sigmastate.utils.Extensions._

object NativeMintBurnOracle extends App {
  def hex(bytes: Array[Byte]): String = Base16.encode(bytes)
  val pk = GroupElementSerializer.toBytes(CryptoConstants.dlogGroup.generator)
  val tree = ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(
    Base16.decode("0008cd" + hex(pk)).get)
  val address = ErgoAddressEncoder(ErgoAddressEncoder.MainnetNetworkPrefix).fromProposition(tree).get
  val token = sigma.data.Digest32Coll @@ Colls.fromArray(Array.fill(32)(0x11.toByte))
  val input = new ErgoBox(10000000L, tree, Colls.fromArray(Array(token -> 10L)), Map.empty,
    bytesToId(Array.fill(32)(0xcd.toByte)), 0.toShort, 100)
  val payment = new ErgoBoxCandidate(2000000L, tree, 200, Colls.fromArray(Array(token -> 2L)))
  val metadata = Map(
    ErgoBox.R4 -> ByteArrayConstant("Native Token".getBytes("UTF-8")),
    ErgoBox.R5 -> ByteArrayConstant("Scala oracle".getBytes("UTF-8")),
    ErgoBox.R6 -> ByteArrayConstant("2".getBytes("UTF-8")))
  val mint = new ErgoBoxCandidate(1000000L, tree, 200,
    Colls.fromArray(Array(sigma.data.Digest32Coll @@ Colls.fromArray(input.id) -> 1000L)), metadata)
  val tx = TransactionBuilder.buildUnsignedTx(IndexedSeq(input), IndexedSeq.empty,
    Seq(payment, mint), 200, Some(1000000L), address, 1000000L, 720,
    Map(bytesToId(token.toArray) -> 5L)).get
  println("{\"provenance\":\"Scala sigma-state/ergo-wallet 6.0.6 TransactionBuilder.buildUnsignedTx; scripts/jvm_wallet_builder_oracle/NativeMintBurnOracle.scala\",")
  println("\"input_hex\":\"" + hex(ErgoBox.sigmaSerializer.toBytes(input)) + "\",")
  println("\"input_id\":\"" + hex(input.id) + "\",")
  println("\"output_candidates_hex\":[" + tx.outputCandidates.map(c => "\"" + hex(ErgoBoxCandidate.serializer.toBytes(c)) + "\"").mkString(",") + "]}")
}

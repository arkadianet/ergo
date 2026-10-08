//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
//> using dep org.ergoplatform::ergo-wallet:6.0.7

// Reference block-cost boundary vectors.
// Mirrors ErgoState.execTransactions (ergo 6.0.7 src/main/scala/org/ergoplatform/nodeView/state/ErgoState.scala:140-157):
// validateStateless, then validateStateful(toSpend, dataBoxes, ctx, accumulatedCost) with the running Long payload.
// Boxes and outputs use creation height 1000, matching the synthetic test header.
import java.io.File
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import io.circe.Json
import org.ergoplatform._
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.bytesToId
import scorex.util.encode.Base16
import sigma.Colls
import sigma.data.CGroupElement
import sigma.serialization.SigmaSerializer
import sigma.interpreter.{ContextExtension, ProverResult}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.eval.CPreHeader
import scala.util.{Failure, Success, Try}

object BlockRecoveryBudgetOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  // Remainder-bearing Boolean identity applied to true.
  val TX0 = "045ef75f5250bf84c11e2d97d8ac4523e26393884c7e23dd7c320735462c1d34280000b989fc0a2c5723a30bbf7773d782a426a601c3dbcb5e83e51b824875820be10c000089c66916d0603b2398951b164d6fcba5275d3ad68a2559454ef1022c7dcccf730000f4dc20b0384b68635596b8367f51b525d78631516b09c52897d7b353b75b1fd2000000000180d0acf30e0008cd023d0faf2ff3580ce38cf6f5a003416f0e9039e388dc2ea8300395603757e6a846c0843d0000"
  val BOXES0 = IndexedSeq(
    "8094ebdc0300d1dad90101017201010101c0843d0000010101010101010101010101010101010101010101010101010101010101010100",
    "8094ebdc0300d1dad90101017201010101c0843d0000020202020202020202020202020202020202020202020202020202020202020201",
    "8094ebdc0300d1dad90101017201010101c0843d0000030303030303030303030303030303030303030303030303030303030303030302",
    "8094ebdc0300d1dad90101017201010101c0843d0000040404040404040404040404040404040404040404040404040404040404040403")

  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val pk = DLogProverInput.random().publicImage
    def params(limit: Int) = Parameters(1000000, Map[Byte, Int](
      1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288,
      4.toByte -> limit, 5.toByte -> 100, 6.toByte -> 2000,
      7.toByte -> 100, 8.toByte -> 100, 123.toByte -> 4), ErgoValidationSettingsUpdate.empty)
    def context(limit: Int) = new ErgoStateContext(Seq.empty, None, chain.genesisStateDigest,
      params(limit), ErgoValidationSettings.initial.updated(ErgoValidationSettingsUpdate(Seq.empty,
        Seq(1000.toShort -> sigma.validation.ReplacedRule(1001.toShort)))), VotingData.empty) {
      override def sigmaPreHeader: sigma.PreHeader = CPreHeader(4.toByte,
        Colls.fromArray(Array.fill(32)(0.toByte)), 0L, 0L, 1051200,
        CGroupElement(pk.value), Colls.fromArray(Array.fill(3)(0.toByte)))
    }
    val tx0 = ErgoTransactionSerializer.parseBytes(Base16.decode(TX0).get)
    val boxes0: IndexedSeq[ErgoBox] = BOXES0.map(h => ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(Base16.decode(h).get)))
    require(boxes0.map(b => Base16.encode(b.id)) == tx0.inputs.map(i => Base16.encode(i.boxId)))
    def mk(fill: Int): IndexedSeq[ErgoBox] = boxes0.zipWithIndex.map { case (b, i) =>
      new ErgoBox(b.value, b.ergoTree, b.additionalTokens, b.additionalRegisters,
        bytesToId(Array.fill(32)((i + fill).toByte)), i.toShort, 1000) }
    val boxes1 = mk(11)
    // A type mismatch recovers under an activated replacement, discarding
    // measured embedded-script charges after they have passed the budget check.
    val paddedTree = sigma.ast.ErgoTree.fromBytes(Base16.decode("00d40801").get)
    val boxes2 = IndexedSeq(new ErgoBox(1000000000L, paddedTree, sigma.Colls.emptyColl[(sigma.data.Digest32Coll, Long)],
      Map.empty, bytesToId(Array.fill(32)(21.toByte)), 0.toShort, 1000))
    val outCand = new ErgoBoxCandidate(tx0.outputCandidates.head.value, tx0.outputCandidates.head.ergoTree, 1000)
    def mkTx(boxes: IndexedSeq[ErgoBox]) = ErgoTransaction(
      boxes.map(b => Input(b.id, ProverResult(Array.emptyByteArray,
        if (boxes.size == 1) ContextExtension(Map(1.toByte -> sigma.ast.ByteArrayConstant(Base16.decode("0ee807" + "00" * 1000).get))) else ContextExtension.empty))),
      IndexedSeq.empty, IndexedSeq(new ErgoBoxCandidate(boxes.map(_.value).sum, outCand.ergoTree, 1000)))
    val tx1 = mkTx(boxes1)
    val tx2 = mkTx(boxes2)

    def validate(tx: ErgoTransaction, boxes: IndexedSeq[ErgoBox], limit: Int, acc: Long): Try[Long] = {
      implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params(limit))
      tx.validateStateful(boxes, IndexedSeq.empty, context(limit), acc).result.toTry
    }
    // ErgoState.execTransactions loop (read from 6.0.7 source), without the UTXO lookups.
    def block(txs: Seq[(String, ErgoTransaction, IndexedSeq[ErgoBox])], limit: Int): Json = {
      var acc = 0L
      var err: Option[(String, String)] = None
      val perTx = txs.flatMap { case (name, tx, boxes) =>
        if (err.isDefined) None else {
          tx.validateStateless().result.toTry match {
            case Failure(e) => err = Some((name, "stateless: " + e.toString)); None
            case Success(_) =>
              validate(tx, boxes, limit, acc) match {
                case Success(c) => val tc = c - acc; acc = c; Some(Json.obj("tx" -> Json.fromString(name), "tx_cost" -> Json.fromLong(tc), "accumulated_after" -> Json.fromLong(c)))
                case Failure(e) => err = Some((name, e.toString)); None
              }
          }
        }
      }
      Json.obj("transactions" -> Json.arr(txs.map(t => Json.fromString(t._1)): _*), "limit" -> Json.fromInt(limit),
        "verdict" -> Json.fromString(if (err.isEmpty) "Accept" else "Reject"),
        "failed_tx" -> err.map(e => Json.fromString(e._1)).getOrElse(Json.Null),
        "error" -> err.map(e => Json.fromString(e._2)).getOrElse(Json.Null),
        "accumulated" -> Json.fromLong(acc), "per_tx" -> Json.arr(perTx: _*))
    }
    val c0 = validate(tx0, boxes0, 1000000, 0L).get
    val c1 = validate(tx1, boxes1, 1000000, 0L).get
    val c2 = validate(tx2, boxes2, 1000000, 0L).get
    val sum = (c1 + c2).toInt
    val ordered = Seq(("tx1", tx1, boxes1), ("tx2", tx2, boxes2))
    val firstAccepted = (sum to (sum + 4096)).find(limit => block(ordered, limit).hcursor.get[String]("verdict").right.get == "Accept").get
    val runs = Seq(block(ordered, sum), block(ordered, sum + 1), block(ordered, firstAccepted - 1), block(ordered, firstAccepted),
      block(Seq(("tx2", tx2, boxes2), ("tx1", tx1, boxes1)), sum + 1), block(Seq(("tx2", tx2, boxes2)), c2.toInt + 1))
    val out = Json.obj(
      "block_version" -> Json.fromInt(4),
      "replaced_rules" -> Json.arr(Json.arr(Json.fromInt(1000), Json.fromInt(1001))),
      "sigma_state_jar" -> Json.fromString(java.nio.file.Paths.get(classOf[sigma.ast.ErgoTree].getProtectionDomain.getCodeSource.getLocation.toURI).getFileName.toString),
      "ergo_core_jar" -> Json.fromString(java.nio.file.Paths.get(classOf[ErgoTransaction].getProtectionDomain.getCodeSource.getLocation.toURI).getFileName.toString),
      "tx0_original_cost" -> Json.fromLong(c0),
      "tx1_cost_alone" -> Json.fromLong(c1), "tx2_cost_alone" -> Json.fromLong(c2), "sum" -> Json.fromInt(sum),
      "tx1_bytes" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx1))),
      "tx2_bytes" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx2))),
      "boxes1" -> Json.arr(boxes1.map(b => Json.fromString(Base16.encode(b.bytes))): _*),
      "boxes2" -> Json.arr(boxes2.map(b => Json.fromString(Base16.encode(b.bytes))): _*),
      "runs" -> Json.arr(runs: _*))
    java.nio.file.Files.write(java.nio.file.Paths.get(args(1)), out.spaces2.getBytes("UTF-8"))
    println(out.spaces2)
  }
}

//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
//> using dep org.ergoplatform::ergo-wallet:6.0.7

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


object ReemissionRulesOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    val baseChain = config.as[ChainSettings]("ergo.chain")
    val r = baseChain.reemission
    val nft = r.emissionNftIdBytes
    val token = r.reemissionTokenIdBytes
    val unit = 1000000000L
    val tree = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(Base16.decode("8094ebdc0300d1dad90101017201010101c0843d0000010101010101010101010101010101010101010101010101010101010101010100").get)).ergoTree
    def tokens(ts: Seq[(sigma.Coll[Byte], Long)]) = Colls.fromArray(ts.map { case (id, amount) => (sigma.data.Digest32Coll @@ id, amount) }.toArray)
    def cand(value: Long, ts: Seq[(sigma.Coll[Byte], Long)], h: Int = 1000, t: sigma.ast.ErgoTree = tree) = new ErgoBoxCandidate(value, t, h, tokens(ts))
    def box(value: Long, ts: Seq[(sigma.Coll[Byte], Long)], index: Int, t: sigma.ast.ErgoTree = tree) = new ErgoBox(value, t, tokens(ts), Map.empty, bytesToId(Array.fill(32)((index + 1).toByte)), index.toShort, 1000)
    val large = 100001L * unit
    val stash = 36L * unit
    val share = 12L * unit
    val emission = box(large, Seq(nft -> 1L, token -> stash), 0)
    val injection = box(unit, Seq(nft -> 1L, token -> stash), 1)
    val bareEmission = box(large, Seq.empty, 2)
    val reward = box(20L * unit, Seq(token -> share), 3)
    val noNft = box(large, Seq(token -> stash), 4)
    val params = Parameters(1000000, Map[Byte, Int](1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288,
      4.toByte -> 1000000, 5.toByte -> 100, 6.toByte -> 2000, 7.toByte -> 100, 8.toByte -> 100, 123.toByte -> 4), ErgoValidationSettingsUpdate.empty)
    val pk = DLogProverInput.random().publicImage
    val activation = r.activationHeight
    val baseOut = Seq(cand(large-unit, Seq(nft -> 1L, token -> (stash-share))), cand(unit, Seq(token -> share)))
    val cases = Seq(
      ("emission-correct", activation+1, Seq(emission), baseOut),
      ("emission-reward-amount", activation+1, Seq(emission), Seq(cand(large-unit, Seq(nft -> 1L, token -> (stash-1))), cand(unit, Seq(token -> 1L)))),
      ("emission-token-order", activation+1, Seq(emission), Seq(cand(large-unit, Seq(token -> (stash-share), nft -> 1L)), baseOut(1))),
      ("emission-token-burn", activation+1, Seq(emission), Seq(cand(large-unit, Seq(nft -> 1L, token -> (stash-share))), cand(unit, Seq.empty))),
      ("emission-one-output", activation+1, Seq(emission), Seq(cand(large, Seq(nft -> 1L, token -> stash)))),
      ("before-activation", activation-1, Seq(emission), Seq(cand(large, Seq(nft -> 1L, token -> stash)))),
      ("activation-correct", activation, Seq(bareEmission, injection), Seq(cand(large, Seq(nft -> 1L, token -> (stash-share))), cand(unit, Seq(token -> share)))),
      ("activation-reward-amount", activation, Seq(bareEmission, injection), Seq(cand(large, Seq(nft -> 1L, token -> (stash-1))), cand(unit, Seq(token -> 1L)))),
      ("large-without-nft", activation+1, Seq(noNft), Seq(cand(large, Seq(token -> stash)))),
      ("reward-unpaid", activation+1, Seq(reward), Seq(cand(20L*unit, Seq.empty))),
      ("reward-paid", activation+1, Seq(reward), Seq(cand(share, Seq.empty, t=r.reemissionRules.payToReemission), cand(8L*unit, Seq.empty)))
    )
    val entries = cases.flatMap { case (name, height, boxes, outputs) => Seq(false, true).map { check =>
      implicit val chain: ChainSettings = baseChain.copy(reemission=r.copy(checkReemissionRules=check))
      val ctx = new ErgoStateContext(Seq.empty, None, chain.genesisStateDigest, params, ErgoValidationSettings.initial, VotingData.empty) {
        override def sigmaPreHeader: sigma.PreHeader = CPreHeader(4.toByte, Colls.fromArray(Array.fill(32)(0.toByte)), 0L, 0L, height, CGroupElement(pk.value), Colls.fromArray(Array.fill(3)(0.toByte)))
      }
      val tx = ErgoTransaction(boxes.map(b => Input(b.id, ProverResult(Array.emptyByteArray, ContextExtension.empty))).toIndexedSeq, IndexedSeq.empty, outputs.toIndexedSeq)
      implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params)
      val result = Try(tx.validateStateful(boxes.toIndexedSeq, IndexedSeq.empty, ctx, 0L).result.toTry).flatten
      Json.obj("name" -> Json.fromString(name + (if(check) "-on" else "-off")), "height" -> Json.fromInt(height), "check" -> Json.fromBoolean(check),
        "tx" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx))), "boxes" -> Json.arr(boxes.map(b => Json.fromString(Base16.encode(b.bytes))): _*),
        "accept" -> Json.fromBoolean(result.isSuccess), "cost" -> result.toOption.map(Json.fromLong).getOrElse(Json.Null), "error" -> result.failed.toOption.map(e => Json.fromString(e.toString)).getOrElse(Json.Null))
    }}
    val out = Json.obj("ergo_core" -> Json.fromString("6.0.7"), "sigma_state" -> Json.fromString("6.0.7"), "entries" -> Json.arr(entries: _*))
    java.nio.file.Files.write(java.nio.file.Paths.get(args(1)), out.spaces2.getBytes("UTF-8"))
  }
}

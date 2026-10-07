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


object RuleGatingOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides().withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf"))).withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    val baseChain = config.as[ChainSettings]("ergo.chain")
    implicit val chain: ChainSettings = baseChain.copy(reemission=baseChain.reemission.copy(checkReemissionRules=true))
    val tree = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(Base16.decode("8094ebdc0300d1dad90101017201010101c0843d0000010101010101010101010101010101010101010101010101010101010101010101010100").get)).ergoTree
    def tokens(n: Int) = Colls.fromArray((1 to n).map(i => (sigma.data.Digest32Coll @@ Colls.fromArray(Array.fill(30)(0.toByte) ++ Array((i >> 8).toByte,i.toByte)),1L)).toArray)
    def cand(value: Long, h: Int=1000, n: Int=0, t: sigma.ast.ErgoTree=tree) = new ErgoBoxCandidate(value,t,h,tokens(n))
    def box(index: Int, n: Int=0) = new ErgoBox(100000000000L,tree,tokens(n),Map.empty,bytesToId(Array.fill(32)((index+1).toByte)),index.toShort,1000)
    val b = box(0)
    val b2 = box(1)
    def input(b: ErgoBox, rent: Boolean=false) = Input(b.id, ProverResult(Array.emptyByteArray, if(rent) ContextExtension(Map(127.toByte -> sigma.ast.ShortConstant(0.toShort))) else ContextExtension.empty))
    def tx(inputs: Seq[Input], outputs: Seq[ErgoBoxCandidate], data: Seq[DataInput]=Seq.empty) = ErgoTransaction(inputs.toIndexedSeq,data.toIndexedSeq,outputs.toIndexedSeq)
    val oversized = sigma.ast.ErgoTree(sigma.ast.ErgoTree.HeaderType @@ 0x18.toByte, IndexedSeq(sigma.ast.ByteArrayConstant(Array.fill(4096)(0.toByte))), tree.toProposition(false))
    val rewardTokens = Colls.fromArray(Array(sigma.data.Digest32Coll @@ chain.reemission.reemissionTokenIdBytes -> 12000000000L))
    val reward = new ErgoBox(20000000000L,tree,rewardTokens,Map.empty,bytesToId(Array.fill(32)(99.toByte)),0.toShort,1000)
    val guardedOversized = new ErgoBoxCandidate(b.value,oversized,1000,Colls.fromArray(Array.empty[(sigma.data.Digest32Coll,Long)]),Map(ErgoBox.R4 -> sigma.ast.IntConstant(1)))
    val oversizedTokenBox = new ErgoBox(b.value,tree,tokens(255),Map(ErgoBox.R4 -> sigma.ast.IntConstant(1)),bytesToId(Array.fill(32)(77.toByte)),0.toShort,1000)
    val cases = Seq(
      ("ordinary-control",110,tx(Seq(input(b)),Seq(cand(b.value))),Seq(b),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("data-input-duplicates",110,tx(Seq(input(b)),Seq(cand(b.value)),Seq.fill(3)(DataInput(b2.id))),Seq(b),Seq.fill(3)(b2),Seq.empty[Int]),
      ("output-minimum",111,tx(Seq(input(b)),Seq(cand(1),cand(b.value-1))),Seq(b),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("box-size-123-tokens",120,tx(Seq(input(box(2,123))),Seq(cand(b.value,n=123))),Seq(box(2,123)),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("box-size-255-tokens",120,tx(Seq(input(box(3,255))),Seq(cand(b.value,n=255))),Seq(box(3,255)),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("box-window-register-after-tokens",120,tx(Seq(input(oversizedTokenBox)),Seq(cand(b.value,n=255))),Seq(oversizedTokenBox),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("box-window-register-after-tree",121,tx(Seq(input(b)),Seq(guardedOversized)),Seq(b),Seq.empty[ErgoBox],Seq(120)),
      ("proposition-size",121,tx(Seq(input(b)),Seq(cand(b.value,t=oversized))),Seq(b),Seq.empty[ErgoBox],Seq(120)),
      ("reemission-payment",123,tx(Seq(input(reward)),Seq(cand(reward.value))),Seq(reward),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("creation-height",124,tx(Seq(input(b)),Seq(cand(b.value,h=999))),Seq(b),Seq.empty[ErgoBox],Seq.empty[Int]),
      ("rent-output-indices",125,tx(Seq(input(b,true),input(b2,true)),Seq(cand(b.value+b2.value,h=1885000))),Seq(b,b2),Seq.empty[ErgoBox],Seq.empty[Int])
    )
    val params = Parameters(1884160,Map[Byte,Int](1.toByte->1250000,2.toByte->360,3.toByte->524288,4.toByte->1000000,5.toByte->100,6.toByte->2000,7.toByte->100,8.toByte->100,123.toByte->4),ErgoValidationSettingsUpdate.empty)
    val entries = cases.flatMap { case(name,id,t,boxes,data,extra) => Seq(false,true).map { disabled =>
      val ids = (extra ++ (if(disabled) Seq(id) else Seq.empty)).map(_.toShort)
      val settings = ErgoValidationSettings.initial.updated(ErgoValidationSettingsUpdate(ids,Seq.empty))
      val ctx = new ErgoStateContext(Seq.empty,None,chain.genesisStateDigest,params,settings,VotingData.empty) {
        override def sigmaPreHeader: sigma.PreHeader = CPreHeader(4.toByte,Colls.fromArray(Array.fill(32)(0.toByte)),0L,0L,1885000,CGroupElement(DLogProverInput.random().publicImage.value),Colls.fromArray(Array.fill(3)(0.toByte)))
      }
      implicit val verifier: ErgoInterpreter = new ErgoInterpreter(params)
      val wire = ErgoTransactionSerializer.toBytes(t)
      val reparsed = Try(ErgoTransactionSerializer.parseBytes(wire))
      val parsedBoxes = Try(boxes.map(b=>ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(b.bytes))))
      val result = reparsed.flatMap(parsed => parsedBoxes.flatMap(bs => Try(parsed.validateStateful(bs.toIndexedSeq,data.toIndexedSeq,ctx,0L).result.toTry).flatten))
      Json.obj("name"->Json.fromString(name+(if(disabled) "-disabled" else "-active")),"rule"->Json.fromInt(id),"disabled"->Json.arr(ids.map(i=>Json.fromInt(i.toInt)): _*),"tx"->Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(t))),"boxes"->Json.arr(boxes.map(b=>Json.fromString(Base16.encode(b.bytes))): _*),"data_boxes"->Json.arr(data.map(b=>Json.fromString(Base16.encode(b.bytes))): _*),"tx_parse_accept"->Json.fromBoolean(reparsed.isSuccess),"boxes_parse_accept"->Json.fromBoolean(parsedBoxes.isSuccess),"accept"->Json.fromBoolean(result.isSuccess),"cost"->result.toOption.map(Json.fromLong).getOrElse(Json.Null),"error"->result.failed.toOption.map(e=>Json.fromString(e.toString)).getOrElse(Json.Null))
    }}
    java.nio.file.Files.write(java.nio.file.Paths.get(args(1)),Json.obj("ergo_core"->Json.fromString("6.0.7"),"sigma_state"->Json.fromString("6.0.7"),"entries"->Json.arr(entries: _*)).spaces2.getBytes("UTF-8"))
  }
}

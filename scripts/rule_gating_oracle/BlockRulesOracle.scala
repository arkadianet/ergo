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


import io.circe.parser.parse
import org.ergoplatform.modifiers.history.header.{Header, HeaderSerializer}
import org.ergoplatform.modifiers.history.extension.Extension
import org.ergoplatform.modifiers.history.BlockTransactions
import org.ergoplatform.modifiers.ErgoFullBlock

object BlockRulesOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides().withFallback(ConfigFactory.parseFile(new File(args(0),"mainnet.conf"))).withFallback(ConfigFactory.parseFile(new File(args(0),"application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    def file(p:String) = parse(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)),"UTF-8")).right.get
    def hex(h:String) = Base16.decode(h).get
    val hj = file(args(1)).asArray.get.find(_.hcursor.get[Int]("height").right.get==1000).get
    val template = HeaderSerializer.parseBytes(hex(hj.hcursor.get[String]("bytes").right.get))
    val cj = file(args(2)).hcursor
    val tx = ErgoTransactionSerializer.parseBytes(hex(cj.get[String]("tx1_bytes").right.get))
    val boxes = cj.get[Vector[String]]("boxes1").right.get.map(h=>ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(hex(h))))
    val table: Map[Byte,Int] = Map(1.toByte->1250000,2.toByte->360,3.toByte->524288,4.toByte->1000000,5.toByte->100,6.toByte->2000,7.toByte->100,8.toByte->100,9.toByte->30,123.toByte->4)
    val dummy = Seq(Array(0x7f.toByte,0.toByte)->Array(1.toByte))
    def fieldsJson(fs: Seq[(Array[Byte],Array[Byte])]) = Json.arr(fs.map {case(k,v)=>Json.obj("key"->Json.fromString(Base16.encode(k)),"value"->Json.fromString(Base16.encode(v)))}: _*)
    val entries = Seq((306,0),(306,3),(111,2),(400,0),(401,0),(402,0),(404,0),(405,0),(406,0),(407,0),(408,0),(410,0),(411,0),(412,0),(413,0)).flatMap { case(id,missing) => Seq(false,true).map { off =>
      val epoch = Set(111,408,410,411,412).contains(id)
      val height = if(epoch) 1885184 else 1885001
      val extras = if(id==401) Seq(402) else if(id==400) Seq(405) else if(epoch) Seq(215,409) else Seq.empty[Int]
      val ids = (extras ++ (if(off) Seq(id) else Seq.empty[Int])).distinct.sorted
      val settings = ErgoValidationSettings.initial.updated(ErgoValidationSettingsUpdate(ids.map(_.toShort),Seq.empty))
      val prevTable = if(id==407) table ++ Map(122.toByte->(height-32768),121.toByte->0) else if(id==306 && missing==3) table - 3.toByte else if(id==306) table.updated(3.toByte,0) else table
      val prev = Parameters(1884160,prevTable,ErgoValidationSettingsUpdate.empty)
      val parent = template.copy(height=height-1,version=4.toByte,votes=Array.fill(3)(0.toByte))
      val header = template.copy(parentId=parent.id,height=height,version=(if(id==410) 3 else 4).toByte,votes=(if(id==407) Array(120.toByte,0.toByte,0.toByte) else Array.fill(3)(0.toByte)))
      val epochFields = Parameters(height,table - missing.toByte,ErgoValidationSettingsUpdate.empty).toExtensionCandidate.fields ++ settings.toExtensionCandidate.fields
      val fields = id match {
        case 400 => (0 until 600).map(i=>Array(0x7f.toByte,i.toByte)->Array.fill(64)(1.toByte))
        case 401 => Seq(Array(1.toByte,0.toByte)->Array.emptyByteArray)
        case 402 => dummy
        case 404 => Seq(Array(0x7f.toByte,0.toByte)->Array.fill(65)(1.toByte))
        case 405 => dummy ++ dummy
        case 406 => Seq.empty[(Array[Byte],Array[Byte])]
        case 408 => epochFields.filterNot(_._1.sameElements(Array(0.toByte,1.toByte))) ++ Seq(Array(0.toByte,1.toByte)->Array(1.toByte))
        case 411 => epochFields.filterNot(_._1(0)==2) ++ Seq(Array(2.toByte,0.toByte)->Array(0.toByte,1.toByte,16.toByte,1.toByte,3.toByte,0.toByte))
        case 412 => epochFields.filterNot(_._1(0)==2)
        case _ => if(epoch) epochFields else dummy
      }
      val ext = Extension(header.id,fields)
      val parentFields = Seq(Array(1.toByte,0.toByte)->(Array(1.toByte)++Array.fill(32)(1.toByte)))
      val parentExt = if(Set(401,402,413).contains(id)) Some(Extension(parent.id,parentFields)) else None
      val headers = if(id==413) Seq.empty else Seq(parent)
      val ctx = new ErgoStateContext(headers,parentExt,chain.genesisStateDigest,prev,settings,VotingData.empty)
      val processed = ctx.appendFullBlock(ErgoFullBlock(header,BlockTransactions(header.id,header.version,Seq(tx)),ext,None))
      val result = processed.flatMap { c =>
        implicit val verifier: ErgoInterpreter = new ErgoInterpreter(c.currentParameters)
        Try(tx.validateStateful(boxes.toIndexedSeq,IndexedSeq.empty,c,0L).result.toTry).flatten
      }
      Json.obj("name"->Json.fromString("rule-"+id+(if(missing!=0) "-missing-"+missing else "")+(if(off) "-disabled" else "-active")),"rule"->Json.fromInt(id),"missing"->Json.fromInt(missing),"disabled"->Json.arr(ids.map(Json.fromInt): _*),"epoch"->Json.fromBoolean(epoch),"parent"->Json.fromString(Base16.encode(HeaderSerializer.toBytes(parent))),"header"->Json.fromString(Base16.encode(HeaderSerializer.toBytes(header))),"fields"->fieldsJson(fields),"parent_fields"->parentExt.map(e=>fieldsJson(e.fields)).getOrElse(Json.Null),"no_parent"->Json.fromBoolean(id==413),"accept"->Json.fromBoolean(result.isSuccess),"cost"->result.toOption.map(Json.fromLong).getOrElse(Json.Null),"adopted_disabled"->processed.toOption.filter(_=>result.isSuccess).map(c=>Json.arr(c.validationSettings.updateFromInitial.rulesToDisable.map(i=>Json.fromInt(i.toInt)): _*)).getOrElse(Json.Null),"error"->result.failed.toOption.map(e=>Json.fromString(e.toString)).getOrElse(Json.Null))
    }}
    java.nio.file.Files.write(java.nio.file.Paths.get(args(3)),Json.obj("ergo_core"->Json.fromString("6.0.7"),"sigma_state"->Json.fromString("6.0.7"),"tx"->cj.downField("tx1_bytes").focus.get,"boxes"->cj.downField("boxes1").focus.get,"entries"->Json.arr(entries: _*)).spaces2.getBytes("UTF-8"))
  }
}

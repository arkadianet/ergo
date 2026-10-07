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

object ParameterSubsetOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    def jsonFile(p: String): Json = parse(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)), "UTF-8")).right.get
    def hex(h: String) = Base16.decode(h).get
    val headerJson = jsonFile(args(1)).asArray.get.find(_.hcursor.get[Int]("height").right.get == 1000).get
    val template = HeaderSerializer.parseBytes(hex(headerJson.hcursor.get[String]("bytes").right.get))
    val parent = template.copy(height=2047, version=4.toByte, votes=Array.fill(3)(0.toByte))
    val header = template.copy(parentId=parent.id, height=2048, version=4.toByte, votes=Array.fill(3)(0.toByte))
    val nextHeader = template.copy(parentId=header.id, height=2049, version=4.toByte, votes=Array.fill(3)(0.toByte))
    val costJson = jsonFile(args(2)).hcursor
    val tx = ErgoTransactionSerializer.parseBytes(hex(costJson.get[String]("tx1_bytes").right.get))
    val boxes = costJson.get[Vector[String]]("boxes1").right.get.map(h => ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(hex(h))))
    val table: Map[Byte,Int] = Map(1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288, 4.toByte -> 1000000, 5.toByte -> 100, 6.toByte -> 2000, 7.toByte -> 100, 8.toByte -> 100, 9.toByte -> 30, 123.toByte -> 4)
    val settings = ErgoValidationSettings.initial.updated(ErgoValidationSettingsUpdate(Seq(215.toShort,409.toShort), Seq.empty))
    val prev = Parameters(1024, table, ErgoValidationSettingsUpdate.empty)
    val entries = Seq(0,1,2,3,4,5,6,7,8,9,123).map { omitted =>
      val advertised = Parameters(2048, table - omitted.toByte, ErgoValidationSettingsUpdate.empty)
      val fields = advertised.toExtensionCandidate.fields ++ settings.toExtensionCandidate.fields
      val ext = Extension(header.id, fields)
      val ctx = new ErgoStateContext(Seq(parent), None, chain.genesisStateDigest, prev, settings, VotingData.empty)
      // appendFullBlock checks the parent maxBlockSize before adopting the parsed table.
      val processed = ctx.appendFullBlock(ErgoFullBlock(header, BlockTransactions(header.id,4.toByte,Seq(tx)), ext, None))
      val first = processed.flatMap { c =>
        implicit val verifier: ErgoInterpreter = new ErgoInterpreter(c.currentParameters)
        Try(tx.validateStateful(boxes, IndexedSeq.empty, c, 0L).result.toTry).flatten
      }
      val next = processed.flatMap { c =>
        // Interlinks are independent of this table-use oracle; omit the previous
        // extension so their recoverable validation path does not obscure size use.
        val nctx = new ErgoStateContext(c.lastHeaders, None, c.genesisStateDigest, c.currentParameters, c.validationSettings, c.votingData)
        val nextExt = Extension(nextHeader.id, Seq(Array(0x7f.toByte,0.toByte) -> Array(1.toByte)))
        nctx.appendFullBlock(ErgoFullBlock(nextHeader, BlockTransactions(nextHeader.id,4.toByte,Seq(tx)), nextExt, None))
          .flatMap { updated =>
            implicit val verifier: ErgoInterpreter = new ErgoInterpreter(updated.currentParameters)
            Try(tx.validateStateful(boxes, IndexedSeq.empty, updated, 0L).result.toTry).flatten
          }
      }
      val parsed = Parameters.parseExtension(2048,ext)
      Json.obj("omitted" -> Json.fromInt(omitted), "fields" -> Json.arr(fields.map {case(k,v) => Json.obj("key" -> Json.fromString(Base16.encode(k)), "value" -> Json.fromString(Base16.encode(v)))}: _*),
        "parse_accept" -> Json.fromBoolean(parsed.isSuccess), "first_accept" -> Json.fromBoolean(first.isSuccess), "next_accept" -> Json.fromBoolean(next.isSuccess),
        "first_cost" -> first.toOption.map(Json.fromLong).getOrElse(Json.Null), "next_cost" -> next.toOption.map(Json.fromLong).getOrElse(Json.Null),
        "first_error" -> first.failed.toOption.map(e=>Json.fromString(e.toString)).getOrElse(Json.Null), "next_error" -> next.failed.toOption.map(e=>Json.fromString(e.toString)).getOrElse(Json.Null))
    }
    val rentHeight = 1843200
    val rentTx = tx.copy(inputs=tx.inputs.map(i => i.copy(spendingProof=ProverResult(Array.emptyByteArray, ContextExtension(Map(127.toByte -> sigma.ast.ShortConstant(0.toShort)))))))
    val rentEntries = Seq(0,1).map { omitted =>
      val rp = Parameters(rentHeight,table - omitted.toByte,ErgoValidationSettingsUpdate.empty)
      val rentCtx = new ErgoStateContext(Seq.empty,None,chain.genesisStateDigest,rp,settings,VotingData.empty) {
        override def sigmaPreHeader: sigma.PreHeader = CPreHeader(4.toByte,Colls.fromArray(Array.fill(32)(0.toByte)),0L,0L,rentHeight,CGroupElement(DLogProverInput.random().publicImage.value),Colls.fromArray(Array.fill(3)(0.toByte)))
      }
      implicit val verifier: ErgoInterpreter = new ErgoInterpreter(rp)
      val result = Try(rentTx.validateStateful(boxes,IndexedSeq.empty,rentCtx,0L).result.toTry).flatten
      Json.obj("omitted" -> Json.fromInt(omitted), "height" -> Json.fromInt(rentHeight), "tx" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(rentTx))),
        "accept" -> Json.fromBoolean(result.isSuccess), "cost" -> result.toOption.map(Json.fromLong).getOrElse(Json.Null), "error" -> result.failed.toOption.map(e=>Json.fromString(e.toString)).getOrElse(Json.Null))
    }
    val out = Json.obj("ergo_core" -> Json.fromString("6.0.7"), "sigma_state" -> Json.fromString("6.0.7"),
      "rent_entries" -> Json.arr(rentEntries: _*), "tx" -> costJson.downField("tx1_bytes").focus.get, "boxes" -> costJson.downField("boxes1").focus.get, "entries" -> Json.arr(entries: _*))
    java.nio.file.Files.write(java.nio.file.Paths.get(args(3)), out.spaces2.getBytes("UTF-8"))
  }
}

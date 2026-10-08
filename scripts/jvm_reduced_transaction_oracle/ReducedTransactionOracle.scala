//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform:ergo-appkit_2.12:6.0.1
//> using repository "https://repo.maven.apache.org/maven2"

// Real SDK reducer/serializer oracle. Public fixture keys only.
import java.math.BigInteger
import java.util.Base64
import java.nio.file.{Files, Paths}
import io.circe.Json
import org.ergoplatform._
import org.ergoplatform.sdk._
import org.ergoplatform.sdk.wallet.protocol.context.CBlockchainStateContext
import org.ergoplatform.validation.ValidationRules
import scorex.util.bytesToId
import scorex.util.encode.Base16
import sigma.{Coll, Colls, Header, VersionContext}
import sigma.ast._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.data._
import sigma.interpreter.{ContextExtension, ProverResult}
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer}
import sigma.util.Extensions.EcpOps
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.Interpreter
import sigmastate.crypto.DLogProtocol.DLogProverInput

object ReducedTransactionOracle extends App {
  def hex(b:Array[Byte]) = Base16.encode(b)
  def j(s:String) = Json.fromString(s)
  def b64(b:Array[Byte]) = Base64.getEncoder.encodeToString(b)
  def qrPages(prefix:String, inner:String, limit:Int=400):Json = {
    // Match ergo-wallet-app ColdWalletUtils.kt at beeecb1009e26c6ea9b506d5fca3a4efb3f79f9e.
    val chunks=inner.grouped(limit-30-prefix.length).toVector
    Json.arr(chunks.zipWithIndex.map {case(chunk,index)=>
      val page=if(chunks.length==1) Json.obj(prefix->j(chunk)) else
        Json.obj(prefix->j(chunk),"n"->Json.fromInt(chunks.length),"p"->Json.fromInt(index+1))
      j(page.noSpaces)
    }:_*)
  }
  val keys=(1 to 3).map(n=>DLogProverInput(BigInteger.valueOf(n))).toIndexedSeq
  val p=keys.map(_.publicImage)
  val params=CBlockchainParameters(1250000,360,524288,100,2000,100,100,1000000,None,None,4.toByte)
  val pre=CPreHeader(4.toByte,Colls.fromArray(Array.fill(32)(0.toByte)),3L,0L,400000,
    p.head.value.toGroupElement,Colls.fromArray(Array.fill(3)(0.toByte)))
  val state=CBlockchainStateContext(Colls.emptyColl[Header],Colls.fromArray(Array.fill(33)(0.toByte)),pre)
  val reducer=new ReducingInterpreter(params)
  val c1=keys(1).publicImage.value.toGroupElement
  val c2=DLogProverInput(BigInteger.valueOf(6)).publicImage.value.toGroupElement
  val dht=JavaHelpers.createDiffieHellmanTupleProverInput(c1,c1,c2,c2,BigInteger.valueOf(3))
  val prover=new AppkitProvingInterpreter(IndexedSeq.empty,keys,IndexedSeq(dht),params)
  val coldClient=new org.ergoplatform.appkit.ColdErgoClient(
    org.ergoplatform.appkit.NetworkType.MAINNET,1000000,4.toByte)
  val coldCtx=coldClient.execute[org.ergoplatform.appkit.BlockchainContext](
    new java.util.function.Function[org.ergoplatform.appkit.BlockchainContext,org.ergoplatform.appkit.BlockchainContext] {
      def apply(ctx:org.ergoplatform.appkit.BlockchainContext)=ctx
    })
  val coldBuilder=coldCtx.newProverBuilder()
  (1 to 3).foreach(n=>coldBuilder.withDLogSecret(BigInteger.valueOf(n)))
  coldBuilder.withDHTData(c1,c1,c2,c2,BigInteger.valueOf(3))
  val coldProver=coldBuilder.build()
  implicit val E: sigmastate.interpreter.CErgoTreeEvaluator = null
  val compiler=new SigmaCompiler(0.toByte)
  def compile(source:String,env:Map[String,Any]=Map.empty):ErgoTree = VersionContext.withVersions(3.toByte,0.toByte) {
    val result=compiler.compile(env,source)(new CompiletimeIRContext)
    ErgoTree.fromProposition(result.buildTree.asInstanceOf[Value[SSigmaProp.type]])
  }
  val trueTree=ErgoTree.fromSigmaBoolean(TrivialProp.TrueProp)
  val pkTree=ErgoTree.fromSigmaBoolean(p.head)
  def tokens(ts:(Int,Long)*)=Colls.fromArray(ts.map {case(n,v)=>(Digest32Coll @@ Colls.fromArray(Array.fill(32)(n.toByte)),v)}.toArray)
  def box(tree:ErgoTree,value:Long=100000000L,idx:Int=0,
      assets:Coll[(Digest32Coll,Long)]=Colls.emptyColl,
      regs:Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]]=Map.empty)=
    new ErgoBox(value,tree,assets,regs,bytesToId(Array.fill(32)((idx+1).toByte)),idx.toShort,100)
  def out(tree:ErgoTree,value:Long,assets:Coll[(Digest32Coll,Long)]=Colls.emptyColl,
      regs:Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]]=Map.empty)=
    new ErgoBoxCandidate(value,tree,100,assets,regs)
  def capture(name:String,boxes:IndexedSeq[ErgoBox],outputs:IndexedSeq[ErgoBoxCandidate],
      data:IndexedSeq[ErgoBox]=IndexedSeq.empty, source:String="",
      extension:ContextExtension=ContextExtension.empty):Json = {
    val unsigned=new UnsignedErgoLikeTransaction(boxes.map(b=>new UnsignedInput(b.id,extension)),
      data.map(b=>DataInput(b.id)),outputs)
    val unreduced=UnreducedTransaction(unsigned,boxes.map(b=>ExtendedInputBox(b,extension)),data,IndexedSeq.empty)
    val reduced=reducer.reduceTransaction(unreduced,state,0)
    val encoded=reduced.toHex
    val parsed=ReducedTransaction.fromHex(encoded)
    assert(parsed.toHex==encoded)
    // Exercise actual AppKit cold APIs, not only the shared SDK serializer.
    val appkitReduced=coldCtx.parseReducedTransaction(Base16.decode(encoded).get)
    assert(hex(appkitReduced.toBytes)==encoded)
    val appkitSigned=coldProver.signReduced(appkitReduced,parsed.ergoTx.cost)
    val signed=coldCtx.parseSignedTransaction(appkitSigned.toBytes).asInstanceOf[org.ergoplatform.appkit.impl.SignedTransactionImpl]
    assert(java.util.Arrays.equals(signed.toBytes,appkitSigned.toBytes))
    assert(signed.getId==appkitReduced.getId)
    val proofs=signed.getTx.inputs.map(i=>hex(i.spendingProof.proof))
    val request=Json.obj("reducedTx"->j(b64(appkitReduced.toBytes)),
      "inputs"->Json.arr(boxes.map(b=>j(b64(ErgoBox.sigmaSerializer.toBytes(b)))):_*)).noSpaces
    val response=Json.obj("signedTx"->j(b64(signed.toBytes))).noSpaces
    Json.obj("name"->j(name),"source"->j(source),"reduced_hex"->j(encoded),
      "input_boxes"->Json.arr(boxes.map(b=>j(hex(ErgoBox.sigmaSerializer.toBytes(b)))):_*),
      "data_boxes"->Json.arr(data.map(b=>j(hex(ErgoBox.sigmaSerializer.toBytes(b)))):_*),
      "sigma_hex"->Json.arr(reduced.ergoTx.reducedInputs.map(i=>j(hex(SigmaBoolean.serializer.toBytes(i.reductionResult.value)))):_*),
      "input_costs"->Json.arr(reduced.ergoTx.reducedInputs.map(i=>Json.fromLong(i.reductionResult.cost)):_*),
      "reduction_cost"->Json.fromInt(reduced.ergoTx.cost),"crypto_cost"->Json.fromInt(appkitSigned.getCost),
      "scala_proofs"->Json.arr(proofs.map(j):_*),
      "unsigned_message_hex"->j(hex(unsigned.messageToSign)),"transaction_id"->j(unsigned.id),
      "ergopay_uri"->j("ergopay:"+Base64.getUrlEncoder.encodeToString(appkitReduced.toBytes)),
      "ergopay_request"->Json.obj("reducedTx"->j(Base64.getUrlEncoder.encodeToString(appkitReduced.toBytes)),
        "message"->j("Fixture signing request"),"messageSeverity"->j("INFORMATION"),
        "replyTo"->j("https://example.invalid/reply")),
      "cold_request"->j(request),"csr_qr_low_pages"->qrPages("CSR",request),
      "scala_signed_hex"->j(hex(ErgoLikeTransactionSerializer.toBytes(signed.getTx))),
      "appkit_signed_hex"->j(hex(signed.toBytes)),"cold_response"->j(response),
      "cstx_qr_low_pages"->qrPages("CSTX",response))
  }
  if (args.headOption.contains("verify")) {
    val json=io.circe.parser.parse(new String(Files.readAllBytes(Paths.get(args(1))),"UTF-8")).right.get
    json.asArray.get.foreach { row =>
      val h=row.hcursor
      val reduced=ReducedTransaction.fromHex(h.get[String]("reduced_hex").right.get)
      val appkitReduced=coldCtx.parseReducedTransaction(Base16.decode(h.get[String]("reduced_hex").right.get).get)
      assert(appkitReduced.getId==reduced.ergoTx.unsignedTx.id)
      val bytes=Base16.decode(h.get[String]("appkit_signed_hex").right.get).get
      val tx=coldCtx.parseSignedTransaction(bytes).asInstanceOf[org.ergoplatform.appkit.impl.SignedTransactionImpl]
      assert(java.util.Arrays.equals(tx.toBytes,bytes),"AppKit signed wrapper was not consumed exactly")
      assert(tx.getId==appkitReduced.getId)
      assert(java.util.Arrays.equals(tx.getTx.messageToSign,reduced.ergoTx.unsignedTx.messageToSign))
      assert(tx.getCost==h.get[Int]("crypto_cost").right.get)
      val rawBytes=Base16.decode(h.get[String]("signed_hex").right.get).get
      assert(java.util.Arrays.equals(ErgoLikeTransactionSerializer.toBytes(tx.getTx),rawBytes),
        "Raw signed transaction differs from AppKit wrapper")
      val signedRequest=Json.obj("signedTx"->j(b64(bytes))).noSpaces
      assert(java.util.Arrays.equals(Base64.getDecoder.decode(
        io.circe.parser.parse(signedRequest).right.get.hcursor.get[String]("signedTx").right.get),bytes))
      val proofHex=h.get[Vector[String]]("proofs").right.get
      assert(proofHex.length==reduced.ergoTx.reducedInputs.length,"Missing or extra Rust proofs")
      assert(proofHex==tx.getTx.inputs.map(i=>hex(i.spendingProof.proof)).toVector,
        "Detached proof array differs from full signed transaction")
      reduced.ergoTx.reducedInputs.zip(proofHex).foreach {case(input,proof)=>
        val bytes=Base16.decode(proof).get
        val valid=input.reductionResult.value match {
          case TrivialProp.TrueProp => bytes.isEmpty
          case TrivialProp.FalseProp => false
          case sigma => prover.verifySignature(sigma,reduced.ergoTx.unsignedTx.messageToSign,bytes)
        }
        assert(valid,"Rust proof rejected for "+h.get[String]("name").right.get)
      }
    }
    println("scala-verifies-rust-reduced-proofs")
  } else {
    val basic=Seq("true"->TrivialProp.TrueProp,"dlog"->p(0),"dht"->dht.publicImage,"and"->CAND(Seq(p(0),p(1))),
      "or"->COR(Seq(p(0),p(1))),"threshold"->CTHRESHOLD(2,Seq(p(0),p(1),p(2))))
      .map {case(n,s)=>capture(n,IndexedSeq(box(ErgoTree.fromSigmaBoolean(s))),IndexedSeq(out(pkTree,100000000L)))}
    val heightSource="{ sigmaProp(HEIGHT > 350000 && OUTPUTS(0).creationInfo._1 == 100) && proveDlog(groupGenerator) }"
    val height=capture("height_contract",IndexedSeq(box(compile(heightSource))),IndexedSeq(out(pkTree,100000000L)),source=heightSource)
    val poolSource=new String(Files.readAllBytes(Paths.get("test-vectors/ergoscript/cannonq/significant15/spectrum_n2t_pool.es")),"UTF-8")
    val pool=compile(poolSource)
    val feeReg=Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]](ErgoBox.R4->IntConstant(999))
    val spectrum=capture("spectrum_n2t_swap",IndexedSeq(box(pool,1000000000L,0,tokens(10->1L,11->(Long.MaxValue-1000L),12->1000L),feeReg),box(pkTree,200000000L,1)),
      IndexedSeq(out(pool,1100000000L,tokens(10->1L,11->(Long.MaxValue-1000L),12->910L),feeReg),out(pkTree,100000000L,tokens(12->90L))),source=poolSource)
    val bankSource=new String(Files.readAllBytes(Paths.get("test-vectors/ergoscript/cannonq/significant15/sigmausd_bank.es")),"UTF-8")
    val bank=compile(bankSource,Map("oraclePoolNFT"->Array.fill(32)(20.toByte),"updateNFT"->Array.fill(32)(21.toByte),
      "minReserveRatioPercent"->400L,"defaultMaxReserveRatioPercent"->800L))
    def bankRegs(sc:Long)=Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]](ErgoBox.R4->LongConstant(sc),ErgoBox.R5->LongConstant(100L))
    val receiptRegs=Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]](ErgoBox.R4->LongConstant(10L),ErgoBox.R5->LongConstant(10200000L))
    val rateRegs=Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]](ErgoBox.R4->LongConstant(100000000L))
    val bankCase=capture("ageusd_bank_mint",IndexedSeq(box(bank,1000000000L,0,tokens(30->1000L,31->1000L,32->1L),bankRegs(100L)),box(pkTree,30000000L,1)),
      IndexedSeq(out(bank,1010200000L,tokens(30->990L,31->1000L,32->1L),bankRegs(110L)),out(pkTree,19800000L,tokens(30->10L),receiptRegs)),
      IndexedSeq(box(trueTree,100000000L,2,tokens(20->1L),rateRegs)),bankSource)
    val extensionSource="{ sigmaProp(getVar[Int](1).get == 42) && proveDlog(groupGenerator) }"
    val extensionCase=capture("context_extension",IndexedSeq(box(compile(extensionSource))),
      IndexedSeq(out(pkTree,100000000L)),source=extensionSource,
      extension=ContextExtension(Map(1.toByte->IntConstant(42))))
    // Exact full-mix contract from anon92048/ergo-mixer-demo at
    // c4df6ad3758aa5bad259b71735891f15439f5753, ErgoMix.scala.
    val zerojoinSource="{ val c1 = SELF.R4[GroupElement].get; val c2 = SELF.R5[GroupElement].get; proveDlog(c2) || proveDHTuple(c1, c1, c2, c2) }"
    val mixRegs=Map[ErgoBox.NonMandatoryRegisterId,EvaluatedValue[_ <: SType]](
      ErgoBox.R4->GroupElementConstant(c1),ErgoBox.R5->GroupElementConstant(c2))
    val zerojoin=capture("zerojoin_full_mix_dht",IndexedSeq(box(compile(zerojoinSource),100000000L,0,Colls.emptyColl,mixRegs)),
      IndexedSeq(out(pkTree,100000000L)),source=zerojoinSource)
    println(Json.obj("provenance"->j("Scala sigma-state 6.0.7 SDK ReducingInterpreter, AppKit 6.0.1 ColdErgoClient; EIP-19 CSR/CSTX and EIP-20 ErgoPay"),
      "block_version"->Json.fromInt(4),"height"->Json.fromInt(400000),"cases"->Json.arr((basic++Seq(height,spectrum,bankCase,zerojoin,extensionCase)):_*)).spaces2)
  }
}

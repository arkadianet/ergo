//> using scala 2.12.20
//> using dep org.ergoplatform::ergo-core:6.0.6
//> using dep org.ergoplatform::ergo-wallet:6.0.6
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.io.File
import java.nio.file.{Files, Paths}
import com.typesafe.config.ConfigFactory
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import io.circe.Json
import io.circe.syntax._
import org.ergoplatform._
import org.ergoplatform.http.api.ApiCodecs
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import org.ergoplatform.modifiers.history.BlockTransactions
import org.ergoplatform.modifiers.history.header.{HeaderWithoutPow, HeaderSerializer}
import org.ergoplatform.mining.{AutolykosSolution, ProofOfUpcomingTransactions}
import org.ergoplatform.nodeView.mempool.TransactionMembershipProof
import org.ergoplatform.nodeView.state.{ErgoStateContext, VotingData}
import org.ergoplatform.settings._
import org.ergoplatform.sdk.wallet.secrets.DlogSecretKey
import org.ergoplatform.wallet.interpreter.{ErgoInterpreter, ErgoProvingInterpreter}
import scorex.util.bytesToId
import scorex.util.encode.Base16
import sigma.Colls
import sigma.ast._
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.data.CGroupElement
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer}
import sigmastate.crypto.DLogProtocol.DLogProverInput
import sigmastate.eval.CPreHeader

object MiningRequestOracle extends PowSchemeReaders with ModifierIdReader with SettingsReaders with ApiCodecs {
  def main(args: Array[String]): Unit = {
    val config = ConfigFactory.defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(args(0), "mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(args(0), "application.conf"))).resolve()
    implicit val chain: ChainSettings = config.as[ChainSettings]("ergo.chain")
    val secret = DLogProverInput(java.math.BigInteger.ONE)
    val other = DLogProverInput(java.math.BigInteger.valueOf(2))
    val height = 15
    val parameters = Parameters(height, Map[Byte, Int](
      1.toByte -> 1250000, 2.toByte -> 360, 3.toByte -> 524288,
      4.toByte -> 1000000, 5.toByte -> 100, 6.toByte -> 2000,
      7.toByte -> 100, 8.toByte -> 100, 123.toByte -> 3), ErgoValidationSettingsUpdate.empty)
    def context(key: DLogProverInput) = new ErgoStateContext(Seq.empty, None, chain.genesisStateDigest,
      parameters, ErgoValidationSettings.initial, VotingData.empty) {
      override def sigmaPreHeader: sigma.PreHeader = CPreHeader(3.toByte,
        Colls.fromArray(Array.fill(32)(0.toByte)), 0L, 0L, height,
        CGroupElement(key.publicImage.value), Colls.fromArray(Array.fill(3)(0.toByte)))
    }
    val source = "sigmaProp(CONTEXT.preHeader.minerPk == groupGenerator) && proveDlog(groupGenerator)"
    val compiler = new SigmaCompiler(0.toByte)
    val policy = sigma.VersionContext.withVersions(2.toByte, 2.toByte) {
      val result = compiler.compile(Map.empty, source)(new CompiletimeIRContext)
      ErgoTree.fromProposition(result.buildTree.asInstanceOf[Value[SSigmaProp.type]])
    }
    val p2pk = ErgoTree.fromProposition(SigmaPropConstant(secret.publicImage))
    val input = new ErgoBox(1000000000L, policy, Colls.emptyColl, Map.empty,
      bytesToId(Array.fill(32)(1.toByte)), 0.toShort, height)
    val prover = new ErgoProvingInterpreter(IndexedSeq(DlogSecretKey(secret)), parameters)
    def make(inputs: IndexedSeq[ErgoBox], value: Long): ErgoTransaction = {
      val unsigned = new UnsignedErgoLikeTransaction(inputs.map(b => new UnsignedInput(b.id)),
        IndexedSeq.empty, IndexedSeq(new ErgoBoxCandidate(value, p2pk, height)))
      val signed = prover.sign(unsigned, inputs, IndexedSeq.empty, context(secret)).get
      ErgoTransaction(signed.inputs, signed.dataInputs, signed.outputCandidates)
    }
    val parent = make(IndexedSeq(input), input.value)
    val corruptedProof = parent.inputs.head.spendingProof.proof.clone()
    corruptedProof(0) = (corruptedProof(0) ^ 0x80).toByte
    val badSignature = ErgoTransaction(IndexedSeq(Input(input.id,
      sigma.interpreter.ProverResult(corruptedProof, sigma.interpreter.ContextExtension.empty))),
      parent.dataInputs, parent.outputCandidates)
    val child = make(parent.outputs, input.value)
    val conflict = make(IndexedSeq(input), input.value - 1000000L)
    implicit val verifier: ErgoInterpreter = new ErgoInterpreter(parameters)
    def verdict(tx: ErgoTransaction, boxes: IndexedSeq[ErgoBox], key: DLogProverInput): Json = {
      val result = tx.validateStateful(boxes, IndexedSeq.empty, context(key), accumulatedCost = 0L).result.toTry
      Json.obj("accept" -> Json.fromBoolean(result.isSuccess),
        "cost" -> result.toOption.map(Json.fromLong).getOrElse(Json.Null))
    }
    val independentInput = new ErgoBox(input.value, p2pk, Colls.emptyColl, Map.empty,
      bytesToId(Array.fill(32)(2.toByte)), 0.toShort, height)
    val independent = make(IndexedSeq(independentInput), input.value)
    val transactions = Seq(parent, child, conflict, independent)
    val proofTransactions = Seq(parent, child, independent)
    val block = BlockTransactions(bytesToId(Array.fill(32)(0.toByte)), 3.toByte, proofTransactions)
    val header = HeaderWithoutPow(3.toByte, bytesToId(Array.fill(32)(0.toByte)),
      scorex.crypto.hash.Digest32 @@ Array.fill(32)(0.toByte),
      scorex.crypto.authds.ADDigest @@ Array.fill(33)(0.toByte), block.digest,
      0L, 0L, height, scorex.crypto.hash.Digest32 @@ Array.fill(32)(0.toByte),
      Array.fill(3)(0.toByte), Array.emptyByteArray)
    val proof = ProofOfUpcomingTransactions(header, proofTransactions.map(tx =>
      TransactionMembershipProof(tx.id, block.proofFor(tx.id).get)))
    val fullHeader = header.toHeader(AutolykosSolution(secret.publicImage.value,
      secret.publicImage.value, Array.fill(8)(0.toByte), BigInt(0)))
    def artifact(cls: Class[_]): Json = {
      val path = Paths.get(cls.getProtectionDomain.getCodeSource.getLocation.toURI)
      val digest = java.security.MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))
      Json.obj("file" -> Json.fromString(path.getFileName.toString), "sha256" -> Json.fromString(Base16.encode(digest)))
    }
    val output = Json.obj(
      "provenance" -> Json.obj("oracle" -> Json.fromString("Ergo core/wallet and sigma-state 6.0.6 standalone JVM"),
        "jvm" -> Json.fromString(System.getProperty("java.runtime.version")),
        "artifacts" -> Json.arr(artifact(classOf[ErgoTransaction]), artifact(classOf[ErgoProvingInterpreter]), artifact(classOf[ErgoTree]))),
      "source" -> Json.fromString(source),
      "miner_pk" -> Json.fromString(Base16.encode(GroupElementSerializer.toBytes(secret.publicImage.value))),
      "wrong_miner_pk" -> Json.fromString(Base16.encode(GroupElementSerializer.toBytes(other.publicImage.value))),
      "height" -> Json.fromInt(height), "block_version" -> Json.fromInt(3),
      "input_box" -> Json.fromString(Base16.encode(input.bytes)),
      "independent_input_box" -> Json.fromString(Base16.encode(independentInput.bytes)),
      "transactions_json" -> Json.arr(transactions.map(tx => Json.fromString(tx.asJson.noSpaces)): _*),
      "bad_signature_transaction" -> Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(badSignature))),
      "parent_bad_signature" -> verdict(badSignature, IndexedSeq(input), secret),
      "transactions" -> Json.arr(transactions.map(tx => Json.fromString(Base16.encode(ErgoTransactionSerializer.toBytes(tx)))): _*),
      "parent_matching_key" -> verdict(parent, IndexedSeq(input), secret),
      "parent_wrong_key" -> verdict(parent, IndexedSeq(input), other),
      "independent" -> verdict(independent, IndexedSeq(independentInput), secret),
      "child" -> verdict(child, parent.outputs, secret),
      "header" -> Json.fromString(Base16.encode(HeaderSerializer.toBytes(fullHeader))),
      "proof" -> proof.asJson)
    Files.write(Paths.get(args(1)), (output.spaces2 + "\n").getBytes("UTF-8"))
  }
}

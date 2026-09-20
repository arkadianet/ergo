//> using scala 2.12
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.15
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import io.circe.HCursor
import org.ergoplatform.{ErgoBox, ErgoBoxCandidate, ErgoLikeContext, ErgoLikeInterpreter, UnsignedErgoLikeTransaction, UnsignedInput}
import org.ergoplatform.modifiers.ErgoFullBlock
import org.ergoplatform.modifiers.mempool.ErgoTransaction
import org.ergoplatform.nodeView.state.UtxoState
import org.ergoplatform.settings.ErgoSettings
import sigma.ast.{ErgoTree, SigmaPropConstant}
import sigma.serialization.ErgoTreeSerializer
import org.ergoplatform.http.api.ApiCodecs
import org.ergoplatform.Input

/** Spend the public scalar-one reward only after the unchanged 720-block maturity delay. */
object CampaignTransactions extends ApiCodecs {
  val secret = sigmastate.crypto.DLogProtocol.DLogProverInput(java.math.BigInteger.ONE)
  val p2pk = ErgoTree.fromProposition(SigmaPropConstant(secret.publicImage))
  def tree(hex: String): ErgoTree = sigma.VersionContext.withVersions(3.toByte, 3.toByte) {
    ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(scorex.util.encode.Base16.decode(hex).get)
  }
  def sign(inputs: IndexedSeq[ErgoBox], outputs: IndexedSeq[ErgoBoxCandidate], signed: Boolean): ErgoTransaction = {
    val unsigned = new UnsignedErgoLikeTransaction(inputs.map(b => new UnsignedInput(b.id)), IndexedSeq.empty, outputs)
    val prover = new ErgoLikeInterpreter with sigmastate.interpreter.ProverInterpreter {
      override type CTX = ErgoLikeContext
      override val secrets = IndexedSeq(secret)
    }
    val proof = if (signed) prover.generateProof(secret.publicImage, unsigned.messageToSign,
      sigmastate.interpreter.HintsBag.empty) else Array.emptyByteArray
    ErgoTransaction(inputs.map(b => Input(b.id, sigma.interpreter.ProverResult(proof,
      sigma.interpreter.ContextExtension.empty))), IndexedSeq.empty, outputs)
  }
  def make(request: HCursor, parents: Vector[ErgoFullBlock], state: UtxoState, settings: ErgoSettings): Vector[ErgoTransaction] = {
    val height = state.stateContext.currentHeight + 1
    def output(value: Long, script: ErgoTree) = new ErgoBoxCandidate(value, script, height)
    val stage = request.get[String]("campaign_stage").right.get
    if (stage == "fund") {
      require(height >= 721, "mine at least 720 blocks before funding")
      val reward = parents.iterator.map(_.transactions.head.outputs.last).find { box =>
        height >= box.creationHeight + settings.miningRewardDelay && state.boxById(box.id).isDefined
      }.getOrElse(throw new IllegalArgumentException("no mature unspent miner reward"))
      val workload = request.get[Vector[String]]("workload_trees").right.get.map(tree)
      // Thirty empty BlockValues use the evaluator path for the P2PK proposition.
      // The production JVM observation must confirm the resulting 37510 boundary.
      val extra = tree("00" + "d800" * 30 + "08cd" + scorex.util.encode.Base16.encode(secret.publicImage.pkBytes))
      val scripts = Vector.fill(3)(p2pk) ++ Vector(extra, p2pk, p2pk) ++ Vector.fill(3)(p2pk) ++ workload
      val allocations = scripts.map(output(1000000000L, _))
      val change = output(reward.value - allocations.map(_.value).sum, p2pk)
      Vector(sign(Vector(reward), allocations :+ change, signed = true))
    } else {
      val funding = request.get[ErgoTransaction]("funding").right.get.outputs
      def spend(index: Int, signed: Boolean, fee: Boolean = false): ErgoTransaction = {
        val input = funding(index)
        val outputs = if (fee) Vector(output(input.value - 1000000L, p2pk),
          output(1000000L, ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(settings.chainSettings.monetary.feePropositionBytes)))
        else Vector(output(input.value, p2pk))
        sign(Vector(input), outputs, signed)
      }
      stage match {
        case "sum-at-cap" => (0 to 2).map(spend(_, true)).toVector
        case "sum-over-cap" => (3 to 5).map(spend(_, true)).toVector
        case "single-at-cap" =>
          val inputs = funding.slice(6, 9).toVector
          val total = inputs.map(_.value).sum
          val outputs = Vector.fill(202)(output(1000000L, p2pk)) :+ output(total - 202000000L, p2pk)
          Vector(sign(inputs, outputs, signed = true))
        case "workload" => Vector(spend(9 + request.get[Int]("workload_index").right.get, false, fee = true))
        case _ => throw new IllegalArgumentException("unknown campaign stage " + stage)
      }
    }
  }
}

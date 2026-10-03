//> using scala 2.12.20
//> using dep org.ergoplatform::ergo-wallet:6.0.6
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.5

// Reduce input scripts after limited structural/monetary prechecks.
// This diagnostic does not verify spending proofs, apply protocol monetary
// limits, or establish signed transaction validity.
//
// Input format (stdin, JSONL — one entry per line):
//   {"txBytes":"<hex>","inputBoxes":[{...box JSON...}],"dataInputBoxes":[{...}],"height":700000,"minerPk":"<33-byte hex>","timestamp":1600000000000}
//
// Output format (stdout, one line per input):
//   REDUCED_UNVERIFIED <txId>
//   FAIL <txId> <errorCategory> <message>
//
// Diagnostic failure categories: STRUCTURAL, MONETARY, SCRIPT, COST, UNKNOWN

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import io.circe.parser._
import io.circe._
import scorex.util.encode.Base16
import sigma.Colls
import sigma.ast.JitCost
import sigma.data.{AvlTreeData, CGroupElement}
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import org.ergoplatform.validation.ValidationRules
import sigmastate.interpreter.CostAccumulator
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.CErgoTreeEvaluator
import sigma.VersionContext
import scorex.util.ModifierId
import java.io._

object ReduceTransactionScripts extends JsonCodecs {
  def main(args: Array[String]): Unit = {
    val reader = new BufferedReader(new InputStreamReader(System.in))
    var line: String = null
    while ({ line = reader.readLine(); line != null }) {
      val trimmed = line.trim
      if (trimmed.nonEmpty) {
        try {
          processLine(trimmed)
        } catch {
          case e: Exception =>
            System.err.println(s"  ERROR processing line: ${e.getMessage}")
            println(s"FAIL unknown UNKNOWN ${e.getClass.getSimpleName}: ${e.getMessage}")
        }
      }
    }
  }

  def processLine(jsonLine: String): Unit = {
    val json = parse(jsonLine).getOrElse(sys.error("invalid JSON"))
    val cursor = json.hcursor

    val txHex = cursor.get[String]("txBytes").getOrElse(sys.error("missing txBytes"))
    val txBytes = Base16.decode(txHex).get
    val tx = ErgoLikeTransactionSerializer.parse(SigmaSerializer.startReader(txBytes))
    val txId = tx.id.toString

    val inputBoxesJson = cursor.downField("inputBoxes").focus.getOrElse(sys.error("missing inputBoxes"))
    val inputBoxes = inputBoxesJson.as[Seq[ErgoBox]](
      Decoder.decodeSeq(ergoBoxDecoder)).getOrElse(sys.error("failed to parse input boxes"))

    val dataInputBoxes = cursor.downField("dataInputBoxes").focus
      .flatMap(_.as[Seq[ErgoBox]](Decoder.decodeSeq(ergoBoxDecoder)).toOption)
      .getOrElse(Seq.empty)

    val height = cursor.get[Int]("height").getOrElse(700000)
    val timestamp = cursor.get[Long]("timestamp").getOrElse(1600000000000L)
    val minerPkHex = cursor.get[String]("minerPk").getOrElse(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    val minerPkBytes = Base16.decode(minerPkHex).get
    val minerPkEcp = GroupElementSerializer.parse(SigmaSerializer.startReader(minerPkBytes))

    // Structural: inputs present
    if (tx.inputs.isEmpty) {
      println(s"FAIL $txId STRUCTURAL no_inputs")
      return
    }
    // Structural: no duplicate inputs
    val inputIds = tx.inputs.map(i => Base16.encode(i.boxId))
    if (inputIds.distinct.size != inputIds.size) {
      println(s"FAIL $txId STRUCTURAL duplicate_inputs")
      return
    }

    // Resolve inputs
    val inputMap = inputBoxes.map(b => Base16.encode(b.id) -> b).toMap
    for (input <- tx.inputs) {
      if (!inputMap.contains(Base16.encode(input.boxId))) {
        println(s"FAIL $txId STRUCTURAL missing_input_box")
        return
      }
    }

    // Monetary: ERG conservation
    val resolvedInputs = tx.inputs.map(i => inputMap(Base16.encode(i.boxId)))
    val inputValue = resolvedInputs.map(_.value).sum
    val outputValue = tx.outputCandidates.map(_.value).sum
    if (outputValue > inputValue) {
      println(s"FAIL $txId MONETARY erg_inflation")
      return
    }

    // Monetary: token conservation
    val inputTokens = scala.collection.mutable.Map[String, Long]()
    for (box <- resolvedInputs; (tokId, amount) <- box.additionalTokens.toArray) {
      val key = Base16.encode(tokId.toArray)
      inputTokens(key) = inputTokens.getOrElse(key, 0L) + amount
    }
    val outputTokens = scala.collection.mutable.Map[String, Long]()
    for (out <- tx.outputCandidates; (tokId, amount) <- out.additionalTokens.toArray) {
      val key = Base16.encode(tokId.toArray)
      outputTokens(key) = outputTokens.getOrElse(key, 0L) + amount
    }
    val firstInputId = Base16.encode(tx.inputs.head.boxId)
    for ((tokId, outAmt) <- outputTokens) {
      val inAmt = inputTokens.getOrElse(tokId, 0L)
      if (outAmt > inAmt && tokId != firstInputId) {
        println(s"FAIL $txId MONETARY token_inflation")
        return
      }
    }

    // Script reduction per input; spending proofs are deliberately unverified
    val preHeader = CPreHeader(
      2.toByte,
      Colls.fromArray(Array.fill(32)(0.toByte)),
      timestamp, 0L, height,
      CGroupElement(minerPkEcp),
      Colls.fromArray(Array.fill(3)(0.toByte)))

    for ((input, idx) <- tx.inputs.zipWithIndex) {
      val box = inputMap(Base16.encode(input.boxId))
      val ergoTree = box.ergoTree

      try {
        val ctx = new ErgoLikeContext(
          AvlTreeData.dummy, Colls.emptyColl, preHeader,
          dataInputBoxes.toIndexedSeq, resolvedInputs.toIndexedSeq,
          tx.asInstanceOf[ErgoLikeTransaction],
          idx, input.spendingProof.extension,
          ValidationRules.currentSettings,
          1000000L, 0L, ergoTree.version)

        val ctxV = ctx.withErgoTreeVersion(ergoTree.version).asInstanceOf[ErgoLikeContext]
        VersionContext.withVersions(ctxV.activatedScriptVersion, ergoTree.version) {
          val costAcc = new CostAccumulator(
            JitCost.fromBlockCost(0),
            Some(JitCost.fromBlockCost(1000000)))
          val settings = CErgoTreeEvaluator.DefaultEvalSettings
          val prop = ergoTree.toProposition(ergoTree.isConstantSegregation && ergoTree.hasDeserialize)
          val (reduced, _) = CErgoTreeEvaluator.eval(
            ctxV.toSigmaContext(), costAcc, ergoTree.constants, prop, settings)

          // Check if the proposition reduced to false
          reduced match {
            case sigma.data.CSigmaProp(sigma.data.TrivialProp.FalseProp) =>
              println(s"FAIL $txId SCRIPT false_proposition input=$idx")
              return
            case _ => // reduction succeeded; no proof-validity claim
          }

          // No verifier is invoked. Non-trivial propositions and arbitrary
          // proof bytes may reach REDUCED_UNVERIFIED; callers must separately
          // use the pinned protocol verifier for transaction validity.

        }
      } catch {
        case e: Exception =>
          val cat = e.getClass.getSimpleName match {
            case n if n.contains("Cost") => "COST"
            case n if n.contains("Limit") => "COST"
            case _ => "SCRIPT"
          }
          println(s"FAIL $txId $cat ${e.getClass.getSimpleName} input=$idx")
          return
      }
    }

    println(s"REDUCED_UNVERIFIED $txId")
  }
}

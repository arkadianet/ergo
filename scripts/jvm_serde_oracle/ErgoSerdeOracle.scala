// JVM reference serde oracle for the ergo-difftest differential fuzzer.
//
// Reads `<surface> <hex>` lines on stdin and, for each, runs the REAL Scala
// reference deserializer (the versions the consensus node runs) and prints:
//   ACCEPT <canonical-hex>   parsed; canonical re-serialization is <canonical-hex>
//   ACCEPT                   parsed, but canonical re-serialization unavailable
//   REJECT <ExceptionName>   reference refused these bytes
//   ERR    <message>         oracle could not handle the line
//
// The Rust harness (ergo-difftest) feeds the same bytes to its own decoder and
// diffs the verdicts. An ACCEPT/REJECT mismatch is a consensus divergence — the
// class the UTF-8 STypeVar and off-curve-GroupElement findings belong to.
//
// Dependencies are pinned to the node's versions (see `/info` appVersion = 6.0.2).
// `ergo-core` (transaction/header) is not on Maven Central — publish it locally:
//   cd <ergo reference>; sbt "avldb/publishLocal" "ergoWallet/publishLocal" "ergoCore/publishLocal"
// avldb pulls leveldbjni-all from the GitLab repo declared below.
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2

import scala.io.StdIn
import scorex.util.encode.Base16
import scorex.util.bytesToId
import sigma.{Colls, Header, PreHeader, VersionContext}
import sigma.crypto.CryptoConstants
import sigma.data.{AvlTreeData, SigmaBoolean, CSigmaProp}
import sigma.interpreter.ContextExtension
import sigma.ast.{ErgoTree, JitCost}
import sigma.serialization.{ConstantSerializer, ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer, TypeSerializer}
import sigma.ast.DeserializationSigmaBuilder
import sigma.util.Extensions.EcpOps
import org.ergoplatform.{ErgoBox, ErgoBoxCandidate, ErgoLikeContext, ErgoLikeTransaction}
import org.ergoplatform.validation.ValidationRules
import org.ergoplatform.modifiers.mempool.ErgoTransactionSerializer
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{CErgoTreeEvaluator, CostAccumulator}
import sigmastate.interpreter.CErgoTreeEvaluator.DefaultEvalSettings

object ErgoSerdeOracle {
  private val tree = ErgoTreeSerializer.DefaultSerializer
  private val constant = ConstantSerializer(DeserializationSigmaBuilder)

  private def hex(b: Array[Byte]): String = Base16.encode(b)

  // The DESERIALIZE step decides ACCEPT vs REJECT. Canonical re-serialization
  // is separate: if it throws on an otherwise-parsed value we still report
  // ACCEPT (no canonical), matching the Rust side which treats a write refusal
  // as accept-at-parse. Mixing the two would flag a false accept/reject diff.
  private def acc(canon: => String): String =
    try "ACCEPT " + canon
    catch { case _: Throwable => "ACCEPT" }

  // ── reduce surface: deserialize + reduce-to-crypto, diff (sigma prop, JIT cost) ──
  // Replicates the SANTA blesser EvalCore.dummyContext (the test-scoped
  // ErgoLikeContextTesting.dummy isn't in the published jar): the SELF box IS the
  // tree at value 1M, the sole input; no data/outputs; empty extension; activated=3.
  // The node's `reduce_expr_with_cost` over a matching ReductionContext is the twin.
  private val dummyPubkey: Array[Byte] =
    GroupElementSerializer.toBytes(CryptoConstants.dlogGroup.generator)

  private def dummyPreHeader(height: Int, activated: Byte): PreHeader = CPreHeader(
    version = (activated + 1).toByte,
    parentId = Colls.fromArray(Array.fill(32)(0: Byte)),
    timestamp = 3L,
    nBits = 0L,
    height = height,
    minerPk = GroupElementSerializer.parse(SigmaSerializer.startReader(dummyPubkey)).toGroupElement,
    votes = Colls.fromArray(Array.fill(3)(0: Byte))
  )

  private def dummyReduceContext(tree: ErgoTree, activatedVersion: Byte): ErgoLikeContext = {
    val selfBox = new ErgoBox(
      value = 1000000L, ergoTree = tree,
      transactionId = bytesToId(Array.fill(32)(0: Byte)), index = 0.toShort, creationHeight = 0)
    new ErgoLikeContext(
      lastBlockUtxoRoot = AvlTreeData.dummy,
      headers = Colls.emptyColl[Header],
      preHeader = dummyPreHeader(0, activatedVersion),
      dataBoxes = IndexedSeq.empty,
      boxesToSpend = IndexedSeq(selfBox),
      spendingTransaction = ErgoLikeTransaction(IndexedSeq(), IndexedSeq()),
      selfIndex = 0,
      extension = ContextExtension.empty,
      validationSettings = ValidationRules.currentSettings,
      costLimit = DefaultEvalSettings.scriptCostLimitInEvaluator,
      initCost = 0L,
      activatedScriptVersion = activatedVersion
    ).withErgoTreeVersion(tree.version)
  }

  // Canonical repr of the reduced root: a SigmaProp → its SigmaBoolean bytes (what
  // gets proven on-chain). A Bool root is coerced to TrivialProp(true/false), exactly
  // as the node's `reduce_expr_with_cost` coerces `Value::Bool` → `SigmaBoolean`, so
  // both sides emit the same `P:` form. A non-prop/non-bool reduced root is REJECTED
  // (a box script with such a root is rejected at deserialize by
  // CheckDeserializedScriptIsSigmaProp anyway) by throwing — propagated to `handle`
  // as a REJECT — so the oracle does not ACCEPT a value the node's `reduce_verdict`
  // rejects (its `reduce_expr_with_cost` errors on a non-SigmaProp/Bool root).
  private def reduceRepr(v: Any): String = v match {
    case sp: CSigmaProp => "P:" + Base16.encode(SigmaBoolean.serializer.toBytes(sp.sigmaTree))
    case b: Boolean     => "P:" + Base16.encode(SigmaBoolean.serializer.toBytes(
      if (b) sigma.data.TrivialProp.TrueProp else sigma.data.TrivialProp.FalseProp))
    case other          =>
      throw new IllegalArgumentException("reduced root is not SigmaProp/Bool: " + other.getClass.getSimpleName)
  }

  private def reduce(bytes: Array[Byte]): String = {
    val t = tree.deserializeErgoTree(bytes)
    VersionContext.withVersions(3.toByte, t.version) {
      val ctx = dummyReduceContext(t, 3.toByte)
      val accu = new CostAccumulator(
        JitCost.fromBlockCost(0),
        Some(JitCost.fromBlockCost(Math.toIntExact(ctx.costLimit))))
      val (v, _blockCost) = CErgoTreeEvaluator.eval(
        ctx.toSigmaContext(), accu, t.constants,
        t.toProposition(t.isConstantSegregation && t.hasDeserialize), DefaultEvalSettings)
      "ACCEPT " + reduceRepr(v) + "|" + accu.totalCost.value
    }
  }

  def handle(surface: String, hexStr: String): String =
    Base16.decode(hexStr) match {
      case scala.util.Failure(_) => "ERR not-hex"
      case scala.util.Success(bytes) =>
        try
          // Match the consensus node's runtime: activatedVersion = 3 (mainnet
          // 6.0.2, = MAX_SUPPORTED_TREE_VERSION). WITHOUT this the oracle runs at
          // the default activatedVersion = 1, whose `withVersions` require
          // short-circuits, so a tree whose header version exceeds the activated
          // version is NEVER rejected — a false ACCEPT vs the node, which rejects
          // it (#120). deserializeErgoTree overrides the tree-version arg from the
          // header; only the activated version (first arg) matters here.
          VersionContext.withVersions(3.toByte, 0.toByte) {
          surface match {
            case "ergo_tree" =>
              val t = tree.deserializeErgoTree(bytes)
              acc(t.bytesHex)
            case "sigma_type" =>
              val tpe = TypeSerializer.deserialize(SigmaSerializer.startReader(bytes))
              acc {
                val w = SigmaSerializer.startWriter()
                TypeSerializer.serialize(tpe, w)
                hex(w.toBytes)
              }
            case "constant" =>
              // type + data — the consensus-meaningful unit (a bare type strips
              // the value/version context the node's type codec defers to)
              val c = constant.deserialize(SigmaSerializer.startReader(bytes))
              acc(hex(constant.toBytes(c)))
            case "ergo_box_candidate" =>
              // standalone box (full token ids) — matches node read_ergo_box_candidate
              val box = ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(bytes))
              acc(hex(ErgoBoxCandidate.serializer.toBytes(box)))
            case "transaction" =>
              val tx = ErgoTransactionSerializer.parseBytes(bytes)
              acc(hex(ErgoTransactionSerializer.toBytes(tx)))
            case "header" =>
              val h = HeaderSerializer.parseBytes(bytes)
              acc(hex(HeaderSerializer.toBytes(h)))
            case "reduce" => reduce(bytes)
            case "mc_root" =>
              // MethodCall-root classifier for the typechecker-registry harness:
              // deserialize (checkType = true, like the box reader) and report
              // whether the root static type is SigmaProp.
              //   SIGMA      root parses (root.isRight) -> static type IS SigmaProp;
              //   WRAP       soft-fork-wrapped by rule 1001 (CheckDeserializedScript-
              //              IsSigmaProp) -> the MethodCall classified and its root is
              //              non-SigmaProp;
              //   WRAPOTHER  wrapped for ANOTHER reason (e.g. method-not-found / a
              //              malformed size-delimited probe) -> the tree NEVER reached
              //              the rule-1001 root classification, so it proves nothing;
              //   THROW      a throw (a sizeless non-sigma root, or a malformed tree).
              // The harness requires WRAP (not merely root.isLeft) so a stale/mis-
              // constructed probe cannot pass as a non-SigmaProp wrapper.
              try {
                val t = tree.deserializeErgoTree(bytes)
                t.root match {
                  case scala.util.Right(_) => "SIGMA"
                  case scala.util.Left(u) =>
                    if (u.error.rule.id == 1001) "WRAP"
                    else "WRAPOTHER rule=" + u.error.rule.id
                }
              } catch { case e: Throwable => "THROW " + e.getClass.getSimpleName }
            case other => "ERR unsupported-surface:" + other
          }
          }
        catch {
          case e: Throwable => "REJECT " + e.getClass.getSimpleName
        }
    }

  def main(args: Array[String]): Unit = {
    var line = StdIn.readLine()
    while (line != null) {
      val t = line.trim
      if (t.nonEmpty) {
        val parts = t.split("\\s+", 2)
        println(if (parts.length == 2) handle(parts(0), parts(1)) else "ERR bad-line")
      }
      line = StdIn.readLine()
    }
  }
}

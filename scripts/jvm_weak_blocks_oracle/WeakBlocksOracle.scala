//> using scala 2.12
package org.ergoplatform.mining

import io.circe.Json
import io.circe.syntax._
import org.ergoplatform.mining.InputBlockFields
import org.ergoplatform.mining.difficulty.DifficultySerializer
import org.ergoplatform.modifiers.history.extension.{Extension, ExtensionCandidate}
import org.ergoplatform.modifiers.history.header.{Header, HeaderSerializer}
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import org.ergoplatform.network.message.inputblocks._
import org.ergoplatform.subblocks.InputBlockAnnouncement
import org.ergoplatform.settings.Algos
import org.ergoplatform.validation.ValidationRules
import org.ergoplatform.{AutolykosSolution, ErgoBox, ErgoBoxCandidate, ErgoLikeContext, ErgoLikeTransaction, Input}
import scorex.crypto.hash.Digest32
import scorex.util.encode.Base16
import scorex.util.{bytesToId, idToBytes, ByteArrayBuilder}
import scorex.util.serialization.VLQByteBufferWriter
import sigma.crypto.CryptoConstants
import sigma.ast.{ErgoTree, JitCost, SBoolean, SSigmaProp, Value}
import sigma.compiler.{CompilerResult, SigmaCompiler}
import sigma.compiler.ir.CompiletimeIRContext
import sigma.data.AvlTreeData
import sigma.data.TrivialProp.TrueProp
import sigma.exceptions.SoftFieldAccessException
import sigma.interpreter.{ContextExtension, ProverResult}
import sigma.serialization.GroupElementSerializer
import sigma.serialization.SigmaSerializer
import sigma.util.Extensions.EcpOps
import sigma.{Colls, VersionContext}
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{CErgoTreeEvaluator, CostAccumulator}
import sigmastate.interpreter.CErgoTreeEvaluator.DefaultEvalSettings
import scala.util.control.NonFatal

/**
  * Oracle harness for the `weak-blocks` (input blocks) port. Prints one JSON
  * document (a `{"cases": [...], "reject_cases"?: [...]}` shape) per invocation,
  * selected by the single CLI argument (vector name). `gen.py` drives this and
  * stamps the manifest block onto the result before writing it to
  * `test-vectors/weak-blocks/<name>.json`.
  */
object WeakBlocksOracle {
  def hex(b: Array[Byte]): String = Base16.encode(b)
  def fill(n: Int, v: Int): Array[Byte] = Array.fill(n)(v.toByte)

  val fixedHeader: Header = Header(2, bytesToId(fill(32, 0x11)), Digest32 @@ fill(32, 0x22),
    scorex.crypto.authds.ADDigest @@ fill(33, 0x33), Digest32 @@ fill(32, 0x44), 1700000000000L,
    DifficultySerializer.encodeCompactBits(BigInt(1000)), 12345, Digest32 @@ fill(32, 0x55),
    new AutolykosSolution(CryptoConstants.dlogGroup.generator, CryptoConstants.dlogGroup.generator,
      Array[Byte](1, 2, 3, 4, 5, 6, 7, 8), BigInt(0)), Array[Byte](0, 0, 0), Array.emptyByteArray)

  def tx(boxFill: Int, proof: Array[Byte]): ErgoTransaction = ErgoTransaction(
    IndexedSeq(Input(scorex.crypto.authds.ADKey @@ fill(32, boxFill), ProverResult(proof, ContextExtension.empty))),
    IndexedSeq(new ErgoBoxCandidate(1000000L, ErgoTree.fromProposition(TrueProp), 1)))
  val tx1: ErgoTransaction = tx(0x66, Array[Byte](9, 9, 9))
  val tx2: ErgoTransaction = tx(0x77, Array.emptyByteArray)

  def parseVerdict[T](p: Array[Byte] => T, bytes: Array[Byte]): (String, String) =
    try { p(bytes); ("Accept", "") } catch { case NonFatal(t) => ("Reject", t.getClass.getSimpleName) }

  def fields(prev: Option[Array[Byte]], txs: Seq[ErgoTransaction], prevDigest: Digest32): InputBlockFields = {
    val digest = org.ergoplatform.settings.Algos.merkleTreeRoot(txs.map(t => scorex.crypto.authds.LeafData @@ t.serializedId))
    val ext = InputBlockFields.toExtensionFields(prev, digest, prevDigest)
    new InputBlockFields(prev, digest, prevDigest, ext.proofForInputBlockData.get)
  }

  def announcementCases(): Json = {
    val zero = Digest32 @@ fill(32, 0)
    val variants = Seq(
      ("no_prev_no_weak_ids", InputBlockAnnouncement(InputBlockAnnouncement.initialMessageVersion, fixedHeader, fields(None, Seq(tx1), zero), None)),
      ("prev_and_weak_ids", InputBlockAnnouncement(InputBlockAnnouncement.initialMessageVersion, fixedHeader, fields(Some(fill(32, 0x88)), Seq(tx1, tx2), zero), Some(Seq(tx1.weakId, tx2.weakId)))),
      ("empty_weak_ids", InputBlockAnnouncement(InputBlockAnnouncement.initialMessageVersion, fixedHeader, fields(None, Seq(tx1), zero), Some(Seq.empty))),
      ("version2_unparsed", InputBlockAnnouncement(2.toByte, fixedHeader, fields(None, Seq(tx1), zero), None, Array[Byte](0xAA.toByte, 0xBB.toByte))))
    val ser = InputBlockAnnouncement.serializer
    val cases = variants.map { case (name, ann) =>
      val bytes = ser.toBytes(ann)
      val ext = InputBlockFields.toExtensionFields(ann.inputBlockFields.prevInputBlockId, ann.transactionsDigest, ann.inputBlockFields.prevTransactionsDigest)
      Json.obj("name" -> name.asJson, "bytes_hex" -> hex(bytes).asJson, "id" -> ann.id.toString.asJson,
        "header_hex" -> hex(HeaderSerializer.toBytes(ann.header)).asJson,
        "prev_input_block_id" -> ann.inputBlockFields.prevInputBlockId.map(hex).asJson,
        "transactions_digest" -> hex(ann.transactionsDigest).asJson,
        "prev_transactions_digest" -> hex(ann.inputBlockFields.prevTransactionsDigest).asJson,
        "weak_tx_ids" -> ann.weakTxIds.map(_.map(hex)).asJson,
        "extension_fields_for_proof" -> ext.fields.map(kv => Json.obj("key" -> hex(kv._1).asJson, "value" -> hex(kv._2).asJson)).asJson,
        "extension_root_of_those_fields" -> hex(ext.digest).asJson,
        "proof_valid_against_that_root" -> ann.merkleProof.valid(ext.digest).asJson)
    }
    val truncated = ser.toBytes(variants.head._2).dropRight(1)
    val rejects = Seq(("truncated_last_byte", truncated), ("empty", Array.emptyByteArray)).map { case (name, b) =>
      val (v, d) = parseVerdict(bs => ser.parseBytes(bs), b)
      Json.obj("name" -> name.asJson, "bytes_hex" -> hex(b).asJson, "jvm" -> v.asJson, "jvm_detail" -> d.asJson)
    }
    Json.obj("cases" -> cases.asJson, "reject_cases" -> rejects.asJson)
  }

  def orderingCases(): Json = {
    val extFields = Seq((Extension.PrevInputBlockIdKey, fill(32, 0x88)), (Array[Byte](0, 1), Array[Byte](0, 0, 0, 100)))
    val variants = Seq(
      ("minimal", OrderingBlockAnnouncement(OrderingBlockAnnouncement.CurrentVersion, fixedHeader, Seq.empty, Seq.empty, Seq.empty)),
      ("full", OrderingBlockAnnouncement(OrderingBlockAnnouncement.CurrentVersion, fixedHeader, Seq(tx1), Seq(tx2.id), extFields, Array[Byte](1, 2))))
    val spec = OrderingBlockAnnouncementMessageSpec
    val cases = variants.map { case (name, ann) =>
      val bytes = spec.toBytes(ann)
      Json.obj("name" -> name.asJson, "bytes_hex" -> hex(bytes).asJson, "header_id" -> ann.header.id.toString.asJson,
        "non_broadcasted_tx_hex" -> ann.nonBroadcastedTransactions.map(t => hex(ErgoTransactionSerializer.toBytes(t))).asJson,
        "broadcasted_ids" -> ann.broadcastedTransactionIds.map(_.toString).asJson,
        "extension_fields" -> ann.extensionFields.map(kv => Json.obj("key" -> hex(kv._1).asJson, "value" -> hex(kv._2).asJson)).asJson,
        "unparsed_hex" -> hex(ann.unparsedBytes).asJson,
        "extension_digest_equals_header_root" -> ExtensionCandidate(ann.extensionFields).digest.sameElements(ann.header.extensionRoot).asJson)
    }
    // bound violation: rewrite the nonBroadcasted-transactions count field to 32769 (> MaxArraySize)
    val base = spec.toBytes(variants.head._2)
    val headerLen = HeaderSerializer.toBytes(fixedHeader).length
    val w = new VLQByteBufferWriter(new ByteArrayBuilder()); w.putUInt(32769L)
    val bad = base.take(1 + headerLen) ++ w.result().toBytes ++ base.drop(1 + headerLen + 1)
    val (v, d) = parseVerdict(bs => spec.parseBytes(bs), bad)
    Json.obj("cases" -> cases.asJson, "reject_cases" -> Seq(Json.obj("name" -> "nbt_count_over_cap".asJson, "bytes_hex" -> hex(bad).asJson, "jvm" -> v.asJson, "jvm_detail" -> d.asJson)).asJson)
  }

  def messageCases(): Json = {
    val ibId = bytesToId(fill(32, 0x99))
    val ids = InputBlockTransactionIdsData(ibId, Seq(tx1.weakId, tx2.weakId))
    val txs = InputBlockTransactionsData(ibId, Seq(tx1, tx2))
    val req = InputBlockTransactionsRequest(ibId, Seq(tx2.weakId))
    def c(name: String, code: Int, bytes: Array[Byte], extra: (String, Json)*) =
      Json.obj((Seq("name" -> name.asJson, "code" -> code.asJson, "bytes_hex" -> hex(bytes).asJson) ++ extra): _*)
    val cases = Seq(
      c("tx_ids", 102, InputBlockTransactionIdsMessageSpec.toBytes(ids), "input_block_id" -> ibId.toString.asJson, "weak_ids" -> Seq(tx1.weakId, tx2.weakId).map(hex).asJson),
      c("txs", 104, InputBlockTransactionsMessageSpec.toBytes(txs), "input_block_id" -> ibId.toString.asJson, "tx_hex" -> Seq(tx1, tx2).map(t => hex(ErgoTransactionSerializer.toBytes(t))).asJson),
      c("txs_request", 105, InputBlockTransactionsRequestMessageSpec.toBytes(req), "input_block_id" -> ibId.toString.asJson, "weak_ids" -> Seq(hex(tx2.weakId)).asJson))
    // count larger than remaining bytes allow
    val w = new VLQByteBufferWriter(new ByteArrayBuilder()); w.putBytes(idToBytes(ibId)); w.putUInt(1000L); w.putBytes(tx1.weakId)
    val overIds = w.result().toBytes
    val (v1, d1) = parseVerdict(bs => InputBlockTransactionIdsMessageSpec.parseBytes(bs), overIds)
    val (v2, d2) = parseVerdict(bs => InputBlockTransactionsRequestMessageSpec.parseBytes(bs), overIds)
    val (v3, d3) = parseVerdict(bs => InputBlockTransactionsMessageSpec.parseBytes(bs), overIds)
    val rejects = Seq(("102_count_exceeds_remaining", 102, v1, d1), ("105_count_exceeds_remaining", 105, v2, d2), ("104_count_exceeds_remaining", 104, v3, d3)).map { case (n, code, v, d) =>
      Json.obj("name" -> n.asJson, "code" -> code.asJson, "bytes_hex" -> hex(overIds).asJson, "jvm" -> v.asJson, "jvm_detail" -> d.asJson) }
    Json.obj("cases" -> cases.asJson, "reject_cases" -> rejects.asJson)
  }

  def weakIdCases(): Json = {
    val txs = Seq("tx1" -> tx1, "tx2_empty_proof" -> tx2, "tx1_other_witness" -> tx(0x66, Array[Byte](8, 8)))
    Json.obj("cases" -> txs.map { case (name, t) =>
      Json.obj("name" -> name.asJson, "tx_hex" -> hex(ErgoTransactionSerializer.toBytes(t)).asJson,
        "tx_id" -> t.id.toString.asJson, "witness_id" -> hex(t.witnessSerializedId).asJson, "weak_id" -> hex(t.weakId).asJson) }.asJson)
  }

  def powCases(): Json = {
    import org.ergoplatform.mining.AutolykosPowScheme
    val scheme = new AutolykosPowScheme(32, 26)
    val nBitsList = Seq(BigInt(1000), BigInt(1L << 20), BigInt("123456789012")).map(d => DifficultySerializer.encodeCompactBits(d))
    val mults = Seq(2, 30, 64, 2048)
    val pure = for (nBits <- nBitsList; n <- mults) yield {
      val b = scheme.getB(nBits); val t = b * n
      val hits = Seq(("target_minus_1", b - 1), ("target", b), ("input_target_minus_1", t - 1), ("input_target", t), ("input_target_plus_1", t + 1))
      hits.map { case (label, hit) =>
        Json.obj("name" -> s"nbits${nBits}_n${n}_$label".asJson, "n_bits" -> nBits.asJson, "multiplier" -> n.asJson,
          "hit" -> hit.toString.asJson, "input_target" -> t.toString.asJson,
          "verifier_accepts" -> (hit < t).asJson,           // checkInputBlockPoW comparison
          "miner_classifies_input" -> (hit <= t && hit > b).asJson, // checkNonces: d <= b*n and not ordering
          "miner_classifies_ordering" -> (hit <= b).asJson)
      }
    }
    // real solutions: search nonces at tiny difficulty on fixedHeader for an input and an ordering solution
    val h = fixedHeader.copy(nBits = DifficultySerializer.encodeCompactBits(BigInt(2)), version = 2)
    val msg = scheme.msgByHeader(h); val b = scheme.getB(h.nBits); val hbs = com.google.common.primitives.Ints.toByteArray(h.height); val N = scheme.calcN(h)
    val params = org.ergoplatform.settings.Parameters(0, org.ergoplatform.settings.Parameters.DefaultParameters, org.ergoplatform.settings.ErgoValidationSettingsUpdate.empty).withNumOfSubblocksPerBlock(30)
    val sk = BigInt(12345); val x = BigInt(67890)
    val found = (0L until 2000000L by 1000L).flatMap { start =>
      scheme.checkNonces(2, hbs, msg, sk, x, b, N, start, start + 1000, params) match {
        case org.ergoplatform.InputSolutionFound(as) => Some(("input", h.copy(powSolution = as)))
        case org.ergoplatform.OrderingSolutionFound(as) => Some(("ordering", h.copy(powSolution = as)))
        case _ => None
      }
    }
    // The nonce scan can come up with only one of the two solution classes.
    // Emitting the partial vector would write JSON the Rust parity test
    // rejects much later; fail here, where the cause is visible.
    val byKind = found.groupBy(_._1).map { case (k, v) => k -> v.head._2 }
    val missing = Seq("input", "ordering").filterNot(byKind.contains)
    if (missing.nonEmpty)
      sys.error(s"pow scan found no ${missing.mkString(" or ")} solution (found: ${byKind.keys.mkString(", ")})")
    val real = Seq("input", "ordering").map { kind =>
      val hdr = byKind(kind)
      Json.obj("name" -> s"real_${kind}_solution".asJson, "header_hex" -> hex(HeaderSerializer.toBytes(hdr)).asJson,
        "hit" -> scheme.hitForVersion2(hdr).toString.asJson, "multiplier" -> 30.asJson,
        "input_pow_valid" -> scheme.checkInputBlockPoW(hdr, params).asJson,
        "ordering_pow_valid" -> scheme.checkOrderingBlockPoW(hdr).asJson)
    }
    Json.obj("pure_cases" -> pure.flatten.asJson, "header_cases" -> real.asJson)
  }

  def extensionLeafCases(): Json = {
    import scorex.crypto.authds.LeafData
    import scorex.crypto.authds.merkle.Leaf
    val cases = Seq(
      ("two_byte_key_32_byte_value", Array[Byte](0x03, 0x00), fill(32, 0)),
      ("prev_input_block_id_key", Extension.PrevInputBlockIdKey, fill(32, 0x88)),
      ("interlinks_style_key", Array[Byte](0x01, 0x00), Array[Byte](1, 2, 3)))
    Json.obj("cases" -> cases.map { case (name, key, value) =>
      val leafDigest = Leaf[Digest32](LeafData @@ Extension.kvToLeaf((key, value)))(Algos.hash).hash
      Json.obj("name" -> name.asJson, "key_hex" -> hex(key).asJson, "value_hex" -> hex(value).asJson,
        "leaf_digest_hex" -> hex(leafDigest).asJson)
    }.asJson)
  }

  // ── extension_proof: extension-proof/field-binding vectors for F4/F4b ──
  // Documents that Scala's `InputBlockFields.inputBlockFieldsProof.valid(header.extensionRoot)`
  // only checks that the proof *reduces* to the header's extension root — a
  // proof whose leaves don't match the announced fields is still accepted
  // as long as it reduces to that root (F4b; `fields_unbound` below).
  // A prior hypothesis (F4) held that Scala's `valid` also accepts an
  // *empty* proof against any root; measuring it here shows that is NOT
  // the case (scrypto 3.0.0's `BatchMerkleProof.valid` reduces an empty
  // proof to an empty sequence, which never satisfies its `size == 1`
  // check, so `empty_proof` below is Scala-`false`). The real F4-shaped
  // divergence is in the Rust `ergo-validation::popow::merkle::verify_batch_merkle_proof`
  // (from M0), which *does* special-case empty-indices/empty-proofs as
  // trivially valid against any root — the opposite direction from the
  // original hypothesis; see `ergo-inputblocks/tests/it/announcement_oracle.rs`.
  // `ergo-inputblocks::announcement::verify_field_binding` closes F4b (and
  // is why an empty proof is rejected regardless of what the Rust reducer
  // says) under `AnnouncementPolicy::default()` (`strict_field_binding = true`).
  def extensionProofCases(): Json = {
    val zero = Digest32 @@ fill(32, 0)
    def ann(prev: Option[Array[Byte]], txs: Seq[ErgoTransaction], proofOverride: Option[scorex.crypto.authds.merkle.BatchMerkleProof[Digest32]] = None, hdr: Header = fixedHeader): InputBlockAnnouncement = {
      val f = fields(prev, txs, zero)
      val ext = InputBlockFields.toExtensionFields(prev, f.transactionsDigest, f.prevTransactionsDigest)
      val h = hdr.copy(extensionRoot = ext.digest) // header commits to exactly these fields
      InputBlockAnnouncement(1, h, new InputBlockFields(prev, f.transactionsDigest, f.prevTransactionsDigest, proofOverride.getOrElse(f.inputBlockFieldsProof)), None)
    }
    val good = ann(Some(fill(32, 0x88)), Seq(tx1, tx2))
    val goodNoPrev = ann(None, Seq(tx1))
    val empty = ann(Some(fill(32, 0x88)), Seq(tx1), Some(scorex.crypto.authds.merkle.BatchMerkleProof(Seq.empty, Seq.empty)(Algos.hash)))
    // proof built over a different digest but announced fields unchanged -> reduces to a different root
    val wrongRoot = { val a = ann(Some(fill(32, 0x88)), Seq(tx1)); a.copy(header = a.header.copy(extensionRoot = Digest32 @@ fill(32, 0x01))) }
    // proof for the fields of txs (tx1) but announced digest for (tx1, tx2): Scala accepts (F4), binding rejects
    val unbound = { val real = ann(Some(fill(32, 0x88)), Seq(tx1)); val other = fields(Some(fill(32, 0x88)), Seq(tx1, tx2), zero)
      real.copy(inputBlockFields = new InputBlockFields(Some(fill(32, 0x88)), other.transactionsDigest, other.prevTransactionsDigest, real.merkleProof)) }
    // expected_binding_verdict: the *field-binding* check alone (proof
    // leaves vs the announced InputBlockFields), independent of the
    // header's extension root — that root/reduction check is
    // `scala_ext_valid` above, checked separately. A binding-consistent
    // proof/fields pair (e.g. `wrong_root`, which corrupts only the
    // header) is still expected `true` here even though the header's
    // root check fails; only `empty_proof` (no leaves) and
    // `fields_unbound` (leaves for different fields than announced) are
    // expected `false`.
    def expectedBindingVerdict(a: InputBlockAnnouncement): Boolean = {
      import scorex.crypto.authds.LeafData
      import scorex.crypto.authds.merkle.Leaf
      val want = InputBlockFields.toExtensionFields(a.inputBlockFields.prevInputBlockId, a.inputBlockFields.transactionsDigest, a.inputBlockFields.prevTransactionsDigest)
        .fields.map { case (k, v) => hex(Leaf[Digest32](LeafData @@ Extension.kvToLeaf((k, v)))(Algos.hash).hash) }.sorted
      val proved = a.merkleProof.indices.map(kv => hex(kv._2)).sorted
      proved.nonEmpty && proved == want
    }
    val cases = Seq(("good_with_prev", good), ("good_no_prev", goodNoPrev), ("empty_proof", empty), ("wrong_root", wrongRoot), ("fields_unbound", unbound)).map { case (name, a) =>
      Json.obj("name" -> name.asJson, "bytes_hex" -> hex(InputBlockAnnouncement.serializer.toBytes(a)).asJson,
        "scala_ext_valid" -> a.merkleProof.valid(a.header.extensionRoot).asJson,
        "expected_binding_verdict" -> expectedBindingVerdict(a).asJson)
    }
    Json.obj("cases" -> cases.asJson)
  }

  // ── soft_fields: Scala `softFieldsAllowed` parity for the Rust evaluator gate ──
  // Task 6 (ergo-sigma) added ReductionContext.soft_fields_allowed + the typed
  // EvalError::SoftFieldAccess. This function is the oracle evidence Task 7
  // asserts at ergo-validation's boundary: for each script below, compiled at
  // ErgoTree version 3 under `VersionContext.withVersions(3, 3)` (v6 activated),
  // record the reduction outcome under both `softFieldsAllowed` settings.
  // Scala semantics (sigmastate/eval/CContext.scala:53, sigma/ast/values.scala:1382):
  // preHeader.timestamp/minerPk/votes and CONTEXT.minerPubKey/MinerPubkey throw
  // SoftFieldAccessException when disallowed; height/HEIGHT/headers do not.
  //
  // Fix round 1 (findings-7-r1.md): `preheader_minerpk`'s self-comparison
  // (`CONTEXT.preHeader.minerPk == CONTEXT.preHeader.minerPk`) is accepted by
  // Scala under BOTH policies — it apparently never actually reaches the
  // soft-field gate inside `SPreHeader.minerPk`'s `MethodCall.eval` (kept as
  // generated; reported as a finding, not edited). `preheader_minerpk_read`
  // is a real field read (`.getEncoded.size`) added alongside it so the
  // vector set still has class-II (`minerPk`) coverage that actually
  // exercises the gate.
  private val softFieldScripts: Seq[(String, String)] = Seq(
    "minerpk_size" -> "CONTEXT.minerPubKey.size >= 0",
    "preheader_minerpk" -> "CONTEXT.preHeader.minerPk == CONTEXT.preHeader.minerPk",
    "preheader_minerpk_read" -> "CONTEXT.preHeader.minerPk.getEncoded.size == 33",
    "preheader_timestamp" -> "CONTEXT.preHeader.timestamp >= 0L",
    "preheader_votes" -> "CONTEXT.preHeader.votes.size == 3",
    "preheader_height" -> "CONTEXT.preHeader.height >= 0",
    "height_only" -> "HEIGHT >= 0",
    "headers_id" -> "CONTEXT.headers.size >= 0")

  // Compiles `source` with ErgoScript v6 (scriptVersion 3) activated, generating
  // a treeVersion-3 ErgoTree — the same compilation surface as ergo's own
  // `ErgoCompilerHelpers.compileSourceV6` (test-scope in the ergo source tree;
  // reimplemented here directly against the runtime-classpath `SigmaCompiler`
  // so this harness needs only `.work/classpath`, not the test classpath).
  private def compileSourceV5(source: String, treeVersion: Byte): ErgoTree =
    compileSourceAt(2.toByte, source, treeVersion)

  private def compileSourceV6(source: String, treeVersion: Byte): ErgoTree =
    compileSourceAt(3.toByte, source, treeVersion)

  private def compileSourceAt(scriptVersion: Byte, source: String, treeVersion: Byte): ErgoTree =
    VersionContext.withVersions(scriptVersion, treeVersion) {
      val compiler = new SigmaCompiler(16.toByte)
      val header = ErgoTree.defaultHeaderWithVersion(treeVersion)
      compiler.compile(Map.empty, source)(new CompiletimeIRContext) match {
        case CompilerResult(_, _, _, script: Value[SSigmaProp.type @unchecked]) if script.tpe == SSigmaProp =>
          ErgoTree.fromProposition(header, script)
        case CompilerResult(_, _, _, script: Value[SBoolean.type @unchecked]) if script.tpe == SBoolean =>
          ErgoTree.fromProposition(header, script.toSigmaProp)
        case other =>
          sys.error(s"soft_fields compile: expected SBoolean/SSigmaProp, got ${other.buildTree.tpe}")
      }
    }

  private val softFieldsPubkey: Array[Byte] =
    GroupElementSerializer.toBytes(CryptoConstants.dlogGroup.generator)

  private def softFieldsPreHeader(activated: Byte): sigma.PreHeader = CPreHeader(
    version = (activated + 1).toByte,
    parentId = Colls.fromArray(fill(32, 0)),
    timestamp = 3L,
    nBits = 0L,
    height = 0,
    minerPk = GroupElementSerializer.parse(SigmaSerializer.startReader(softFieldsPubkey)).toGroupElement,
    votes = Colls.fromArray(fill(3, 0)))

  private def softFieldsContext(selfBox: ErgoBox, activatedVersion: Byte, softFieldsAllowed: Boolean): ErgoLikeContext =
    new ErgoLikeContext(
      lastBlockUtxoRoot = AvlTreeData.dummy,
      headers = Colls.emptyColl[sigma.Header],
      preHeader = softFieldsPreHeader(activatedVersion),
      dataBoxes = IndexedSeq.empty,
      boxesToSpend = IndexedSeq(selfBox),
      spendingTransaction = ErgoLikeTransaction(IndexedSeq(), IndexedSeq()),
      selfIndex = 0,
      extension = ContextExtension.empty,
      validationSettings = ValidationRules.currentSettings,
      costLimit = DefaultEvalSettings.scriptCostLimitInEvaluator,
      initCost = 0L,
      activatedScriptVersion = activatedVersion,
      softFieldsAllowed = softFieldsAllowed
    ).withErgoTreeVersion(selfBox.ergoTree.version)

  def softFieldCases(): Json = {
    val cases = for {
      (name, source) <- softFieldScripts
      softFieldsAllowed <- Seq(true, false)
    } yield {
      val t = compileSourceV6(source, 3.toByte)
      val treeHex = hex(t.bytes)
      val selfBox = new ErgoBox(value = 1000000L, ergoTree = t,
        transactionId = bytesToId(fill(32, 0)), index = 0.toShort, creationHeight = 0)
      val ctx = softFieldsContext(selfBox, 3.toByte, softFieldsAllowed)
      val (outcome, errorClass, cost) =
        try {
          VersionContext.withVersions(3.toByte, 3.toByte) {
            val accu = new CostAccumulator(
              JitCost.fromBlockCost(0),
              Some(JitCost.fromBlockCost(Math.toIntExact(ctx.costLimit))))
            CErgoTreeEvaluator.eval(
              ctx.toSigmaContext, accu, t.constants,
              t.toProposition(t.isConstantSegregation && t.hasDeserialize), DefaultEvalSettings)
            ("Ok", "", Some(accu.totalCost.value))
          }
        } catch {
          // The IR-graph evaluator (CompiletimeIRContext-staged code path)
          // wraps the thrown SoftFieldAccessException in a reflective
          // InvocationTargetException; unwrap to the root cause before
          // classifying, mirroring sigma-state's own test helper
          // (`NegativeTesting.rootCause`).
          case e: Throwable =>
            var cause = e
            while (cause.getCause != null) cause = cause.getCause
            cause match {
              case sfa: SoftFieldAccessException => ("SoftFieldAccess", sfa.getClass.getSimpleName, None)
              case NonFatal(other) => ("Error", other.getClass.getSimpleName, None)
              case fatal => throw fatal
            }
        }
      Json.obj("name" -> name.asJson, "tree_hex" -> treeHex.asJson,
        "soft_fields_allowed" -> softFieldsAllowed.asJson, "outcome" -> outcome.asJson,
        "error_class" -> errorClass.asJson, "cost" -> cost.asJson)
    }
    Json.obj("cases" -> cases.asJson)
  }


  // ── input_block_validation: Scala `UtxoState.applyInputBlock` outcomes ──
  // Builds a real UTXO state (three fixture boxes from
  // `InputBlockProcessorSpecification` plus spendable filler boxes), advances it
  // by real full blocks so `stateContext.lastHeaders` is non-empty (spec 6.4
  // needs a real pre-header), and records the verdict + cost of
  // `us.applyInputBlock(txs, previousTxs, header)` for each scenario.
  //
  // Runs against `.work/test-classpath` (ergo's Test scope) with the working
  // directory set to `.work/source`, because `ErgoNodeTestConstants.initSettings`
  // reads the relative path `src/test/resources/application.conf`.
  def inputBlockValidationCases(): Json = {
    import org.ergoplatform.DataInput
    import org.ergoplatform.modifiers.ErgoFullBlock
    import org.ergoplatform.nodeView.state.{BoxHolder, ErgoStateContext, UtxoState}
    import org.ergoplatform.settings.Parameters
    import org.ergoplatform.utils.ErgoCoreTestConstants.parameters
    import org.ergoplatform.utils.ErgoNodeTestConstants.settings
    import org.ergoplatform.utils.generators.ValidBlocksGenerators
    import org.ergoplatform.wallet.boxes.ErgoBoxSerializer
    import scorex.crypto.authds.ADKey
    import scala.collection.JavaConverters._

    val trueTree = ErgoTree.fromProposition(TrueProp)
    val emptyProof = ProverResult(Array.emptyByteArray, ContextExtension.empty)

    def box(v: Long, tree: ErgoTree, tag: String, idx: Short): ErgoBox = new ErgoBox(
      value = v, ergoTree = tree, additionalTokens = Colls.emptyColl,
      additionalRegisters = Map.empty, transactionId = bytesToId(Algos.hash(tag)),
      index = idx, creationHeight = 0)

    // The three fixture boxes of InputBlockProcessorSpecification, verbatim.
    val eb1 = box(1000000000L, trueTree, "dummyTx", 0)
    val eb2 = box(1000000000L, compileSourceV5("CONTEXT.minerPubKey.size >= 0", 0), "dummyTx2", 1)
    val eb3 = box(1000000000L, trueTree, "dummyTx3", 2)
    // Filler boxes: spent by the full blocks that advance the state, so eb1..eb3
    // stay unspent and available to the input-block scenarios.
    val fillers = (0 until 3).map(i => box(1000000000L, trueTree, s"filler$i", i.toShort))

    val bh = BoxHolder(Seq(eb1, eb2, eb3) ++ fillers)
    var us: UtxoState = ValidBlocksGenerators.createUtxoState(bh, parameters)

    def spend(in: ErgoBox, outValue: Long, dataInputs: IndexedSeq[DataInput] = IndexedSeq.empty): ErgoTransaction =
      ErgoTransaction(
        IndexedSeq(Input(in.id, emptyProof)),
        dataInputs,
        IndexedSeq(new ErgoBoxCandidate(outValue, trueTree, 0)))

    // Advance the state by three real full blocks (each spends one filler box).
    var parentOpt: Option[ErgoFullBlock] = None
    var blockTxs: Seq[ErgoTransaction] = Seq.empty
    var utxo: Seq[ErgoBox] = bh.boxes.values.toSeq
    fillers.foreach { f =>
      val tx = spend(f, f.value)
      val fb = ValidBlocksGenerators.validFullBlock(parentOpt, us, Seq(tx))
      us = us.applyModifier(fb, None)(_ => ()).get
      parentOpt = Some(fb)
      blockTxs = blockTxs ++ Seq(tx)
      utxo = utxo.filterNot(b => tx.inputs.exists(i => java.util.Arrays.equals(i.boxId, b.id))) ++ tx.outputs
    }
    val tipHeader = parentOpt.get.header
    utxo.foreach(b => require(us.boxById(b.id).isDefined, s"tracked box ${hex(b.id)} not in state"))

    // Scenario transactions.
    val txA = spend(eb1, eb1.value)                        // spends eb1
    val txB = spend(txA.outputs.head, txA.outputs.head.value) // spends txA's output
    val txC = spend(eb2, eb2.value)                        // class II: reads CONTEXT.minerPubKey
    val txD = ErgoTransaction(                             // spends eb3, data-input = txA's output
      IndexedSeq(Input(eb3.id, emptyProof)),
      IndexedSeq(DataInput(txA.outputs.head.id)),
      IndexedSeq(new ErgoBoxCandidate(eb3.value, trueTree, 0)))
    val txADup = spend(eb1, eb1.value - 1)                 // different tx, same input as txA
    val missingBoxId: ADKey = ADKey @@ (Algos.hash("no such box"): Array[Byte])
    val txMissing = ErgoTransaction(
      IndexedSeq(Input(missingBoxId, emptyProof)),
      IndexedSeq(new ErgoBoxCandidate(1000000L, trueTree, 0)))

    // `cost_limit_rejected` needs maxBlockCost lowered on the state context. The
    // fixture API has no public way to swap parameters on a live UtxoState
    // (`persistentProver` is protected, `stateContext` is read from the store),
    // so we build a sibling UtxoState over the *same* prover/store with an
    // overridden `stateContext`. Reflection is only used to read the protected
    // `persistentProver` accessor; nothing is mutated.
    def withBlockCost(base: UtxoState, cost: Int): UtxoState = {
      val m = classOf[UtxoState].getMethod("persistentProver")
      m.setAccessible(true)
      val pp = m.invoke(base).asInstanceOf[scorex.crypto.authds.avltree.batch.PersistentBatchAVLProver[Digest32, org.ergoplatform.settings.Algos.HF]]
      new UtxoState(pp, base.version, base.store, settings) {
        override def stateContext: ErgoStateContext = {
          val sc = base.stateContext
          new ErgoStateContext(sc.lastHeaders, sc.lastExtensionOpt, sc.genesisStateDigest,
            sc.currentParameters.withBlockCost(cost), sc.validationSettings, sc.votingData)(sc.chainSettings)
        }
      }
    }

    val scenarios: Seq[(String, Seq[ErgoTransaction], Seq[ErgoTransaction], UtxoState)] = Seq(
      ("normal_tx_ok", Seq(txA), Seq.empty, us),
      ("class2_tx_rejected", Seq(txC), Seq.empty, us),
      ("chained_in_block_ok", Seq(txA, txB), Seq.empty, us),
      ("out_of_order_rejected", Seq(txB, txA), Seq.empty, us),
      ("data_input_forward_ok", Seq(txD, txA), Seq.empty, us),
      ("double_spend_current_rejected", Seq(txA, txADup), Seq.empty, us),
      ("double_spend_previous_rejected", Seq(txA), Seq(txA), us),
      ("spend_previous_output_ok", Seq(txB), Seq(txA), us),
      ("missing_utxo_rejected", Seq(txMissing), Seq.empty, us),
      ("cost_limit_rejected", Seq(txA), Seq.empty, withBlockCost(us, 1000)))

    // Scala wraps a SoftFieldAccessException thrown inside script evaluation into
    // a generic `MalformedModifierError("Scripts ... should pass verification")`,
    // so `error_class` alone cannot tell a soft-field rejection from any other
    // script failure. This discriminator is Scala-derived rather than asserted by
    // hand: a transaction whose first input validates under `softFieldsAllowed =
    // true` and fails under `false` was rejected *because of* a soft field.
    def softFieldSensitive(state: UtxoState, tx: ErgoTransaction): Boolean = {
      val sc = state.stateContext
      def run(allowed: Boolean) =
        try state.validateWithCost(tx, sc, sc.currentParameters.maxBlockCost, None, allowed)
        catch { case NonFatal(t) => scala.util.Failure(t) }
      run(true).isSuccess && run(false).isFailure
    }

    val cases = scenarios.map { case (name, txs, prev, state) =>
      val sc = state.stateContext
      val (outcome, errClass, errMsg, cost) =
        try {
          state.applyInputBlock(txs, prev, tipHeader) match {
            case scala.util.Success(c) => ("Ok", "", "", Some(c))
            case scala.util.Failure(t) => ("Failure", t.getClass.getSimpleName, String.valueOf(t.getMessage), None)
          }
        } catch {
          case NonFatal(t) => ("Failure", t.getClass.getSimpleName, String.valueOf(t.getMessage), None)
        }
      Json.obj(
        "name" -> name.asJson,
        "state_root_before" -> hex(state.rootDigest).asJson,
        "block_txs_hex" -> blockTxs.map(t => hex(ErgoTransactionSerializer.toBytes(t))).asJson,
        "last_headers_hex" -> sc.lastHeaders.map(h => hex(HeaderSerializer.toBytes(h))).asJson,
        "current_parameters" -> sc.currentParameters.parametersTable.map { case (k, v) => k.toInt.toString -> v }.asJson,
        "utxo_boxes_hex" -> utxo.map(b => hex(ErgoBoxSerializer.toBytes(b))).asJson,
        "previous_tx_hex" -> prev.map(t => hex(ErgoTransactionSerializer.toBytes(t))).asJson,
        "tx_hex" -> txs.map(t => hex(ErgoTransactionSerializer.toBytes(t))).asJson,
        "outcome" -> outcome.asJson,
        "error_class" -> errClass.asJson,
        "error_message" -> errMsg.asJson,
        "soft_field_sensitive" -> txs.exists(t => softFieldSensitive(state, t)).asJson,
        "cost" -> cost.asJson)
    }
    Json.obj("cases" -> cases.asJson)
  }

  def main(args: Array[String]): Unit = {
    val out = args(0) match {
      case "announcement" => announcementCases()
      case "ordering_announcement" => orderingCases()
      case "messages" => messageCases()
      case "weak_ids" => weakIdCases()
      case "pow" => powCases()
      case "extension_leaf" => extensionLeafCases()
      case "extension_proof" => extensionProofCases()
      case "soft_fields" => softFieldCases()
      case "input_block_validation" => inputBlockValidationCases()
      case other => sys.error(s"unknown vector $other")
    }
    println(out.spaces2)
  }
}

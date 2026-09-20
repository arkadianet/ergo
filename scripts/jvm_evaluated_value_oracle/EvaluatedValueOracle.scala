// Generator for the ContextExtension / box-register `EvaluatedValue` oracle vectors.
//
// `ErgoSerdeOracle.scala` (the difftest oracle) reduces against
// `ContextExtension.empty` and cannot express "reduce THIS tree against THAT
// extension / register", which is what the EvaluatedValue vectors need. This
// script drives the same Scala reference stack directly and prints every value
// pinned in:
//
//   test-vectors/scala/context_extension_evaluated_values.json
//   test-vectors/scala/group_generator_evaluated_value.json
//   test-vectors/scala/evaluated_value_forms.json
//   test-vectors/scala/get_var_type_mismatch.json
//
// Run (deps pinned to the versions mainnet runs; `ergo-core` is not on Maven
// Central — publish it locally, see ErgoSerdeOracle.scala's header):
//
//   scala-cli run scripts/jvm_evaluated_value_oracle/EvaluatedValueOracle.scala
//
// Every line is `key = value`. ACCEPT lines carry the canonical
// re-serialization (serde surfaces) or `P:<sigma-boolean hex>|<jit cost>`
// (reduce surfaces); REJECT lines carry the JVM exception class and message.
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2
//> using dep org.ergoplatform::ergo-wallet:6.0.2

// verify manifest: sigma-state/ergo-core/ergo-wallet = 6.0.2 fallback.
// Requested 6.0.6/6.0.5/6.0.5: core 6.0.5 absent from Ivy/coursier and
// returns HTTP 404 from Maven Central and the pinned GitLab repository.
// Usage: scala-cli run <this file> --server=false -- verify < requests.jsonl
// Self-test: scala-cli run <this file> --server=false -- verify_self_test
// Direct probes: jitcost_probe, accumulator_probe, raw_coll_equals, serialize_expr.
// Each has a corresponding <command>_self_test. serialize_expr reads one JSON AST:
// {"op":"Upcast","input_type":"Int","target_type":"Long","value":1}.
// scripts/gen-evaluated-probe.py captures direct output with a reproducibility manifest.
// One JSON request and response per line; no-argument vector output is unchanged.
// Required request keys: tree_hex, ctx_ext_hex, proof_hex, cost_limit_block,
// init_cost_block, activated_version, tree_version_expected, self_box_hex,
// inputs_hex, data_inputs_hex, outputs_hex, headers_hex, pre_header_hex, message_hex.
// inputs/data_inputs/SELF are full ErgoBox bytes; outputs are ErgoBoxCandidate bytes.
// Headers are node HeaderSerializer bytes (newest first).
// PreHeader has no node wire serializer: pre_header_hex is an 89-byte frame,
// big-endian version:u8, parentId:32, timestamp:i64, nBits:i64, height:i32,
// minerPk:33, votes:3. With no headers the UTXO root is AvlTreeData.dummy.
// Optional rent=true selects the actual wallet ErgoInterpreter rent implementation,
// including its 50 BC return, eligibility checks and recoverWith fallback.
// rent requires storage_fee_factor (the voted parameter); rent_path echoes rent.
// Completed rent reports eval=0, crypto=0, rent_block_cost=50 and total=init+50.
// The wallet returns 50 independently of init/limit; transaction validation supplies
// init=0 per input and accumulates externally. This API includes the supplied init
// in its total; transaction-level limit checks remain outside this API.
// Ordinary verification and rent fallback report rent_block_cost=0.
// Failure mapping (cause chain, cost takes precedence):
// CostLimitException => RejectCost; SigmaException, ValidationException,
// SerializerException, IllegalArgumentException, NoSuchElementException,
// IndexOutOfBoundsException, ClassCastException, ArithmeticException => RejectScript
// during verification; all request decoding errors and other exceptions => RejectOther.
// failure_class is the selected fully qualified exception class (null on Success).
// Unexposed costs/legacy use "unavailable". CostAccumulator exceptions expose JIT
// units, converted to BC by /10; addCostChecked exceptions expose BC directly.
// The breakdown observes fullReduction in the actual verify call, without replay.
// legacy is supplementary raw evaluator P:<prop>|<jit>, evaluated independently
// after verification; it cannot affect the verdict or structured costs.

import io.circe.Json
import io.circe.parser.parse
import scala.util.{Try, Success, Failure}
import scala.util.control.NonFatal
import sigmastate.interpreter.Interpreter
import sigma.exceptions.CostLimitException
import org.ergoplatform.modifiers.history.header.{Header => NodeHeader, HeaderSerializer}
import org.ergoplatform.settings.{Parameters, ErgoValidationSettingsUpdate}
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import scorex.util.encode.Base16
import scorex.util.bytesToId
import scorex.crypto.authds.ADKey
import sigma.{Colls, Header, PreHeader, VersionContext}
import sigma.crypto.CryptoConstants
import sigma.data.{AvlTreeData, SigmaBoolean, CSigmaProp}
import sigma.interpreter.{ContextExtension, ProverResult}
import sigma.ast._
import sigma.serialization.{ErgoTreeSerializer, GroupElementSerializer, SigmaSerializer, ValueSerializer}
import sigma.util.Extensions.EcpOps
import org.ergoplatform._
import org.ergoplatform.validation.ValidationRules
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.{CErgoTreeEvaluator, CostAccumulator}
import sigmastate.interpreter.CErgoTreeEvaluator.DefaultEvalSettings

object EvaluatedValueOracle {
  val treeSer = ErgoTreeSerializer.DefaultSerializer
  def hex(b: Array[Byte]): String = Base16.encode(b)
  def out(k: String, v: String): Unit = println(k + " = " + v)
  def fail(e: Throwable): String =
    "REJECT " + e.getClass.getSimpleName + ": " + String.valueOf(e.getMessage).take(240).replace("\n", " ")

  val dummyPubkey: Array[Byte] = GroupElementSerializer.toBytes(CryptoConstants.dlogGroup.generator)

  def dummyPreHeader(activated: Byte): PreHeader = CPreHeader(
    version = (activated + 1).toByte,
    parentId = Colls.fromArray(Array.fill(32)(0: Byte)),
    timestamp = 3L, nBits = 0L, height = 0,
    minerPk = GroupElementSerializer.parse(SigmaSerializer.startReader(dummyPubkey)).toGroupElement,
    votes = Colls.fromArray(Array.fill(3)(0: Byte)))

  /** Reduce `t` against the dummy context, with `ext` bound as the SELF input's
    * extension and `regs` as the SELF box's non-mandatory registers. Mirrors the
    * `reduce` surface of ErgoSerdeOracle (activated version 3, SELF = the tree
    * at 1000000 nanoERG as the sole input, no outputs / data inputs). */
  def reduce(t: ErgoTree,
             ext: ContextExtension,
             regs: Map[ErgoBox.NonMandatoryRegisterId, EvaluatedValue[_ <: SType]]): String =
    try VersionContext.withVersions(3.toByte, t.version) {
      val selfBox = new ErgoBox(1000000L, t, Colls.emptyColl, regs,
        bytesToId(Array.fill(32)(0: Byte)), 0.toShort, 0)
      val ctx = new ErgoLikeContext(
        lastBlockUtxoRoot = AvlTreeData.dummy,
        headers = Colls.emptyColl[Header],
        preHeader = dummyPreHeader(3.toByte),
        dataBoxes = IndexedSeq.empty,
        boxesToSpend = IndexedSeq(selfBox),
        spendingTransaction = ErgoLikeTransaction(IndexedSeq(), IndexedSeq()),
        selfIndex = 0,
        extension = ext,
        validationSettings = ValidationRules.currentSettings,
        costLimit = DefaultEvalSettings.scriptCostLimitInEvaluator,
        initCost = 0L,
        activatedScriptVersion = 3.toByte).withErgoTreeVersion(t.version)
      val accu = new CostAccumulator(JitCost.fromBlockCost(0),
        Some(JitCost.fromBlockCost(Math.toIntExact(ctx.costLimit))))
      val (v, _) = CErgoTreeEvaluator.eval(ctx.toSigmaContext(), accu, t.constants,
        t.toProposition(t.isConstantSegregation && t.hasDeserialize), DefaultEvalSettings)
      val repr = v match {
        case sp: CSigmaProp => "P:" + hex(SigmaBoolean.serializer.toBytes(sp.sigmaTree))
        case b: Boolean => "P:" + hex(SigmaBoolean.serializer.toBytes(
          if (b) sigma.data.TrivialProp.TrueProp else sigma.data.TrivialProp.FalseProp))
        case o => "OTHER:" + o.getClass.getSimpleName
      }
      "ACCEPT " + repr + "|" + accu.totalCost.value
    } catch { case e: Throwable => fail(e) }

  val trueTree: ErgoTree = ErgoTree.fromProposition(TrueLeaf.toSigmaProp)

  def extOf(bindings: (Byte, EvaluatedValue[_ <: SType])*): ContextExtension =
    ContextExtension(bindings.toMap)

  def txWith(ext: ContextExtension): ErgoTransaction =
    ErgoTransaction(
      IndexedSeq(Input(ADKey @@ Array.fill(32)(1: Byte), ProverResult(Array[Byte](), ext))),
      IndexedSeq(),
      IndexedSeq(new ErgoBoxCandidate(1000000L, trueTree, 0)))

  /** `<name>_value_hex` / `<name>_ctxext_{hex,parse}` / `<name>_tx_{hex,roundtrip,id}`
    * / `<name>_reg_{hex,roundtrip}` for one EvaluatedValue form. */
  def dumpForm(name: String, v: EvaluatedValue[_ <: SType]): Unit = {
    out(s"${name}_value_hex", hex(ValueSerializer.serialize(v)))

    val ext = extOf((1: Byte) -> v)
    val extBytes = ContextExtension.serializer.toBytes(ext)
    out(s"${name}_ctxext_hex", hex(extBytes))
    out(s"${name}_ctxext_parse", try {
      "ACCEPT " + hex(ContextExtension.serializer.toBytes(
        ContextExtension.serializer.parse(SigmaSerializer.startReader(extBytes))))
    } catch { case e: Throwable => fail(e) })

    val tx = txWith(ext)
    val txBytes = ErgoTransactionSerializer.toBytes(tx)
    out(s"${name}_tx_hex", hex(txBytes))
    out(s"${name}_tx_roundtrip", try {
      "ACCEPT " + hex(ErgoTransactionSerializer.toBytes(ErgoTransactionSerializer.parseBytes(txBytes)))
    } catch { case e: Throwable => fail(e) })
    out(s"${name}_tx_id", tx.id.toString)

    val cand = new ErgoBoxCandidate(1000000L, trueTree, 0, Colls.emptyColl, Map(ErgoBox.R4 -> v))
    val candBytes = ErgoBoxCandidate.serializer.toBytes(cand)
    out(s"${name}_reg_hex", hex(candBytes))
    out(s"${name}_reg_roundtrip", try {
      "ACCEPT " + hex(ErgoBoxCandidate.serializer.toBytes(
        ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(candBytes))))
    } catch { case e: Throwable => fail(e) })

    val fullBox = new ErgoBox(1000000L, trueTree, Colls.emptyColl, Map(ErgoBox.R4 -> v),
      bytesToId(Array.fill(32)(7: Byte)), 3.toShort, 0)
    out(s"${name}_box_bytes_hex", hex(fullBox.bytes))
    out(s"${name}_box_id", hex(fullBox.id))
  }

  def parseCtxExtHex(h: String): String =
    try {
      val e = ContextExtension.serializer.parse(SigmaSerializer.startReader(Base16.decode(h).get))
      "ACCEPT keys=" + e.values.keys.toSeq.sorted.mkString(",") + " " +
        hex(ContextExtension.serializer.toBytes(e))
    } catch { case e: Throwable => fail(e) }

  def parseBoxCandidateHex(h: String): String =
    try {
      val c = ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(Base16.decode(h).get))
      "ACCEPT " + hex(ErgoBoxCandidate.serializer.toBytes(c)) + " R4=" +
        c.additionalRegisters.get(ErgoBox.R4).map(_.toString).getOrElse("-")
    } catch { case e: Throwable => fail(e) }

  /** Parse a full signed transaction from hex and report the reference's
    * canonical re-serialization plus its id. `ErgoLikeTransaction.id` is
    * Blake2b256(bytesToSign), and `bytesToSign` rebuilds every input from the
    * PARSED `ContextExtension` (ErgoLikeTransaction.scala:190-197 ->
    * Input.serializer -> ProverResult.serializer -> ContextExtension.serializer
    * .serialize), so the id commits to the CANONICAL extension encoding, never
    * to the verbatim wire bytes. */
  def parseTxHex(h: String): String =
    try {
      val tx = ErgoTransactionSerializer.parseBytes(Base16.decode(h).get)
      "ACCEPT " + hex(ErgoTransactionSerializer.toBytes(tx)) + " id=" + tx.id.toString
    } catch { case e: Throwable => fail(e) }

  /** A 1-in / 1-out transaction whose sole input carries `extHex` verbatim as
    * its ContextExtension wire bytes. */
  def txHexWithRawExtension(extHex: String): String = {
    val boxId = "01" * 32
    val out = hex(ErgoBoxCandidate.serializer.toBytes(new ErgoBoxCandidate(1000000L, trueTree, 0)))
    // inputCount | boxId | proofLen=0 | <extension> | dataInputs=0 | tokens=0 | outputs=1 | out
    "01" + boxId + "00" + extHex + "00" + "00" + "01" + out
  }

  // ----- helpers -----

  private val unavailable = Json.fromString("unavailable")

  private def causes(error: Throwable): Vector[Throwable] = {
    val seen = scala.collection.mutable.ArrayBuffer.empty[Throwable]
    var next = error
    while (next != null && !seen.exists(_ eq next)) {
      seen += next
      next = next.getCause
    }
    seen.toVector
  }

  private def failure(error: Throwable, verifying: Boolean): (String, Throwable) = {
    val chain = causes(error)
    chain.collectFirst { case e: CostLimitException => ("RejectCost", e) }
      .getOrElse {
        val script = chain.find {
          case e: RuntimeException if e.getMessage != null &&
              e.getMessage.startsWith("Should be overriden in class sigma.ast.") => true
          case _: sigma.SigmaException | _: sigma.validation.ValidationException |
               _: sigma.serialization.SerializerException | _: IllegalArgumentException |
               _: NoSuchElementException | _: IndexOutOfBoundsException |
               _: ClassCastException | _: ArithmeticException => true
          case _ => false
        }
        if (verifying && script.isDefined) ("RejectScript", script.get)
        else ("RejectOther", error)
      }
  }

  private def failureCost(error: Throwable): Json =
    causes(error).collectFirst { case e: CostLimitException =>
      val jit = e.getStackTrace.exists(_.getClassName ==
        "sigmastate.interpreter.CostAccumulator")
      Json.fromLong(if (jit) e.estimatedCost / 10 else e.estimatedCost)
    }.getOrElse(unavailable)

  private trait ObservedReduction extends ErgoLikeInterpreter {
    override type CTX = ErgoLikeContext
    var measureOperationTime = false
    override protected def evalSettings: sigma.eval.EvalSettings =
      DefaultEvalSettings.copy(isMeasureOperationTime = measureOperationTime)
    var reduction: Option[Interpreter.ReductionResult] = None
    var chargedCrypto: Option[Long] = None
    var gateFailureCost: Option[Long] = None
    var gateBypass = false
    var deserializedCost: Option[Long] = None
    var propositionFailureCost: Option[Long] = None
    abstract override protected def propositionFromErgoTree(tree: ErgoTree, ctx: ErgoLikeContext): sigma.ast.Value[sigma.ast.SSigmaProp.type] = {
      try super.propositionFromErgoTree(tree, ctx)
      catch {
        case NonFatal(e) =>
          // This stage has only the context baseline, before reduction charges.
          propositionFailureCost = Some(ctx.initCost)
          throw e
      }
    }
    abstract override protected def checkSoftForkCondition(tree: ErgoTree, ctx: ErgoLikeContext): Option[Interpreter.VerificationResult] = {
      try {
        val result = super.checkSoftForkCondition(tree, ctx)
        gateBypass = result.isDefined
        result
      } catch {
        case NonFatal(e) =>
          gateFailureCost = Some(ctx.initCost)
          throw e
      }
    }
    abstract override protected def deserializeMeasured(ctx: ErgoLikeContext, bytes: Array[Byte]): (ErgoLikeContext, sigma.ast.Value[sigma.ast.SType]) = {
      val result = super.deserializeMeasured(ctx, bytes)
      deserializedCost = Some(result._1.initCost)
      result
    }
    abstract override protected def addCryptoCost(sb: SigmaBoolean, base: Long, limit: Long): Long = {
      val result = super.addCryptoCost(sb, base, limit)
      chargedCrypto = Some(result)
      result
    }
    abstract override def fullReduction(tree: ErgoTree, ctx: ErgoLikeContext,
                                       env: Interpreter.ScriptEnv): Interpreter.ReductionResult = {
      val result = super.fullReduction(tree, ctx, env)
      reduction = Some(result)
      result
    }
  }

  private def readPreHeader(bytes: Array[Byte]): PreHeader = {
    require(bytes.length == 89, "pre_header_hex must contain the 89-byte pre-header frame")
    val b = java.nio.ByteBuffer.wrap(bytes)
    def take(n: Int): Array[Byte] = { val result = new Array[Byte](n); b.get(result); result }
    val version = b.get()
    val parent = take(32)
    val timestamp = b.getLong()
    val nBits = b.getLong()
    val height = b.getInt()
    val pk = GroupElementSerializer.parse(SigmaSerializer.startReader(take(33))).toGroupElement
    CPreHeader(version, Colls.fromArray(parent), timestamp, nBits, height,
      pk, Colls.fromArray(take(3)))
  }

  def verifyLine(line: String): Json = {
    var rent = false
    var verifying = false
    var eval = unavailable
    var crypto = unavailable
    var rentCost = Json.fromLong(0)
    var legacy = unavailable
    var evaluatorFailureCost = unavailable
    def record(verdict: String, total: Json, error: Option[Throwable], detail: String): Json =
      Json.obj("verdict" -> Json.fromString(verdict), "eval_block_cost" -> eval,
        "crypto_block_cost" -> crypto, "rent_block_cost" -> rentCost, "rent_path" -> Json.fromBoolean(rent),
        "total_block_cost" -> total,
        "failure_class" -> error.map(e => Json.fromString(e.getClass.getName)).getOrElse(Json.Null),
        "rejection_detail" -> Json.fromString(detail), "legacy" -> legacy,
        "evaluator_failure_block_cost" -> evaluatorFailureCost)
    try {
      val cursor = parse(line).fold(throw _, identity).hcursor
      def str(key: String) = cursor.get[String](key).fold(throw _, identity)
      def number(key: String) = cursor.get[Long](key).fold(throw _, identity)
      def byte(key: String): Byte = {
        val n = number(key)
        require(n >= 0 && n <= 127, key + " is outside the script version range")
        n.toByte
      }
      def bytes(key: String) = Base16.decode(str(key)).get
      def array(key: String) = cursor.get[Vector[String]](key).fold(throw _, identity)
        .map(h => Base16.decode(h).get)
      def box(b: Array[Byte]) = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(b))
      rent = cursor.get[Option[Boolean]]("rent").fold(throw _, identity).getOrElse(false)
      val activated = byte("activated_version")
      val expected = byte("tree_version_expected")
      val treeBytes = bytes("tree_hex")
      require((treeBytes(0) & 7) == expected, "tree_version_expected differs from serialized tree")
      val parseOnly = cursor.get[Boolean]("parse_only").getOrElse(false)
      if (parseOnly) verifying = true
      val tree = VersionContext.withVersions(1.toByte, 1.toByte) {
        treeSer.deserializeErgoTree(treeBytes)
      }
      if (parseOnly) {
        // A size-delimited parser retains its ValidationException in Left.
        // Force that retained result without entering Interpreter.verify.
        tree.toProposition(false)
        return record("Accept", unavailable, None, "")
      }
      val self = box(bytes("self_box_hex"))
      val inputs = array("inputs_hex").map(box)
      val data = array("data_inputs_hex").map(box)
      val outputs = array("outputs_hex").map(b =>
        ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(b)))
      val headers = array("headers_hex").map(b => NodeHeader.toSigma(HeaderSerializer.parseBytes(b)))
      val preHeader = readPreHeader(bytes("pre_header_hex"))
      val selfIndex = inputs.indexWhere(b => java.util.Arrays.equals(b.bytes, self.bytes))
      require(selfIndex >= 0, "self_box_hex must occur in inputs_hex")
      val ext = ContextExtension.serializer.parse(SigmaSerializer.startReader(bytes("ctx_ext_hex")))
      val proof = ProverResult(bytes("proof_hex"), ext)
      val message = bytes("message_hex")
      val init = number("init_cost_block")
      val limit = number("cost_limit_block")
      require(init >= 0 && limit >= 0, "costs must be nonnegative")
      val tx = new ErgoLikeTransaction(inputs.map(b => Input(b.id, proof)),
        data.map(b => DataInput(b.id)), outputs)
      val root = headers.headOption.map(h => ErgoInterpreter.avlTreeFromDigest(h.stateRoot.digest))
        .getOrElse(AvlTreeData.dummy)
      // ReplacedRule makes the caught validation exception a recognized soft fork
      // (core/.../ValidationRules.scala:248, Interpreter.scala:249).
      val replacements = cursor.get[Option[Map[String, Short]]]("validation_settings_replaced_rules")
        .fold(throw _, identity).getOrElse(Map.empty)
      val disabled = cursor.get[Option[Vector[Short]]]("validation_settings_disabled_rules")
        .fold(throw _, identity).getOrElse(Vector.empty)
      val withDisabled = disabled.foldLeft(ValidationRules.currentSettings) {
        case (settings, id) => settings.updated(id, sigma.validation.DisabledRule)
      }
      val changes = cursor.get[Option[Map[String, String]]]("validation_settings_changed_rules")
        .fold(throw _, identity).getOrElse(Map.empty)
      val withChanges = changes.foldLeft(withDisabled) {
        case (settings, (id, codes)) =>
          settings.updated(id.toShort, sigma.validation.ChangedRule(Base16.decode(codes).get))
      }
      val validationSettings = replacements.foldLeft(withChanges) {
        case (settings, (id, replacement)) =>
          settings.updated(id.toShort, sigma.validation.ReplacedRule(replacement))
      }
      val ctx = new ErgoLikeContext(root, Colls.fromArray(headers.toArray), preHeader,
        data, inputs, tx, selfIndex, ext, validationSettings,
        limit, init, activated).withErgoTreeVersion(expected)
      var rentCompleted = false
      val interpreter: ErgoLikeInterpreter with ObservedReduction = if (rent) {
        val factor = Math.toIntExact(number("storage_fee_factor"))
        require(factor >= 0, "storage_fee_factor must be nonnegative")
        val params = Parameters(preHeader.height, Map(1.toByte -> factor),
          ErgoValidationSettingsUpdate.empty)
        new ErgoInterpreter(params) with ObservedReduction {
          override protected def checkExpiredBox(box: ErgoBox, output: ErgoBoxCandidate,
                                                 height: Int): Boolean = {
            val ok = super.checkExpiredBox(box, output, height)
            rentCompleted = true
            ok
          }
        }
      } else new ErgoLikeInterpreter with ObservedReduction
      interpreter.measureOperationTime = cursor.get[Option[Boolean]]("measure_operation_time")
        .fold(throw _, identity).getOrElse(false)
      verifying = true
      val result = interpreter.verify(tree, ctx, proof, message)
      interpreter.reduction.foreach { r =>
        eval = Json.fromLong(r.cost - init)
        crypto = Json.fromLong(Interpreter.estimateCryptoVerifyCost(r.value).toBlockCost)
      }
      if (interpreter.gateBypass) {
        eval = Json.fromLong(0)
        crypto = Json.fromLong(0)
      }
      // The wallet rent path returns without invoking fullReduction.
      if (rentCompleted && result.isSuccess) {
        eval = Json.fromLong(0)
        crypto = Json.fromLong(0)
        rentCost = Json.fromLong(result.get._2)
      }
      if (interpreter.reduction.isDefined) {
        legacy = Try(VersionContext.withVersions(activated, tree.version) {
          val accu = new CostAccumulator(JitCost.fromBlockCost(0),
            Some(JitCost.fromBlockCost(Math.toIntExact(limit))))
          val (v, _) = CErgoTreeEvaluator.eval(ctx.withInitCost(0).toSigmaContext(), accu,
            tree.constants, tree.toProposition(tree.isConstantSegregation && tree.hasDeserialize),
            DefaultEvalSettings)
          val sb = v match {
            case p: CSigmaProp => p.sigmaTree
            case b: Boolean => if (b) sigma.data.TrivialProp.TrueProp else sigma.data.TrivialProp.FalseProp
            case other => throw new IllegalArgumentException("Unexpected evaluator value: " + other)
          }
          Json.fromString("P:" + hex(SigmaBoolean.serializer.toBytes(sb)) + "|" + accu.totalCost.value)
        }).getOrElse(unavailable)
      }
      result match {
        case Success((ok, cost)) => record(if (ok) "Accept" else "RejectScript",
          Json.fromLong(if (rentCompleted) Math.addExact(init, cost) else cost), None, if (ok) "" else "Script reduced to false or proof invalid")
        case Failure(e) =>
          val (verdict, selected) = failure(e, verifying)
          // Supplementary evaluation exposes the accumulator retained on a throw.
          // This is not a substitute for the full verify result, which stays unavailable.
          if (cursor.get[Boolean]("observe_evaluator_failure").getOrElse(false)) {
            require(!tree.hasDeserialize && init == 0 && !rent,
              "failure observation requires a plain evaluator tree with zero init cost")
            VersionContext.withVersions(activated, tree.version) {
              val accu = new CostAccumulator(JitCost.fromBlockCost(0),
                Some(JitCost.fromBlockCost(Math.toIntExact(limit))))
              val evaluated = Try(CErgoTreeEvaluator.eval(ctx.toSigmaContext(), accu,
                tree.constants, tree.toProposition(false), DefaultEvalSettings))
              require(evaluated.isFailure, "failure observation unexpectedly succeeded")
              evaluatorFailureCost = Json.fromLong(accu.totalCost.toBlockCost)
            }
          }
          val cost = if (verdict == "RejectCost") failureCost(e)
            else if (cursor.get[Boolean]("observe_deserialization_failure").getOrElse(false)) {
              require(selected.isInstanceOf[sigma.validation.ValidationException], "expected deserialization validation failure")
              interpreter.deserializedCost.map(Json.fromLong).getOrElse(unavailable)
            } else interpreter.gateFailureCost.orElse(interpreter.propositionFailureCost).orElse(interpreter.chargedCrypto).map(Json.fromLong).getOrElse(unavailable)
          record(verdict, cost, Some(selected), e.toString)
      }
    } catch {
      case NonFatal(e) =>
        val (verdict, selected) = failure(e, verifying)
        record(verdict, failureCost(e), Some(selected), e.toString)
    }
  }

  // ----- happy path -----

  private def verify_self_test(): Unit = {
    val pkTree = treeSer.deserializeErgoTree(Base16.decode("0008cd" + hex(dummyPubkey)).get)
    def request(tree: ErgoTree = pkTree, height: Int = 0): Json = {
      val self = new ErgoBox(1000000L, tree, Colls.emptyColl, Map.empty,
        bytesToId(Array.fill(32)(0: Byte)), 0.toShort, 0)
      val pre = java.nio.ByteBuffer.allocate(89).put(4.toByte)
        .put(Array.fill(32)(0: Byte)).putLong(3L).putLong(0L).putInt(height)
        .put(dummyPubkey).put(Array.fill(3)(0: Byte)).array()
      Json.obj("tree_hex" -> Json.fromString(hex(tree.bytes)),
        "ctx_ext_hex" -> Json.fromString("00"), "proof_hex" -> Json.fromString(""),
        "cost_limit_block" -> Json.fromLong(1000000), "init_cost_block" -> Json.fromLong(0),
        "activated_version" -> Json.fromInt(3), "tree_version_expected" -> Json.fromInt(tree.version),
        "self_box_hex" -> Json.fromString(hex(self.bytes)),
        "inputs_hex" -> Json.arr(Json.fromString(hex(self.bytes))),
        "data_inputs_hex" -> Json.arr(), "outputs_hex" -> Json.arr(),
        "headers_hex" -> Json.arr(), "pre_header_hex" -> Json.fromString(hex(pre)),
        "message_hex" -> Json.fromString(""))
    }
    def patch(req: Json, values: (String, Json)*): Json = req.deepMerge(Json.obj(values: _*))
    var count = 0
    def check(name: String, req: Json, expected: (String, Json)*): Unit = {
      val actual = verifyLine(req.noSpaces)
      require(actual.asObject.get.keys.toSet == Set("verdict", "eval_block_cost",
        "crypto_block_cost", "rent_block_cost", "rent_path", "total_block_cost", "failure_class",
        "rejection_detail", "legacy", "evaluator_failure_block_cost"), name + ": response schema")
      expected.foreach { case (key, value) =>
        require(actual.hcursor.downField(key).focus.contains(value),
          name + ": " + key + " expected " + value + ", got " + actual.noSpaces)
      }
      val c = actual.hcursor
      for {
        init <- req.hcursor.get[Long]("init_cost_block").toOption
        eval <- c.get[Long]("eval_block_cost").toOption
        crypto <- c.get[Long]("crypto_block_cost").toOption
        rent <- c.get[Long]("rent_block_cost").toOption
        total <- c.get[Long]("total_block_cost").toOption
      } require(init + eval + crypto + rent == total, name + ": breakdown identity")
      count += 1
    }
    def str(s: String) = Json.fromString(s)
    def num(n: Long) = Json.fromLong(n)
    val pk = request()
    check("p2pk_empty_proof_cost_breakdown", pk,
      "verdict" -> str("RejectScript"), "eval_block_cost" -> num(5),
      "crypto_block_cost" -> num(398), "total_block_cost" -> num(403),
      "legacy" -> str("P:cd" + hex(dummyPubkey) + "|5"))
    val truth = request(ErgoTree.fromProposition(SigmaPropConstant(sigma.data.TrivialProp.TrueProp)))
    check("true_empty_proof_accept", truth, "verdict" -> str("Accept"),
      "eval_block_cost" -> num(5), "crypto_block_cost" -> num(0), "total_block_cost" -> num(5))
    check("false_empty_proof_reject_script",
      request(ErgoTree.fromProposition(SigmaPropConstant(sigma.data.TrivialProp.FalseProp))),
      "verdict" -> str("RejectScript"), "total_block_cost" -> num(5))
    check("p2pk_nonzero_init_cost_preserved", patch(pk, "init_cost_block" -> num(17)),
      "eval_block_cost" -> num(5), "crypto_block_cost" -> num(398), "total_block_cost" -> num(420))

    val secret = sigmastate.crypto.DLogProtocol.DLogProverInput(java.math.BigInteger.ONE)
    val prover = new ErgoLikeInterpreter with sigmastate.interpreter.ProverInterpreter {
      override type CTX = ErgoLikeContext
      override val secrets = IndexedSeq(secret)
    }
    val signature = prover.generateProof(secret.publicImage, Array.emptyByteArray,
      sigmastate.interpreter.HintsBag.empty)
    val signed = patch(pk, "proof_hex" -> str(hex(signature)))
    check("p2pk_valid_proof_accept", signed, "verdict" -> str("Accept"),
      "eval_block_cost" -> num(5), "crypto_block_cost" -> num(398), "total_block_cost" -> num(403))
    check("p2pk_wrong_message_reject_script", patch(signed, "message_hex" -> str("01")),
      "verdict" -> str("RejectScript"), "total_block_cost" -> num(403))
    for (limit <- Seq(402, 403, 404)) {
      check("p2pk_signed_limit_" + limit + "_verdict", patch(signed, "cost_limit_block" -> num(limit)),
        "verdict" -> str(if (limit < 403) "RejectCost" else "Accept"),
        "total_block_cost" -> num(403))
    }

    // ----- round-trips -----
    val original = verifyLine(pk.noSpaces)
    require(parse(original.noSpaces).fold(throw _, identity) == original)
    count += 1

    // ----- error paths -----
    for (limit <- Seq(402, 403, 404)) {
      check("p2pk_limit_" + limit + "_verdict", patch(pk, "cost_limit_block" -> num(limit)),
        "verdict" -> str(if (limit < 403) "RejectCost" else "RejectScript"),
        "total_block_cost" -> num(403))
    }
    check("p2pk_reduction_limit_reject_cost", patch(pk, "cost_limit_block" -> num(4)),
      "verdict" -> str("RejectCost"), "total_block_cost" -> num(5),
      "eval_block_cost" -> unavailable, "crypto_block_cost" -> unavailable)
    check("p2pk_init_limit_reject_cost",
      patch(pk, "init_cost_block" -> num(17), "cost_limit_block" -> num(16)),
      "verdict" -> str("RejectCost"), "total_block_cost" -> num(22))
    check("request_tree_version_mismatch_reject_other", patch(pk, "tree_version_expected" -> num(1)),
      "verdict" -> str("RejectOther"), "total_block_cost" -> unavailable)
    check("tree_above_activation_reject_script",
      patch(pk, "tree_hex" -> str("092308cd" + hex(dummyPubkey)),
        "tree_version_expected" -> num(1), "activated_version" -> num(0)),
      "verdict" -> str("RejectScript"),
      "failure_class" -> str("sigma.exceptions.InterpreterException"),
      "eval_block_cost" -> unavailable, "total_block_cost" -> num(0))
    require(verifyLine("{").hcursor.get[String]("verdict") == Right("RejectOther"))
    count += 1
    val wrapped = new RuntimeException("wrapper", new CostLimitException(51, "limit"))
    require(failure(wrapped, true)._1 == "RejectCost" && failureCost(wrapped) == num(51))
    require(failure(new RuntimeException("cost"), true)._1 == "RejectOther")
    count += 1

    // ----- oracle parity -----
    // Oracle: the pinned wallet ErgoInterpreter (StorageContractCost = 50 BC).
    val rent = patch(request(height = 1051200), "rent" -> Json.True,
      "storage_fee_factor" -> num(1250000), "ctx_ext_hex" -> str("017f0300"),
      "outputs_hex" -> Json.arr(str(hex(ErgoBoxCandidate.serializer.toBytes(
        new ErgoBoxCandidate(1000000L, trueTree, 1051200))))))
    check("rent_expired_box_accept", rent, "verdict" -> str("Accept"),
      "eval_block_cost" -> num(0), "rent_block_cost" -> num(50), "crypto_block_cost" -> num(0),
      "total_block_cost" -> num(50), "rent_path" -> Json.True, "legacy" -> unavailable)
    check("rent_low_limit_nonzero_init_wallet_cost",
      patch(rent, "init_cost_block" -> num(17), "cost_limit_block" -> num(49)),
      "verdict" -> str("Accept"), "eval_block_cost" -> num(0),
      "crypto_block_cost" -> num(0), "rent_block_cost" -> num(50), "total_block_cost" -> num(67))
    check("rent_unexpired_box_fallback_reject_script",
      patch(rent, "pre_header_hex" -> request().hcursor.downField("pre_header_hex").focus.get),
      "verdict" -> str("RejectScript"), "total_block_cost" -> num(403))
    check("rent_bad_index_fallback_reject_script", patch(rent, "ctx_ext_hex" -> str("017f0302")),
      "verdict" -> str("RejectScript"), "eval_block_cost" -> num(5),
      "crypto_block_cost" -> num(398), "total_block_cost" -> num(403))
    check("rent_missing_extension_fallback_reject_script", patch(rent, "ctx_ext_hex" -> str("00")),
      "verdict" -> str("RejectScript"), "total_block_cost" -> num(403))
    check("rent_bad_type_fallback_reject_script", patch(rent, "ctx_ext_hex" -> str("017f0400")),
      "verdict" -> str("RejectScript"), "total_block_cost" -> num(403))
    check("rent_uncovered_fee_bad_output_reject_script",
      patch(rent, "storage_fee_factor" -> num(0)),
      "verdict" -> str("RejectScript"), "eval_block_cost" -> num(0), "rent_block_cost" -> num(50),
      "crypto_block_cost" -> num(0), "total_block_cost" -> num(50))
    check("rent_fallback_low_limit_reject_cost",
      patch(rent, "ctx_ext_hex" -> str("017f0302"), "cost_limit_block" -> num(402)),
      "verdict" -> str("RejectCost"), "total_block_cost" -> num(403))
    val expression = request(ErgoTree.fromProposition(BoolToSigmaProp(EQ(Height, IntConstant(0)))))
    val expressionResult = verifyLine(expression.noSpaces)
    require(expressionResult.hcursor.get[String]("verdict") == Right("Accept"))
    val lowExpression = verifyLine(patch(expression, "cost_limit_block" -> num(0)).noSpaces)
    require(lowExpression.hcursor.get[String]("verdict") == Right("RejectCost"))
    require(lowExpression.hcursor.get[Long]("total_block_cost").exists(_ > 0))
    count += 2
    val deserializeTree = treeSer.deserializeErgoTree(treeSer.serializeErgoTree(
      ErgoTree.fromProposition(DeserializeContext(1.toByte, SSigmaProp))))
    require(deserializeTree.hasDeserialize, "deserialize serialized tree must select substitution")
    val deserialize = patch(request(deserializeTree), "init_cost_block" -> num(17),
      "ctx_ext_hex" -> str(hex(ContextExtension.serializer.toBytes(extOf(
        (1: Byte) -> ByteArrayConstant(ValueSerializer.serialize(
          SigmaPropConstant(sigma.data.TrivialProp.TrueProp))))))))
    // Pinned JVM observation: init=17, reduction=14 BC, total=31 BC.
    // Internal cost is 315 JIT: limit=31 BC rejects before BC truncation; 32 accepts.
    // These requests traverse serialized DeserializeContext substitution in verify.
    for (limit <- Seq(30, 31, 32)) {
      check("deserialize_context_nonzero_init_limit_" + limit + "_verdict",
        patch(deserialize, "cost_limit_block" -> num(limit)),
        "verdict" -> str(if (limit < 32) "RejectCost" else "Accept"),
        "total_block_cost" -> num(31), "rent_block_cost" -> num(0),
        "eval_block_cost" -> (if (limit < 32) unavailable else num(14)),
        "crypto_block_cost" -> (if (limit < 32) unavailable else num(0)))
    }
    val mismatch = patch(deserialize, "ctx_ext_hex" -> str("01010e020101"))
    check("validation_settings_replaced_rule_accepts", patch(mismatch,
      "validation_settings_replaced_rules" -> Json.obj("1000" -> num(1001))),
      "verdict" -> str("Accept"), "total_block_cost" -> num(27))
    check("validation_settings_disabled_rule_rejects", patch(mismatch,
      "validation_settings_disabled_rules" -> Json.arr(num(1000))),
      "verdict" -> str("RejectScript"), "failure_class" -> str("sigma.validation.ValidationException"))
    val primitiveFailure = patch(deserialize, "activated_version" -> num(2),
      "ctx_ext_hex" -> str("01010e03d40a00"))
    for (matching <- Seq(false, true)) {
      check("validation_settings_changed_type_" + matching, patch(primitiveFailure,
        "validation_settings_changed_rules" -> Json.obj("1007" -> str(if (matching) "0a" else "ff"))),
        "verdict" -> str(if (matching) "Accept" else "RejectScript"))
    }
    println("verify self-test: " + count + " passed, 0 failed")
  }

  private def rawCollEquals(): Json = {
    import sigma.data.RType._
    val cases = for (version <- Seq(2, 3); reverse <- Seq(false, true)) yield {
      VersionContext.withVersions(3.toByte, version.toByte) {
        val pair = Colls.fromItems(1).zip(Colls.fromItems(2))
        val array = pair.map(p => p)
        require(pair.isInstanceOf[sigma.PairColl[_, _]])
        require(array.isInstanceOf[sigma.data.CollOverArray[_]])
        val result = if (reverse) array.equals(pair) else pair.equals(array)
        Json.obj("version" -> Json.fromInt(version), "reverse" -> Json.fromBoolean(reverse),
          "pair_class" -> Json.fromString(pair.getClass.getName),
          "array_class" -> Json.fromString(array.getClass.getName),
          "left" -> Json.arr(Json.arr(Json.fromInt(1), Json.fromInt(2))),
          "right" -> Json.arr(Json.arr(Json.fromInt(1), Json.fromInt(2))),
          "equals" -> Json.fromBoolean(result),
          "same_representation_equals" -> Json.fromBoolean(pair.equals(pair) && array.equals(array)))
      }
    }
    Json.obj("oracle" -> Json.fromString("sigma-state:6.0.2 / raw_coll_equals"),
      "cases" -> Json.arr(cases: _*))
  }

  private def serializeExpr(line: String): Json = {
    val ast = parse(line).right.get
    val h = ast.hcursor
    require(h.get[String]("op").right.get == "Upcast")
    require(h.get[String]("input_type").right.get == "Int")
    require(h.get[String]("target_type").right.get == "Long")
    val n = h.get[Int]("value").right.get
    val root = BoolToSigmaProp(EQ(Upcast(IntConstant(n), SLong), LongConstant(n.toLong)))
    val cases = Seq(2, 3).map { version =>
      VersionContext.withVersions(3.toByte, version.toByte) {
        val bytes = ValueSerializer.serialize(root)
        val tree = Array((version | 8).toByte, bytes.length.toByte) ++ bytes
        Json.obj("name" -> Json.fromString("upcast-int-long-v" + version),
          "version" -> Json.fromInt(version), "expression_hex" -> Json.fromString(hex(bytes)),
          "tree_hex" -> Json.fromString(hex(tree)))
      }
    }
    Json.obj("ast" -> ast, "cases" -> Json.arr(cases: _*),
      "jvm_bytes_v2" -> cases(0).hcursor.downField("expression_hex").focus.get,
      "jvm_bytes_v3" -> cases(1).hcursor.downField("expression_hex").focus.get)
  }

  private def accumulatorProbe(): Json = {
    val cases = for (initial <- Seq(9, 10, 11); delta <- Seq(0, 1)) yield {
      val accumulator = new CostAccumulator(JitCost(initial), Some(JitCost(10)))
      val before = accumulator.totalCost.value
      val exception = try {
        accumulator.add(JitCost(delta))
        Json.Null
      } catch { case NonFatal(e) => Json.fromString(e.getClass.getName) }
      Json.obj("initial" -> Json.fromInt(initial), "limit" -> Json.fromInt(10),
        "delta" -> Json.fromInt(delta), "before" -> Json.fromInt(before),
        "after" -> Json.fromInt(accumulator.totalCost.value), "exception" -> exception)
    }
    Json.obj("oracle" -> Json.fromString("sigma-state:6.0.2 / accumulator_probe"),
      "cases" -> Json.arr(cases: _*))
  }

  private def jitcostProbe(): Json = {
    val cases = Seq(("add", 2147483646, 1), ("add", 2147483647, 1),
      ("from_block_cost", 214748364, 0), ("from_block_cost", 214748365, 0)).map {
      case (op, a, b) =>
        val result = try {
          val cost = if (op == "add") JitCost(a) + JitCost(b) else JitCost.fromBlockCost(a)
          Json.obj("value" -> Json.fromInt(cost.value), "exception" -> Json.Null)
        } catch { case NonFatal(e) =>
          Json.obj("value" -> Json.Null, "exception" -> Json.fromString(e.getClass.getName))
        }
        Json.obj("operation" -> Json.fromString(op), "a" -> Json.fromInt(a),
          "b" -> Json.fromInt(b), "result" -> result)
    }
    Json.obj("oracle" -> Json.fromString("sigma-state:6.0.2 / jitcost_probe"),
      "cases" -> Json.arr(cases: _*))
  }

  def main(args: Array[String]): Unit = {
    if (args.sameElements(Array("raw_coll_equals"))) {
      println(rawCollEquals().spaces2)
    } else if (args.sameElements(Array("raw_coll_equals_self_test"))) {
      val cases = rawCollEquals().hcursor.downField("cases").focus.get.asArray.get
      require(cases.size == 4)
      cases.foreach { c =>
        require(c.hcursor.get[Boolean]("equals").right.get ==
          (c.hcursor.get[Int]("version").right.get >= 3))
        require(c.hcursor.get[Boolean]("same_representation_equals").right.get)
      }
      println("raw_coll_equals self-test: 4 passed, 0 failed")
    } else if (args.sameElements(Array("serialize_expr"))) {
      println(serializeExpr(scala.io.Source.stdin.mkString).spaces2)
    } else if (args.sameElements(Array("serialize_expr_self_test"))) {
      val result = serializeExpr("""{"op":"Upcast","input_type":"Int","target_type":"Long","value":1}""")
      require(result.hcursor.get[String]("jvm_bytes_v2").right.get == "d19304020502")
      require(result.hcursor.get[String]("jvm_bytes_v3").right.get == "d1937e0402050502")
      println("serialize_expr self-test: 2 passed, 0 failed")
    } else if (args.sameElements(Array("accumulator_probe"))) {
      println(accumulatorProbe().spaces2)
    } else if (args.sameElements(Array("accumulator_probe_self_test"))) {
      val cases = accumulatorProbe().hcursor.downField("cases").focus.get.asArray.get
      require(cases.size == 6)
      cases.foreach { c =>
        val h = c.hcursor
        val initial = h.get[Int]("initial").right.get
        val after = initial + h.get[Int]("delta").right.get
        require(h.get[Int]("before").right.get == initial)
        require(h.get[Int]("after").right.get == after)
        require(h.get[Option[String]]("exception").right.get ==
          (if (after > 10) Some("sigma.exceptions.CostLimitException") else None))
      }
      println("accumulator_probe self-test: 6 passed, 0 failed")
    } else if (args.sameElements(Array("jitcost_probe"))) {
      println(jitcostProbe().spaces2)
    } else if (args.sameElements(Array("jitcost_probe_self_test"))) {
      val cases = jitcostProbe().hcursor.downField("cases").focus.get.asArray.get
      require(cases.size == 4)
      require(cases(0).hcursor.downField("result").get[Int]("value").right.get == Int.MaxValue)
      require(cases(2).hcursor.downField("result").get[Int]("value").right.get == 2147483640)
      Seq(1, 3).foreach(i => require(cases(i).hcursor.downField("result")
        .get[String]("exception").right.get == "java.lang.ArithmeticException"))
      println("jitcost_probe self-test: 4 passed, 0 failed")
    } else if (args.sameElements(Array("verify"))) {
      scala.io.Source.stdin.getLines().foreach { line =>
        // Parser diagnostics belong on stderr; stdout is one JSON record per request.
        val result = Console.withOut(System.err) { verifyLine(line) }
        println(result.noSpaces)
      }
    } else if (args.sameElements(Array("verify_self_test"))) {
      verify_self_test()
    } else {
      require(args.isEmpty, "Usage: EvaluatedValueOracle [verify|jitcost_probe|accumulator_probe|raw_coll_equals|serialize_expr] (or <command>_self_test)")
      dumpVectors()
    }
  }

  private def dumpVectors(): Unit = VersionContext.withVersions(3.toByte, 0.toByte) {

    // ── hand-crafted bytes: the TrueLeaf / FalseLeaf OPCODES (0x7f / 0x80).
    // `ValueSerializer` never WRITES these for a boolean constant (it routes
    // constants through ConstantSerializer, so TrueLeaf comes out as `0101`),
    // but `deserialize` accepts them via CaseObjectSerialization and they are
    // `ConstantNode[SBoolean]`, hence `EvaluatedValue`. So the reference
    // ACCEPTS them on input and canonicalizes on output.
    out("ctxext_true_leaf_opcode_parse", parseCtxExtHex("01017f"))
    out("ctxext_false_leaf_opcode_parse", parseCtxExtHex("010180"))
    out("reg_true_leaf_opcode_parse", parseBoxCandidateHex("c0843d10010101d17300000001" + "7f"))
    out("reg_false_leaf_opcode_parse", parseBoxCandidateHex("c0843d10010101d17300000001" + "80"))
    out("reg_group_generator_parse", parseBoxCandidateHex("c0843d10010101d17300000001" + "82"))
    out("reg_bool_collection_parse", parseBoxCandidateHex("c0843d10010101d17300000001" + "850201"))
    // Non-canonical Boolean constant payload (`0105`): does the reference
    // canonicalize it on re-serialization the way it does `7f` / `80`?
    out("reg_bool_noncanonical_parse", parseBoxCandidateHex("c0843d10010101d17300000001" + "0105"))
    out("ctxext_bool_noncanonical_parse", parseCtxExtHex("01010105"))

    // ── the EvaluatedValue forms, on both surfaces ────────────────────────────
    dumpForm("tuple", Tuple(IndexedSeq(IntConstant(1), IntConstant(2))))
    dumpForm("concrete_collection",
      ConcreteCollection(IndexedSeq(IntConstant(7), IntConstant(8)), SInt)
        .asInstanceOf[EvaluatedValue[_ <: SType]])
    dumpForm("group_generator", GroupGenerator)
    dumpForm("true_leaf", TrueLeaf)
    dumpForm("false_leaf", FalseLeaf)
    // A Coll[Boolean] of constants ALWAYS serializes as
    // ConcreteCollectionBooleanConstant (0x85) — values.scala:845.
    dumpForm("bool_collection",
      ConcreteCollection(IndexedSeq(TrueLeaf, FalseLeaf), SBoolean)
        .asInstanceOf[EvaluatedValue[_ <: SType]])
    // Control: the same point as GroupGenerator, but as a Constant.
    dumpForm("group_element_constant", GroupElementConstant(GroupGenerator.value))
    dumpForm("bool_constant_true", BooleanConstant(true))

    // ── negative control: a node that is NOT an EvaluatedValue ───────────────
    out("height_value_hex", hex(ValueSerializer.serialize(Height)))
    out("ctxext_height_parse", parseCtxExtHex("0101" + hex(ValueSerializer.serialize(Height))))

    // ── context-extension key domain: 6.0.2 has no `k < 0` guard at parse ────
    out("ctxext_negative_key_parse", parseCtxExtHex("0180" + "0405"))
    out("reduce_negative_key_true_script",
      reduce(trueTree, extOf((-128: Byte) -> IntConstant(2)), Map.empty))

    // ── reduce vectors over the accepted forms ───────────────────────────────
    val tupleExt = extOf((1: Byte) -> Tuple(IndexedSeq(IntConstant(1), IntConstant(2))),
      (2: Byte) -> ConcreteCollection(IndexedSeq(IntConstant(7), IntConstant(8)), SInt)
        .asInstanceOf[EvaluatedValue[_ <: SType]])
    out("ctxext_tuple_and_coll_hex", hex(ContextExtension.serializer.toBytes(tupleExt)))

    val sTrue = trueTree
    out("script_true_hex", hex(treeSer.serializeErgoTree(sTrue)))
    out("reduce_true_with_tuple_ext", reduce(sTrue, tupleExt, Map.empty))

    val tupleT = STuple(SInt, SInt)
    val sSelect = ErgoTree.fromProposition(BoolToSigmaProp(EQ(
      SelectField(OptionGet(GetVar(1.toByte, SOption(tupleT))).asInstanceOf[Value[STuple]], 1.toByte)
        .asInstanceOf[Value[SInt.type]], IntConstant(1))))
    out("script_tuple_selectfield_hex", hex(treeSer.serializeErgoTree(sSelect)))
    out("reduce_tuple_selectfield", reduce(sSelect, tupleExt, Map.empty))

    val sDefined = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionIsDefined(GetVar(1.toByte, SOption(tupleT)))))
    out("script_tuple_isdefined_hex", hex(treeSer.serializeErgoTree(sDefined)))
    out("reduce_tuple_isdefined", reduce(sDefined, tupleExt, Map.empty))

    val sByIndex = ErgoTree.fromProposition(BoolToSigmaProp(EQ(
      ByIndex(OptionGet(GetVar(2.toByte, SOption(SCollection(SInt)))), IntConstant(0)),
      IntConstant(7))))
    out("script_coll_byindex_hex", hex(treeSer.serializeErgoTree(sByIndex)))
    out("reduce_coll_byindex", reduce(sByIndex, tupleExt, Map.empty))

    val ggExt = extOf((1: Byte) -> GroupGenerator)
    val sGeEq = ErgoTree.fromProposition(BoolToSigmaProp(EQ(
      OptionGet(GetVar(1.toByte, SOption(SGroupElement))).asInstanceOf[Value[SGroupElement.type]],
      GroupGenerator)))
    out("script_ext_ge_eq_generator_hex", hex(treeSer.serializeErgoTree(sGeEq)))
    out("reduce_ext_ge_eq_generator", reduce(sGeEq, ggExt, Map.empty))

    val sGeDefined = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionIsDefined(GetVar(1.toByte, SOption(SGroupElement)))))
    out("script_ext_ge_isdefined_hex", hex(treeSer.serializeErgoTree(sGeDefined)))
    out("reduce_ext_ge_isdefined", reduce(sGeDefined, ggExt, Map.empty))

    val sRegGeEq = ErgoTree.fromProposition(BoolToSigmaProp(EQ(
      OptionGet(ExtractRegisterAs(Self, ErgoBox.R4, SOption(SGroupElement)))
        .asInstanceOf[Value[SGroupElement.type]], GroupGenerator)))
    out("script_reg_ge_eq_generator_hex", hex(treeSer.serializeErgoTree(sRegGeEq)))
    out("reduce_reg_ge_eq_generator", reduce(sRegGeEq, ContextExtension.empty, Map(ErgoBox.R4 -> GroupGenerator)))
    out("reduce_reg_ge_constant_control",
      reduce(sRegGeEq, ContextExtension.empty, Map(ErgoBox.R4 -> GroupElementConstant(GroupGenerator.value))))

    // getVar[Boolean](1) over a TrueLeaf var; getVar[Coll[Boolean]](1) over 0x85.
    val sBoolVar = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionGet(GetVar(1.toByte, SOption(SBoolean)))))
    out("script_ext_bool_get_hex", hex(treeSer.serializeErgoTree(sBoolVar)))
    out("reduce_ext_true_leaf_get", reduce(sBoolVar, extOf((1: Byte) -> TrueLeaf), Map.empty))
    out("reduce_ext_false_leaf_get", reduce(sBoolVar, extOf((1: Byte) -> FalseLeaf), Map.empty))

    val boolColl = ConcreteCollection(IndexedSeq(TrueLeaf, FalseLeaf), SBoolean)
      .asInstanceOf[EvaluatedValue[_ <: SType]]
    val sBoolColl = ErgoTree.fromProposition(BoolToSigmaProp(
      ByIndex(OptionGet(GetVar(1.toByte, SOption(SCollection(SBoolean)))), IntConstant(0))))
    out("script_ext_boolcoll_byindex_hex", hex(treeSer.serializeErgoTree(sBoolColl)))
    out("reduce_ext_boolcoll_byindex", reduce(sBoolColl, extOf((1: Byte) -> boolColl), Map.empty))

    val sRegBoolColl = ErgoTree.fromProposition(BoolToSigmaProp(
      ByIndex(OptionGet(ExtractRegisterAs(Self, ErgoBox.R4, SOption(SCollection(SBoolean)))), IntConstant(0))))
    out("script_reg_boolcoll_byindex_hex", hex(treeSer.serializeErgoTree(sRegBoolColl)))
    out("reduce_reg_boolcoll_byindex", reduce(sRegBoolColl, ContextExtension.empty, Map(ErgoBox.R4 -> boolColl)))

    val sRegBool = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionGet(ExtractRegisterAs(Self, ErgoBox.R4, SOption(SBoolean)))))
    out("script_reg_bool_get_hex", hex(treeSer.serializeErgoTree(sRegBool)))
    out("reduce_reg_true_leaf_get", reduce(sRegBool, ContextExtension.empty, Map(ErgoBox.R4 -> TrueLeaf)))

    // ── getVar / getReg TYPE-MISMATCH semantics ──────────────────────────────
    // Extension var 1 is an Int; the script asks for a Long. Scala's
    // CContext.getVar throws InvalidType for a PRESENT var of the wrong type,
    // and returns None only for an absent slot.
    val intExt = extOf((1: Byte) -> IntConstant(5))
    val sVarMismatch = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionIsDefined(GetVar(1.toByte, SOption(SLong)))))
    out("script_getvar_long_isdefined_hex", hex(treeSer.serializeErgoTree(sVarMismatch)))
    out("reduce_getvar_type_mismatch_present", reduce(sVarMismatch, intExt, Map.empty))
    out("reduce_getvar_absent_slot", reduce(sVarMismatch, ContextExtension.empty, Map.empty))

    val sVarMismatchEmpty = ErgoTree.fromProposition(BoolToSigmaProp(
      LogicalNot(OptionIsDefined(GetVar(1.toByte, SOption(SLong))))))
    out("script_getvar_long_not_isdefined_hex", hex(treeSer.serializeErgoTree(sVarMismatchEmpty)))
    out("reduce_getvar_type_mismatch_present_not_isdefined", reduce(sVarMismatchEmpty, intExt, Map.empty))
    out("reduce_getvar_absent_slot_not_isdefined", reduce(sVarMismatchEmpty, ContextExtension.empty, Map.empty))

    // Matching type, as a control.
    val sVarMatch = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionIsDefined(GetVar(1.toByte, SOption(SInt)))))
    out("script_getvar_int_isdefined_hex", hex(treeSer.serializeErgoTree(sVarMatch)))
    out("reduce_getvar_type_match_control", reduce(sVarMatch, intExt, Map.empty))

    // Register analogue: R4 holds an Int, the script asks for a Long.
    val sRegMismatch = ErgoTree.fromProposition(BoolToSigmaProp(
      OptionIsDefined(ExtractRegisterAs(Self, ErgoBox.R4, SOption(SLong)))))
    out("script_getreg_long_isdefined_hex", hex(treeSer.serializeErgoTree(sRegMismatch)))
    out("reduce_getreg_type_mismatch_present",
      reduce(sRegMismatch, ContextExtension.empty, Map(ErgoBox.R4 -> IntConstant(5))))
    out("reduce_getreg_absent_slot", reduce(sRegMismatch, ContextExtension.empty, Map.empty))

    val sRegMismatchEmpty = ErgoTree.fromProposition(BoolToSigmaProp(
      LogicalNot(OptionIsDefined(ExtractRegisterAs(Self, ErgoBox.R4, SOption(SLong))))))
    out("script_getreg_long_not_isdefined_hex", hex(treeSer.serializeErgoTree(sRegMismatchEmpty)))
    out("reduce_getreg_type_mismatch_present_not_isdefined",
      reduce(sRegMismatchEmpty, ContextExtension.empty, Map(ErgoBox.R4 -> IntConstant(5))))

    // ── transaction id canonicalizes the ContextExtension ────────────────────
    // Same transaction, three encodings of the same var-1 Boolean `true`:
    // the TrueLeaf opcode, a non-canonical Boolean payload, and the canonical
    // constant. All three must yield the SAME id and the SAME canonical bytes.
    for ((label, extHex) <- Seq(
           "true_leaf_opcode" -> "01017f",
           "false_leaf_opcode" -> "010180",
           "bool_noncanonical" -> "01010105",
           "bool_canonical" -> "01010101",
           "bool_false_canonical" -> "01010100",
           "concrete_collection" -> "0101830204040e0410",
           "bool_collection" -> "0101850201",
           "group_generator" -> "010182",
           "create_tuple" -> "0101860204020404")) {
      val h = txHexWithRawExtension(extHex)
      out(s"txid_ext_${label}_input_hex", h)
      out(s"txid_ext_${label}", parseTxHex(h))
    }

    // ── GroupElement normalization ───────────────────────────────────────────
    // GroupElementSerializer.parse (GroupElementSerializer.scala:35-42) maps
    // ANY 33 bytes whose first byte is 0 to the infinity point; serialize
    // (:20-33) writes infinity as 33 zeroes and re-encodes every other point
    // from affine coordinates. So a register `07 00 AA..` is accepted and
    // re-serialized as `07 00*33`, and the box id is computed over THAT.
    val geAllZero = "00" * 33
    val geZeroLeadGarbage = "00" + ("aa" * 32)
    val geGenerator = hex(GroupElementSerializer.toBytes(CryptoConstants.dlogGroup.generator))
    for ((label, geHex) <- Seq(
           "identity_all_zero" -> geAllZero,
           "identity_zero_lead_garbage" -> geZeroLeadGarbage,
           "generator" -> geGenerator)) {
      out(s"reg_ge_${label}_parse",
        parseBoxCandidateHex("c0843d10010101d17300000001" + "07" + geHex))
      // The same point inside a ProveDlog SigmaProp constant (`08cd` + point).
      out(s"reg_sigmaprop_dlog_${label}_parse",
        parseBoxCandidateHex("c0843d10010101d17300000001" + "08cd" + geHex))
      out(s"ctxext_ge_${label}_parse", parseCtxExtHex("0101" + "07" + geHex))
    }
    // Box ids over the full box for the two infinity encodings.
    for ((label, geHex) <- Seq(
           "identity_all_zero" -> geAllZero,
           "identity_zero_lead_garbage" -> geZeroLeadGarbage,
           "generator" -> geGenerator)) {
      val candHex = "c0843d10010101d17300000001" + "07" + geHex
      out(s"box_ge_${label}_id", try {
        val c = ErgoBoxCandidate.serializer.parse(SigmaSerializer.startReader(Base16.decode(candHex).get))
        val b = new ErgoBox(c.value, c.ergoTree, c.additionalTokens, c.additionalRegisters,
          bytesToId(Array.fill(32)(7: Byte)), 3.toShort, c.creationHeight)
        "ACCEPT bytes=" + hex(b.bytes) + " id=" + hex(b.id)
      } catch { case e: Throwable => fail(e) })
    }

    // ── block-level: transactionsRoot is built over the canonical ids ────────
    out("transactions_root_true_leaf_vs_canonical", try {
      import org.ergoplatform.modifiers.history.BlockTransactions
      val hdrId = bytesToId(Array.fill(32)(9: Byte))
      val roots = Seq("01017f", "01010101").map { extHex =>
        val tx = ErgoTransactionSerializer.parseBytes(
          Base16.decode(txHexWithRawExtension(extHex)).get)
        hex(BlockTransactions(hdrId, 3.toByte, Seq(tx)).digest)
      }
      "roots=" + roots.mkString(",") + (if (roots.distinct.size == 1) " IDENTICAL" else " DIFFERENT")
    } catch { case e: Throwable => fail(e) })
  }
}

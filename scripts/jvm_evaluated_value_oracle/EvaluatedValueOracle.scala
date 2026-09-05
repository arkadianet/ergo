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

  def main(args: Array[String]): Unit = VersionContext.withVersions(3.toByte, 0.toByte) {
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

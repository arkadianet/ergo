//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.ergoplatform::ergo-wallet:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.15
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.nio.file.{Files, Path, Paths}
import com.typesafe.config.ConfigFactory
import io.circe.{Json, HCursor}
import io.circe.parser.parse
import org.ergoplatform._
import org.ergoplatform.modifiers.ErgoFullBlock
import org.ergoplatform.modifiers.history.{ADProofs, BlockTransactions}
import org.ergoplatform.modifiers.history.header.HeaderSerializer
import org.ergoplatform.modifiers.history.extension.ExtensionCandidate
import org.ergoplatform.modifiers.history.popow.NipopowAlgos
import org.ergoplatform.modifiers.mempool.{ErgoTransaction, ErgoTransactionSerializer}
import org.ergoplatform.nodeView.state._
import org.ergoplatform.settings._
import scorex.util.encode.Base16
import sigma.ast.{ErgoTree, SigmaPropConstant}
import sigma.serialization.SigmaSerializer
import scala.collection.JavaConverters._
import scala.util.Try

/** Oracle: production UtxoState.applyModifier, with an identity return-value observer. */
object BlockOracle {
  // ----- helpers -----
  val home: Path = Paths.get("scripts/jvm_block_oracle").toAbsolutePath
  def hex(bytes: Array[Byte]): String = Base16.encode(bytes)
  def bytes(value: String): Array[Byte] = Base16.decode(value).get
  def read(path: String): Json = {
    val raw = Files.newInputStream(Paths.get(path))
    val stream = if (path.endsWith(".gz")) new java.util.zip.GZIPInputStream(raw) else raw
    val source = scala.io.Source.fromInputStream(stream, "UTF-8")
    try parse(source.mkString).right.get finally source.close()
  }
  def write(path: String, json: Json): Unit = Files.write(Paths.get(path), (json.spaces2 + "\n").getBytes("UTF-8")) match { case _ => () }
  def field[A: io.circe.Decoder](c: HCursor, name: String): A = c.get[A](name).right.get
  def box(value: String): ErgoBox = ErgoBox.sigmaSerializer.parse(SigmaSerializer.startReader(bytes(value)))
  def tx(value: String): ErgoTransaction = ErgoTransactionSerializer.parseBytes(bytes(value))
  def extension(c: HCursor): ExtensionCandidate = ExtensionCandidate(
    field[Vector[Vector[String]]](c, "extension_fields").map { pair =>
      require(pair.size == 2, "extension field must be a key/value pair")
      bytes(pair.head) -> bytes(pair(1))
    })
  def encodeBlock(block: ErgoFullBlock): Json = Json.obj(
    "header_hex" -> Json.fromString(hex(block.header.bytes)),
    "transactions_hex" -> Json.arr(block.transactions.map(t => Json.fromString(hex(t.bytes))): _*),
    "extension_fields" -> Json.arr(block.extension.fields.map { case (k, v) =>
      Json.arr(Json.fromString(hex(k)), Json.fromString(hex(v)))
    }: _*),
    "ad_proofs_hex" -> Json.fromString(hex(block.adProofs.get.proofBytes)))
  def decodeBlock(json: Json): ErgoFullBlock = {
    val c = json.hcursor
    val h = HeaderSerializer.parseBytes(bytes(field[String](c, "header_hex")))
    ErgoFullBlock(h, BlockTransactions(h.id, h.version, field[Vector[String]](c, "transactions_hex").map(tx)),
      extension(c).toExtension(h.id), Some(ADProofs(h.id, scorex.crypto.authds.SerializedAdProof @@ bytes(field[String](c, "ad_proofs_hex")))))
  }
  def settings: ErgoSettings = {
    val resources = home.resolve(".work/source/src/main/resources").toFile
    val config = ConfigFactory.parseString("scorex.logging.level = ERROR\nergo.node.stateType = utxo")
      .withFallback(ConfigFactory.parseFile(new java.io.File(resources, "devnet.conf")))
      .withFallback(ConfigFactory.parseFile(new java.io.File(resources, "application.conf")))
      .withFallback(ConfigFactory.defaultReference()).resolve()
    ErgoSettingsReader.fromConfig(config)
  }
  def parameters(c: HCursor): Parameters = {
    val table = field[Map[String, Int]](c, "parameters").map { case (k, v) => k.toByte -> v }
    require(table.keySet == DevnetLaunchParameters.parametersTable.keySet, "complete devnet parameters required")
    require(table(Parameters.BlockVersion) >= 2 && table(Parameters.BlockVersion) <= 4)
    new Parameters(0, table, ErgoValidationSettingsUpdate.empty)
  }
  def withState[A](fixture: Json)(run: (UtxoState, ErgoSettings, Parameters) => A): A = {
    val c = fixture.hcursor
    require(field[Int](c, "schema_version") == 1)
    val boxes = field[Vector[String]](c, "parent_boxes_hex").map(box) :+ bootstrapBox(c)
    require(boxes.map(b => hex(b.id)).distinct.size == boxes.size, "duplicate parent boxes")
    val p = parameters(c)
    val directory = Files.createTempDirectory(home.resolve(".work"), "state-")
    val holder = BoxHolder(boxes)
    val prover = new scorex.crypto.authds.avltree.batch.BatchAVLProver[scorex.crypto.hash.Digest32, Algos.HF](32, None)
    holder.sortedBoxes.foreach(b => prover.performOneOperation(
      scorex.crypto.authds.avltree.batch.Insert(b.id, scorex.crypto.authds.ADValue @@ b.bytes)).get)
    val base = settings
    val s = base.copy(directory = directory.toString,
      chainSettings = base.chainSettings.copy(genesisStateDigestHex = hex(prover.digest)))
    val state = UtxoState.fromBoxHolder(holder, None, Files.createDirectory(directory.resolve("utxo")).toFile, s, p)
    try run(state, s, p) finally {
      state.store.close()
      scorex.db.LDBFactory.createKvDb(directory.resolve("snapshots").toString).close()
      val paths = Files.walk(directory)
      try paths.iterator.asScala.toVector.reverse.foreach(Files.delete) finally paths.close()
    }
  }
  def bootstrapBox(c: HCursor): ErgoBox = c.get[String]("bootstrap_box_hex").toOption.map(box).getOrElse(
    new ErgoBox(1000000000L, ErgoTree.fromProposition(SigmaPropConstant(sigma.data.TrivialProp.TrueProp)),
      sigma.Colls.emptyColl, Map.empty, scorex.util.bytesToId(Array.fill(32)(2.toByte)), 0.toShort, 0))
  def bootstrapTransaction(input: ErgoBox, height: Int): ErgoTransaction =
    ErgoTransaction(IndexedSeq(Input(input.id, sigma.interpreter.ProverResult(Array.emptyByteArray,
      sigma.interpreter.ContextExtension.empty))), IndexedSeq.empty,
      IndexedSeq(new ErgoBoxCandidate(input.value, input.ergoTree, height)))
  def proof(state: UtxoState, transactions: Seq[ErgoTransaction]) = {
    val operations = ErgoState.stateChanges(transactions).get.operations
    state.persistentProver.avlProver.generateProofForOperations(operations).get
  }
  def mine(state: UtxoState, s: ErgoSettings, p: Parameters,
           transactions: Seq[ErgoTransaction]): ErgoFullBlock = {
    val context = state.stateContext
    val links = new NipopowAlgos(s.chainSettings)
    val ext = p.toExtensionCandidate ++ context.validationSettings.toExtensionCandidate ++
      links.interlinksToExtension(links.updateInterlinks(context.lastHeaderOpt, context.lastExtensionOpt))
    val (ad, root) = proof(state, transactions)
    s.chainSettings.powScheme.proveBlock(context.lastHeaderOpt, p.blockVersion,
      s.chainSettings.initialNBits, root, ad, transactions,
      context.lastHeaderOpt.map(_.timestamp + 100).getOrElse(1000L), ext,
      Array.fill(3)(0.toByte), BigInt(1), 0L, 100000L).get
  }
  def checkEnvelope(block: ErgoFullBlock, state: UtxoState, s: ErgoSettings): Unit = {
    state.stateContext.lastHeaderOpt match {
      case Some(parent) => require(block.parentId == parent.id, "disconnected parent")
      case None => require(block.header.isGenesis && block.parentId ==
        org.ergoplatform.modifiers.history.header.Header.GenesisParentId, "invalid synthetic genesis parent")
    }
    require(block.header.nBits == s.chainSettings.initialNBits, "difficulty must be one")
    s.chainSettings.powScheme.validate(block.header).get
    require(block.header.transactionsRoot.sameElements(BlockTransactions.transactionsRoot(block.transactions, block.header.version)), "transactions root")
    require(block.header.extensionRoot.sameElements(block.extension.digest), "extension root")
    require(block.header.ADProofsRoot.sameElements(ADProofs.proofDigest(block.adProofs.get.proofBytes)), "proof root")
  }
  def parents(fixture: Json, initial: UtxoState, s: ErgoSettings): UtxoState = {
    val c = fixture.hcursor
    require(hex(initial.rootDigest) == field[String](c, "genesis_state_root"), "genesis state root mismatch")
    val insertionOrder = BoxHolder(field[Vector[String]](c, "parent_boxes_hex").map(box) :+
      bootstrapBox(c)).sortedBoxes.toVector.map(b => hex(b.bytes))
    require(field[Vector[String]](c, "initial_box_order_hex") == insertionOrder, "initial insertion order mismatch")
    val blocks = field[Vector[Json]](c, "parent_blocks").map(decodeBlock)
    require(blocks.nonEmpty && blocks.head.height == 1, "parent chain must start at height one")
    require(field[Vector[String]](c, "parent_headers_hex") == blocks.map(b => hex(b.header.bytes)))
    val state = blocks.foldLeft(initial) { (state, block) =>
      require(block.transactions.size == 1, "one bootstrap transaction per parent block")
      checkEnvelope(block, state, s)
      val (ad, root) = proof(state, block.transactions)
      require(ad.sameElements(block.adProofs.get.proofBytes) && root.sameElements(block.header.stateRoot), "parent proof mismatch")
      state.applyModifier(block, None)(_ => ()).get
    }
    field[Vector[String]](c, "parent_boxes_hex").map(box).foreach { expected =>
      require(state.boxById(expected.id).exists(_.bytes.sameElements(expected.bytes)), "parent fixture box was spent")
    }
    require(hex(state.rootDigest) == field[String](c, "parent_state_root"))
    require(state.stateContext.lastHeaders.size == 10, "complete header window required")
    require(state.stateContext.currentParameters.height > 0, "parent chain must process voted parameters at an epoch boundary")
    require(state.stateContext.currentParameters.parametersTable == parameters(c).parametersTable)
    state
  }
  def evaluate(fixture: Json): Json = withState(fixture) { (initial, s, _) =>
    val state = parents(fixture, initial, s)
    val block = decodeBlock(field[Json](fixture.hcursor, "block"))
    val before = hex(state.rootDigest)
    CostObservation.reset()
    val applied = Try(checkEnvelope(block, state, s)).flatMap(_ => state.applyModifier(block, None)(_ => ()))
    val results = CostObservation.results
    require(results.size <= 1, "one execTransactions call per target block")
    val cost = results.headOption.flatMap(_.payload)
    if (applied.isSuccess) require(results.size == 1 && cost.isDefined, "missing successful cost observation")
    if (applied.isFailure) require(hex(state.rootDigest) == before, "rejection changed state root")
    val error = applied.failed.toOption
    Json.obj("verdict" -> Json.fromString(if (applied.isSuccess) "Accept" else "Reject"),
      "failure_class" -> error.map(e => Json.fromString(e.getClass.getName)).getOrElse(Json.Null),
      "rejection_detail" -> error.map(e => Json.fromString(e.getMessage)).getOrElse(Json.Null),
      "sum_block_cost" -> cost.map(Json.fromLong).getOrElse(Json.Null),
      "exec_transactions_calls" -> Json.fromInt(results.size),
      "state_root_before" -> Json.fromString(before),
      "state_root_after" -> Json.fromString(hex(state.rootDigest)))
  }
  def build(request: Json): Json = withState(request) { (initial, s, p) =>
    val genesisRoot = hex(initial.rootDigest)
    val existing = request.hcursor.downField("parent_blocks").focus
    var state = initial
    val parentBlocks = existing match {
      case Some(value) =>
        state = parents(request, initial, s)
        value.asArray.get
      case None =>
        var bootstrap = bootstrapBox(request.hcursor)
        (1 to s.chainSettings.voting.votingLength).map { height =>
          val transaction = bootstrapTransaction(bootstrap, height)
          val block = mine(state, s, p, Seq(transaction))
          state = state.applyModifier(block, None)(_ => ()).get
          bootstrap = transaction.outputs.head
          encodeBlock(block)
        }.toVector
    }
    val transactions = field[Vector[String]](request.hcursor, "transactions_hex").map(tx)
    require(transactions.nonEmpty, "target needs at least one transaction")
    val block = mine(state, s, p, transactions)
    request.deepMerge(Json.obj(
      "genesis_state_root" -> Json.fromString(genesisRoot),
      "initial_box_order_hex" -> Json.arr(BoxHolder(field[Vector[String]](request.hcursor, "parent_boxes_hex").map(box) :+
        bootstrapBox(request.hcursor)).sortedBoxes.toVector.map(b => Json.fromString(hex(b.bytes))): _*),
      "bootstrap_box_hex" -> Json.fromString(hex(bootstrapBox(request.hcursor).bytes)),
      "parent_blocks" -> Json.arr(parentBlocks: _*),
      "parent_headers_hex" -> Json.arr(parentBlocks.map(b => b.hcursor.downField("header_hex").focus.get): _*),
      "parent_state_root" -> Json.fromString(hex(state.rootDigest)),
      "block" -> encodeBlock(block)))
  }
  def signP2pk(input: ErgoBox, height: Int): ErgoTransaction = {
    val secret = sigmastate.crypto.DLogProtocol.DLogProverInput(java.math.BigInteger.ONE)
    val unsigned = new UnsignedErgoLikeTransaction(IndexedSeq(new UnsignedInput(input.id)), IndexedSeq.empty,
      IndexedSeq(new ErgoBoxCandidate(input.value, input.ergoTree, height)))
    val prover = new ErgoLikeInterpreter with sigmastate.interpreter.ProverInterpreter {
      override type CTX = ErgoLikeContext
      override val secrets = IndexedSeq(secret)
    }
    val signature = prover.generateProof(secret.publicImage, unsigned.messageToSign, sigmastate.interpreter.HintsBag.empty)
    ErgoTransaction(IndexedSeq(Input(input.id, sigma.interpreter.ProverResult(signature,
      sigma.interpreter.ContextExtension.empty))), IndexedSeq.empty, unsigned.outputCandidates)
  }
  def smokeRequest(): Json = {
    val secret = sigmastate.crypto.DLogProtocol.DLogProverInput(java.math.BigInteger.ONE)
    val tree = ErgoTree.fromProposition(SigmaPropConstant(secret.publicImage))
    val input = new ErgoBox(1000000000L, tree, sigma.Colls.emptyColl, Map.empty,
      scorex.util.bytesToId(Array.fill(32)(1.toByte)), 0.toShort, 0)
    val signed = signP2pk(input, 128)
    Json.obj("schema_version" -> Json.fromInt(1),
      "parameters" -> Json.obj(DevnetLaunchParameters.parametersTable.toSeq.map { case (k, v) => k.toString -> Json.fromInt(v) }: _*),
      "parent_boxes_hex" -> Json.arr(Json.fromString(hex(input.bytes))),
      "transactions_hex" -> Json.arr(Json.fromString(hex(signed.bytes))))
  }
  def selfTest(fixture: Json): Json = {
    var count = 0
    def check(name: String)(test: => Boolean): Unit = {
      require(test, name)
      count += 1
      System.err.println("PASS " + name)
    }
    def seed(limit: Int): Json = Json.obj(
      "schema_version" -> Json.fromInt(1),
      "parent_boxes_hex" -> fixture.hcursor.downField("parent_boxes_hex").focus.get,
      "bootstrap_box_hex" -> fixture.hcursor.downField("bootstrap_box_hex").focus.get,
      "parameters" -> fixture.hcursor.downField("parameters").focus.get.deepMerge(Json.obj("4" -> Json.fromInt(limit))),
      "transactions_hex" -> fixture.hcursor.downField("transactions_hex").focus.get)
    // ----- happy path -----
    val accepted = evaluate(fixture)
    check("p2pk_block_valid_accepts")(field[String](accepted.hcursor, "verdict") == "Accept")
    check("p2pk_block_cost_observed_once")(field[Int](accepted.hcursor, "exec_transactions_calls") == 1)
    val atCap = evaluate(build(seed(12503)))
    check("p2pk_block_exact_cap_accepts")(field[String](atCap.hcursor, "verdict") == "Accept" &&
      field[Long](atCap.hcursor, "sum_block_cost") == 12503L)
    val first = tx(field[Vector[String]](fixture.hcursor, "transactions_hex").head)
    val second = signP2pk(first.outputs.head, 129)
    val twoRequest = seed(1000000).deepMerge(Json.obj("transactions_hex" ->
      Json.arr(Json.fromString(hex(first.bytes)), Json.fromString(hex(second.bytes)))))
    val two = evaluate(build(twoRequest))
    check("block_two_chained_p2pk_accumulates_25006")(field[String](two.hcursor, "verdict") == "Accept" &&
      field[Long](two.hcursor, "sum_block_cost") == 25006L && field[Int](two.hcursor, "exec_transactions_calls") == 1)
    // ----- round-trips -----
    val block = field[Json](fixture.hcursor, "block")
    check("block_sections_serialization_round_trips")(encodeBlock(decodeBlock(block)) == block)
    check("p2pk_block_rebuild_same_bytes")(field[Json](build(fixture).hcursor, "block") == block)
    check("p2pk_block_fresh_state_same_result")(evaluate(fixture) == accepted)
    // ----- error paths -----
    val overCap = evaluate(build(seed(12502)))
    check("p2pk_block_over_cap_rejects")(field[String](overCap.hcursor, "verdict") == "Reject" &&
      overCap.hcursor.downField("sum_block_cost").focus.contains(Json.Null) &&
      field[Int](overCap.hcursor, "exec_transactions_calls") == 1)
    check("p2pk_block_rejection_preserves_root")(field[String](overCap.hcursor, "state_root_before") ==
      field[String](overCap.hcursor, "state_root_after"))
    val brokenParents = fixture.deepMerge(Json.obj("parent_headers_hex" -> Json.arr()))
    check("parent_headers_mismatch_fails_setup")(Try(evaluate(brokenParents)).isFailure)
    val brokenBlock = fixture.deepMerge(Json.obj("block" -> Json.obj("ad_proofs_hex" -> Json.fromString("00"))))
    val badProof = evaluate(brokenBlock)
    check("block_proof_root_mismatch_rejects_before_execution")(
      field[String](badProof.hcursor, "verdict") == "Reject" && field[Int](badProof.hcursor, "exec_transactions_calls") == 0)
    val invalidSignature = ErgoTransaction(first.inputs.map(i => Input(i.boxId,
      sigma.interpreter.ProverResult(Array.fill(56)(0.toByte), sigma.interpreter.ContextExtension.empty))),
      first.dataInputs, first.outputCandidates)
    val invalidRequest = seed(1000000).deepMerge(Json.obj("transactions_hex" ->
      Json.arr(Json.fromString(hex(invalidSignature.bytes)))))
    val invalid = evaluate(build(invalidRequest))
    check("p2pk_invalid_signature_rejects_without_total")(field[String](invalid.hcursor, "verdict") == "Reject" &&
      invalid.hcursor.downField("sum_block_cost").focus.contains(Json.Null) &&
      field[Int](invalid.hcursor, "exec_transactions_calls") == 1)
    val wrongDigestFixture = withState(fixture) { (initial, s, _) =>
      val state = parents(fixture, initial, s)
      val original = decodeBlock(block)
      val changed = original.header.stateRoot.clone()
      changed(0) = (changed(0) ^ 1).toByte
      val bad = s.chainSettings.powScheme.proveBlock(state.stateContext.lastHeaderOpt,
        original.header.version, original.header.nBits, scorex.crypto.authds.ADDigest @@ changed,
        original.adProofs.get.proofBytes, original.transactions, original.header.timestamp,
        original.extension, original.header.votes, BigInt(1), 0L, 100000L).get
      fixture.deepMerge(Json.obj("block" -> encodeBlock(bad)))
    }
    val wrongDigest = evaluate(wrongDigestFixture)
    check("block_bad_digest_rejects_after_observed_cost")(field[String](wrongDigest.hcursor, "verdict") == "Reject" &&
      field[Long](wrongDigest.hcursor, "sum_block_cost") == 12503L)
    check("block_bad_digest_rolls_back_avl_updates")(field[String](wrongDigest.hcursor, "state_root_before") ==
      field[String](wrongDigest.hcursor, "state_root_after"))
    // ----- oracle parity -----
    val oracle = read("test-vectors/ergo-sigma/cost-ledger/fixtures/interpreter/p2pk.json")
    check("p2pk_script_task_3_4e_expected_403")(
      field[Long](oracle.hcursor.downField("expected").success.get, "total_block_cost") == 403L)
    check("p2pk_block_independent_expected_12503")(field[Long](accepted.hcursor, "sum_block_cost") == 12503L)
    Json.obj("selected" -> Json.fromInt(count), "executed" -> Json.fromInt(count),
      "failed" -> Json.fromInt(0), "skipped" -> Json.fromInt(0))
  }
  def main(args: Array[String]): Unit = {
    // Node logging is redirected so stdout contains only the result record.
    val stdout = System.out
    System.setOut(System.err)
    val sigmaJar = classOf[sigma.VersionContext].getProtectionDomain.getCodeSource.getLocation.toString
    require(sigmaJar.endsWith("sigma-state_2.12-6.0.6.jar"), "expected sigma-state 6.0.6: " + sigmaJar)
    val result = args.toList match {
      case "build" :: input :: output :: Nil =>
        val fixture = build(read(input)); write(output, fixture)
        Json.obj("built" -> Json.fromString(output))
      case "evaluate" :: input :: Nil => evaluate(read(input))
      case "self-test" :: input :: Nil => selfTest(read(input))
      case "smoke" :: output :: Nil =>
        val fixture = build(smokeRequest())
        val result = evaluate(fixture)
        // Task 3.4e measured P2PK = 5 eval + 398 crypto block units.
        // JVM transaction initialization is 10000 + 2000 input + 100 output.
        require(field[String](result.hcursor, "verdict") == "Accept", result.noSpaces)
        require(field[Long](result.hcursor, "sum_block_cost") == 12503L, result.noSpaces)
        write(output, fixture.deepMerge(Json.obj("expected" -> result)))
        result
      case _ => throw new IllegalArgumentException("build REQUEST OUTPUT | evaluate FIXTURE | smoke OUTPUT | self-test FIXTURE")
    }
    stdout.println(result.noSpaces)
  }
}

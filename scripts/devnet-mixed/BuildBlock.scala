//> using scala 2.12
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep io.circe::circe-parser:0.14.15
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.nio.file.{Files, Paths}
import com.typesafe.config.ConfigFactory
import io.circe.parser.parse
import io.circe.syntax._
import org.ergoplatform.http.api.ApiCodecs
import org.ergoplatform.mining.CandidateGenerator
import org.ergoplatform.modifiers.ErgoFullBlock
import org.ergoplatform.modifiers.history.popow.NipopowAlgos
import org.ergoplatform.modifiers.mempool.ErgoTransaction
import org.ergoplatform.nodeView.state.ErgoState
import org.ergoplatform.settings.ErgoSettingsReader
import scala.collection.JavaConverters._

/** Reconstruct the private devnet state independently; never open a live node database. */
object BuildBlock extends ApiCodecs {
  def main(args: Array[String]): Unit = {
    val request = parse(new String(Files.readAllBytes(Paths.get(args(0))), "UTF-8")).right.get.hcursor
    val config = ConfigFactory.parseFile(Paths.get("scripts/devnet-mixed/scala-node.conf").toFile)
      .withFallback(ConfigFactory.load()).resolve()
    val directory = Files.createTempDirectory(Paths.get("scripts/devnet-mixed/.work"), "builder-")
    val settings = ErgoSettingsReader.fromConfig(config).copy(directory = directory.toString)
    val initial = ErgoState.generateGenesisUtxoState(Files.createDirectory(directory.resolve("state")).toFile, settings)._1
    try {
      val state = request.get[Vector[ErgoFullBlock]]("parents").right.get.foldLeft(initial) {
        (state, block) => state.applyModifier(block, None)(_ => ()).get
      }
      val context = state.stateContext
      val supplied = request.get[Vector[ErgoTransaction]]("transactions").right.get
      val pk = sigmastate.crypto.DLogProtocol.DLogProverInput(java.math.BigInteger.ONE).publicImage
      val transactions = if (supplied.nonEmpty) supplied else CandidateGenerator.collectEmission(state, pk, context).toVector
      require(transactions.nonEmpty, "provide transactions when emission is exhausted")
      val operations = ErgoState.stateChanges(transactions).get.operations
      val (proof, root) = state.persistentProver.avlProver.generateProofForOperations(operations).get
      val links = new NipopowAlgos(settings.chainSettings)
      val interlinks = links.interlinksToExtension(links.updateInterlinks(context.lastHeaderOpt, context.lastExtensionOpt))
      val ext = if (context.lastHeaderOpt.isEmpty)
        context.currentParameters.toExtensionCandidate ++ context.validationSettings.toExtensionCandidate ++ interlinks
      else interlinks
      require(settings.chainSettings.initialDifficulty == BigInt(1), "difficulty must be one")
      val block = settings.chainSettings.powScheme.proveBlock(context.lastHeaderOpt,
        context.currentParameters.blockVersion, settings.chainSettings.initialNBits, root, proof,
        transactions, math.max(System.currentTimeMillis(), context.lastHeaderOpt.map(_.timestamp + 1).getOrElse(0L)),
        ext, Array.fill(3)(0.toByte), BigInt(1), 0L, 100000L).get
      settings.chainSettings.powScheme.validate(block.header).get
      state.applyModifier(block, None)(_ => ()).get
      Files.write(Paths.get(args(1)), (block.asJson.spaces2 + "\n").getBytes("UTF-8"))
    } finally {
      initial.store.close()
      scorex.db.LDBFactory.createKvDb(directory.resolve("snapshots").toString).close()
      val paths = Files.walk(directory)
      try paths.iterator.asScala.toVector.reverse.foreach(Files.delete) finally paths.close()
    }
  }
}

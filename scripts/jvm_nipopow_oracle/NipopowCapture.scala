// NiPoPoW Scala-oracle byte capture.
//
// Decodes a REST-captured mainnet NipopowProof JSON (the fixtures under
// `test-vectors/mainnet/nipopow/`) with the REAL Scala circe decoder
// (`NipopowProof.nipopowProofDecoder`) and re-emits it through the REAL
// Scala wire serializer (`NipopowProofSerializer`), producing genuine
// Scala-serializer bytes for the Rust codec parity test
// (`ergo-ser/tests/nipopow_scala_oracle.rs`).
//
// Usage:
//   scala-cli run NipopowCapture.scala -- \
//     <reference-resources-dir> <proof.json> <out.bin>
//
// where <reference-resources-dir> is the ergo reference checkout's
// `src/main/resources` (application.conf + mainnet.conf provide the
// mainnet ChainSettings exactly as the Scala node reads them).
//
// Dependency pinning matches scripts/jvm_serde_oracle (node = 6.0.2).
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2

import java.io.File
import java.nio.file.{Files, Paths}
import java.security.MessageDigest

import com.typesafe.config.ConfigFactory
import io.circe.parser.parse
import net.ceedubs.ficus.Ficus._
import net.ceedubs.ficus.readers.ArbitraryTypeReader._
import org.ergoplatform.modifiers.history.popow.{NipopowAlgos, NipopowProof, NipopowProofSerializer}
import org.ergoplatform.settings.{ChainSettings, ModifierIdReader, PowSchemeReaders, SettingsReaders}

object NipopowCapture extends PowSchemeReaders with ModifierIdReader with SettingsReaders {
  def main(args: Array[String]): Unit = {
    if (args.length < 3) {
      Console.err.println(
        "usage: NipopowCapture <resourcesDir> <proofJson> <outBin>"
      )
      sys.exit(1)
    }
    val resourcesDir = args(0)
    val jsonPath = args(1)
    val outPath = args(2)

    // Same layering as Scala's ChainSettingsReader, with mainnet.conf
    // as the network layer (the captured vectors are mainnet).
    val fullConfig = ConfigFactory
      .defaultOverrides()
      .withFallback(ConfigFactory.parseFile(new File(s"$resourcesDir/mainnet.conf")))
      .withFallback(ConfigFactory.parseFile(new File(s"$resourcesDir/application.conf")))
      .resolve()
    val chainSettings = fullConfig.as[ChainSettings]("ergo.chain")
    val algos = new NipopowAlgos(chainSettings)

    val raw = new String(Files.readAllBytes(Paths.get(jsonPath)), "UTF-8")
    val json = parse(raw).fold(e => sys.error(s"json parse: $e"), identity)
    val proof = NipopowProof
      .nipopowProofDecoder(algos)
      .decodeJson(json)
      .fold(e => sys.error(s"proof decode: $e"), identity)

    val serializer = new NipopowProofSerializer(algos)
    val bytes = serializer.toBytes(proof)
    Files.write(Paths.get(outPath), bytes)

    val sha = MessageDigest
      .getInstance("SHA-256")
      .digest(bytes)
      .map("%02x".format(_))
      .mkString
    println(s"OK bytes=${bytes.length} sha256=$sha")
    println(
      s"proof: m=${proof.m} k=${proof.k} prefix=${proof.prefix.size} " +
        s"suffixTail=${proof.suffixTail.size} continuous=${proof.continuous}"
    )

    // Sanity: Scala round-trip (parse own bytes, re-serialize, compare).
    val reparsed = serializer.parseBytes(bytes)
    val rebytes = serializer.toBytes(reparsed)
    require(java.util.Arrays.equals(bytes, rebytes), "Scala self-round-trip diverged")
    println("scala self-round-trip: OK")
  }
}

//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

// Reads header JSON (from Ergo node API) on stdin.
// Prints one line: <hwp_hex> <full_header_hex> <computed_id_hex>
//
// hwp_hex         = HeaderWithoutPow serialization
// full_header_hex = hwp_hex ++ PoW solution serialization
// computed_id_hex = Blake2b256(full_header_bytes)
//
// Usage: curl -s http://localhost:9053/blocks/{id}/header | scala-cli run PrintHeaderBytes.scala

import org.ergoplatform._
import sigma.serialization.{SigmaSerializer, GroupElementSerializer}
import scorex.util.encode.Base16
import scorex.crypto.hash.{Digest32, Blake2b256}
import scorex.crypto.authds.ADDigest
import scorex.util.ModifierId
import io.circe.parser.parse
import scala.io.StdIn

object PrintHeaderBytes {
  private def decodeGroupElement(hex: String): sigma.crypto.Ecp = {
    val bytes = Base16.decode(hex).get
    GroupElementSerializer.parse(SigmaSerializer.startReader(bytes))
  }

  def main(args: Array[String]): Unit = {
    val input = Iterator.continually(StdIn.readLine()).takeWhile(_ != null).mkString("\n")
    val doc = parse(input).fold(e => sys.error(s"JSON parse failed: $e"), identity)
    val c = doc.hcursor

    val version   = c.get[Int]("version").getOrElse(sys.error("missing version")).toByte
    val parentId  = ModifierId @@ c.get[String]("parentId").getOrElse(sys.error("missing parentId"))
    val adProofsRoot    = Digest32 @@ Base16.decode(c.get[String]("adProofsRoot").getOrElse(sys.error("missing adProofsRoot"))).get
    val stateRoot       = ADDigest @@ Base16.decode(c.get[String]("stateRoot").getOrElse(sys.error("missing stateRoot"))).get
    val transactionsRoot = Digest32 @@ Base16.decode(c.get[String]("transactionsRoot").getOrElse(sys.error("missing transactionsRoot"))).get
    val timestamp   = c.get[Long]("timestamp").getOrElse(sys.error("missing timestamp"))
    val nBits       = c.get[Long]("nBits").getOrElse(sys.error("missing nBits"))
    val height      = c.get[Int]("height").getOrElse(sys.error("missing height"))
    val extensionHash = Digest32 @@ Base16.decode(c.get[String]("extensionHash").getOrElse(sys.error("missing extensionHash"))).get
    val votes       = Base16.decode(c.get[String]("votes").getOrElse(sys.error("missing votes"))).get

    val pow = c.downField("powSolutions")
    val pk = decodeGroupElement(pow.get[String]("pk").getOrElse(sys.error("missing pk")))
    val w  = decodeGroupElement(pow.get[String]("w").getOrElse(sys.error("missing w")))
    val n  = Base16.decode(pow.get[String]("n").getOrElse(sys.error("missing n"))).get

    // d can be very large; circe decodes it as BigDecimal losslessly
    val dBigInt: scala.math.BigInt =
      pow.get[BigDecimal]("d").getOrElse(sys.error("missing d")).toBigInt

    val unparsedBytes = c.get[String]("unparsedBytes").toOption match {
      case Some(s) if s.nonEmpty => Base16.decode(s).get
      case _ => Array.emptyByteArray
    }

    val solution = new AutolykosSolution(pk, w, n, dBigInt)
    val header = new ErgoHeader(
      version, parentId, adProofsRoot, stateRoot, transactionsRoot,
      timestamp, nBits, height, extensionHash, solution, votes,
      unparsedBytes, Array.emptyByteArray
    )

    val hwpBytes = HeaderWithoutPowSerializer.toBytes(header)
    val powSerializer = if (version < 2) AutolykosSolution.sigmaSerializerV1
                        else AutolykosSolution.sigmaSerializerV2
    val powBytes = powSerializer.toBytes(solution)
    val fullHeaderBytes = hwpBytes ++ powBytes

    val hwpHex = Base16.encode(hwpBytes)
    val fullHex = Base16.encode(fullHeaderBytes)
    val computedId = Base16.encode(Blake2b256(fullHeaderBytes))

    println(s"$hwpHex $fullHex $computedId")
  }
}

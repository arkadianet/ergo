//> using scala "2.12.20"
//> using dep org.scorexfoundation::sigma-state:6.0.6

import io.circe.Json
import io.circe.syntax._
import org.ergoplatform.{ErgoAddressEncoder, P2PKAddress}
import org.ergoplatform.sdk.wallet.secrets.{DerivationPath, ExtendedSecretKey}
import scorex.util.encode.Base16

object LeadingZeroMaster extends App {
  val seedHex = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
  val seed = Base16.decode(seedHex).get
  val paths = Seq("m" -> Seq.empty[Int], "m/0'" -> Seq(Int.MinValue), "m/1" -> Seq(1), "m/44'/429'/0'/0/0" -> Seq(44 | Int.MinValue, 429 | Int.MinValue, Int.MinValue, 0, 0))
  val modes = Seq("modern", "legacy", "legacy-rust-trimmed-master")
  val vectors = modes.flatMap { mode =>
    val original = ExtendedSecretKey.deriveMasterKey(seed, mode != "modern")
    val root = if (mode == "legacy-rust-trimmed-master") {
      new ExtendedSecretKey(original.keyBytes.dropWhile(_ == 0), original.chainCode, true, DerivationPath.MasterPath)
    } else original
    paths.map { case (path, indices) =>
      val leaf = indices.foldLeft(root)(_.child(_))
      Json.obj("mode" -> mode.asJson, "path" -> path.asJson, "secret" -> Base16.encode(leaf.keyBytes).asJson,
        "publicKey" -> Base16.encode(leaf.publicKey.keyBytes).asJson, "chainCode" -> Base16.encode(leaf.chainCode).asJson,
        "address" -> P2PKAddress(leaf.publicImage)(ErgoAddressEncoder.Mainnet).toString.asJson)
    }
  }
  println(Json.obj("seed" -> seedHex.asJson, "vectors" -> vectors.asJson).spaces2)
}

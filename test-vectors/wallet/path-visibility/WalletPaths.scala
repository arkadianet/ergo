//> using scala "2.12.20"
//> using dep org.scorexfoundation::sigma-state:6.0.6

import io.circe.Json
import io.circe.syntax._
import org.ergoplatform.{ErgoAddressEncoder, P2PKAddress}
import org.ergoplatform.sdk.wallet.secrets.{DerivationPath, ExtendedSecretKey}
import scorex.util.encode.Base16

object WalletPaths extends App {
  val root = ExtendedSecretKey.deriveMasterKey(Base16.decode("000102030405060708090a0b0c0d0e0f").get, false)
  val cases = Seq(
    "master-only" -> Seq("m"),
    "master-pre-eip3" -> Seq("m", "m/1"),
    "master-eip3" -> Seq("m", "m/44'/429'/0'/0/0"),
    "master-eip3-three" -> Seq("m", "m/44'/429'/0'/0/0", "m/44'/429'/0'/0/1"),
    "non-master-eip3" -> Seq("m/1", "m/44'/429'/0'/0/0"),
    "master-eip3-account" -> Seq("m", "m/44'/429'/0'")
  )
  val output = cases.map { case (name, strings) =>
    val keys = strings.map { encoded =>
      val path = DerivationPath.fromEncoded(encoded).get
      path.decodedPath.tail.foldLeft(root)(_.child(_))
    }
    val paths = keys.map { key => Json.obj(
      "components" -> key.path.decodedPath.tail.map(_.toLong & 0xffffffffL).asJson,
      "isMaster" -> key.path.isMaster.asJson, "isEip3" -> key.path.isEip3.asJson,
      "publicKey" -> Base16.encode(key.publicKey.keyBytes).asJson,
      "address" -> P2PKAddress(key.publicImage)(ErgoAddressEncoder.Mainnet).toString.asJson)
    }
    val next = DerivationPath.nextPath(keys.toIndexedSeq, false).map(_.encoded).toOption
    Json.obj("name" -> name.asJson, "keys" -> paths.asJson, "nextPath" -> next.asJson)
  }
  println(Json.obj("sdk" -> "6.0.6".asJson, "cases" -> output.asJson).spaces2)
}

//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using dep org.ergoplatform::ergo-wallet:6.0.6
//> using repository "https://repo.maven.apache.org/maven2"

import io.circe.Json
import io.circe.syntax._
import org.ergoplatform.{ErgoAddressEncoder, P2PKAddress}
import org.ergoplatform.sdk.SecretString
import org.ergoplatform.sdk.wallet.secrets.ExtendedSecretKey
import org.ergoplatform.sdk.wallet.settings.EncryptionSettings
import org.ergoplatform.wallet.crypto.AES
import org.ergoplatform.wallet.mnemonic.Mnemonic
import org.ergoplatform.wallet.secrets.{EncryptedSecret, JsonSecretStorage}
import scorex.util.encode.Base16

object WalletOracle extends App {
  val settings = EncryptionSettings("HmacSHA512", 128000, 256)
  val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  val legacyPhrase = "race relax argue hair sorry riot there spirit ready fetch food hedgehog hybrid mobile pretty"
  def seed(words: String) = Mnemonic.toSeed(SecretString.create(words), None)
  def hex(bytes: Array[Byte]) = Base16.encode(bytes)
  def decode(bytes: String) = Base16.decode(bytes).get
  def address(words: String, legacy: Boolean): String = {
    val root = ExtendedSecretKey.deriveMasterKey(seed(words), legacy)
    val key = Seq(44 | 0x80000000, 429 | 0x80000000, 0x80000000, 0, 0).foldLeft(root)(_.child(_))
    P2PKAddress(key.publicImage)(ErgoAddressEncoder.Mainnet).toString
  }
  if (args.headOption.contains("verify")) {
    // JsonSecretStorage ignores the file's cipherParams and decrypts with the
    // node's configured settings, so verify against the stock node default
    // (application.conf: HmacSHA256, 128000, 256) that Rust now writes.
    val nodeDefault = EncryptionSettings("HmacSHA256", 128000, 256)
    val storage = new JsonSecretStorage(new java.io.File(args(1)), nodeDefault)
    storage.unlock(SecretString.create(args(2))).get
    assert(java.util.Arrays.equals(storage.secret.get.keyBytes, ExtendedSecretKey.deriveMasterKey(seed(phrase), false).keyBytes))
    println("scala-unlock-ok")
  } else {
    val ascii = "hello, scala parity test".getBytes("UTF-8")
    val vectors = Seq(
      ("correct horse battery staple", "000102030405060708090a0b0c0d0e0f", "0a0b0c0d0e0f000102030405", ascii),
      ("another password", "ffeeddccbbaa99887766554433221100", "aabbccddeeff001122334455", decode("deadbeef" * 40))
    ).map { case (password, salt, iv, plaintext) =>
      val (ciphertext, tag) = AES.encrypt(plaintext, password.toCharArray, decode(salt), decode(iv))(settings)
      Json.obj("password" -> password.asJson, "salt" -> salt.asJson, "iv" -> iv.asJson,
        "plaintext" -> hex(plaintext).asJson, "cipherText" -> hex(ciphertext).asJson, "authTag" -> hex(tag).asJson)
    }
    val salt = Array.tabulate[Byte](32)(_.toByte)
    val iv = Array.tabulate[Byte](12)(i => (i + 32).toByte)
    val (ciphertext, tag) = AES.encrypt(seed(phrase), "test-password".toCharArray, salt, iv)(settings)
    val modern = EncryptedSecret(ciphertext, salt, iv, tag, settings, Some(false)).asJson
    val legacy = EncryptedSecret(ciphertext, salt, iv, tag, settings, None).asJson
    val legacyKeys = Seq(44 | 0x80000000, 429 | 0x80000000, 0x80000000, 0, 0)
      .scanLeft(ExtendedSecretKey.deriveMasterKey(seed(legacyPhrase), true))(_.child(_))
      .zipWithIndex.map { case (key, depth) =>
        Json.obj("depth" -> depth.asJson, "secret" -> hex(key.keyBytes).asJson,
          "chainCode" -> hex(key.chainCode).asJson)
      }
    println(Json.obj("scalaVersion" -> "ergo-wallet 6.0.6 / sigma-state 6.0.6".asJson,
      "aes" -> vectors.asJson, "modern" -> modern, "legacy" -> legacy,
      "legacyDerivation" -> legacyKeys.asJson,
      "modernAddress" -> address(phrase, false).asJson,
      "pre1627Address" -> address(legacyPhrase, true).asJson,
      "post1627Address" -> address(legacyPhrase, false).asJson).spaces2)
  }
}

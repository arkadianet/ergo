//> using scala 2.12.20
//> using dep org.ergoplatform::ergo-appkit:6.0.1

import io.circe.Json
import io.circe.syntax._
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import org.ergoplatform.appkit.{SecretStorage => AppkitStorage}
import org.ergoplatform.sdk.SecretString
import org.ergoplatform.sdk.wallet.secrets.{DerivationPath, ExtendedSecretKey}
import org.ergoplatform.sdk.wallet.settings.EncryptionSettings
import org.ergoplatform.wallet.crypto.AES
import org.ergoplatform.wallet.mnemonic.Mnemonic
import org.ergoplatform.wallet.secrets.{EncryptedSecret, JsonSecretStorage}
import scorex.util.encode.Base16

/** Generate deterministic reference-wallet files, or unlock a Rust-written file in Appkit. */
object KeystoreOracle extends App {
  def hex(bytes: Array[Byte]): String = Base16.encode(bytes)
  val phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  val password = "lithos-interop-é-🔒"
  val seed = Mnemonic.toSeed(SecretString.create(phrase), None)
  val eip3Path = DerivationPath.fromEncoded("m/44'/429'/0'/0/0").get

  if (args.headOption.contains("verify")) {
    val storage = AppkitStorage.loadFrom(args(1))
    storage.unlock(password)
    val pre1627 = args.lift(2).exists(_.toBoolean)
    require(storage.getSecret.usePre1627KeyDerivation == pre1627, "derivation mode changed")
    val expected = ExtendedSecretKey.deriveMasterKey(seed, pre1627)
    require(storage.getSecret.publicImage == expected.publicImage, "Appkit recovered another master key")
    require(storage.getSecret.derive(eip3Path).publicImage == expected.derive(eip3Path).publicImage,
      "Appkit recovered another EIP-3 key")
    println("Appkit 6.0.1 unlocked Rust wallet; master public key = " + hex(storage.getSecret.publicImage.pkBytes))
  } else {
    require(AppkitStorage.DEFAULT_SETTINGS.prf == "HmacSHA256")
    require(AppkitStorage.DEFAULT_SETTINGS.c == 128000 && AppkitStorage.DEFAULT_SETTINGS.dkLen == 256)
    val salt = (0 until 32).map(_.toByte).toArray
    val iv = (32 until 44).map(_.toByte).toArray
    val vectors = Seq("HmacSHA256", "HmacSHA512").map { prf =>
      val settings = EncryptionSettings(prf, 128000, 256)
      val (ciphertext, prefix) = AES.encrypt(seed, password.toCharArray, salt, iv)(settings)
      require(AES.decrypt(ciphertext, password.toCharArray, salt, iv, prefix)(settings).get.sameElements(seed))
      val secret = EncryptedSecret(ciphertext, salt, iv, prefix, settings, Some(false))
      val temporary = Files.createTempFile("ergo-reference-keystore", ".json")
      try {
        Files.write(temporary, secret.asJson.noSpaces.getBytes(StandardCharsets.UTF_8))
        val storage = new JsonSecretStorage(temporary.toFile, settings)
        storage.unlock(SecretString.create(password)).get
        val publicKey = hex(storage.secret.get.publicImage.pkBytes)
        if (prf == "HmacSHA256") {
          val appkit = AppkitStorage.loadFrom(temporary.toFile)
          appkit.unlock(password)
          require(hex(appkit.getSecret.publicImage.pkBytes) == publicKey)
        }
        val key = SecretKeyFactory.getInstance("PBKDF2With" + prf)
          .generateSecret(new PBEKeySpec(password.toCharArray, salt, 128000, 256)).getEncoded
        Json.obj("prf" -> prf.asJson, "derived_key" -> hex(key).asJson,
          "master_public_key" -> publicKey.asJson, "encrypted_secret" -> secret.asJson)
      } finally Files.deleteIfExists(temporary)
    }
    println(Json.obj(
      "provenance" -> "Appkit 6.0.1 reference AES.encrypt/JsonSecretStorage.unlock and JVM SecretKeyFactory; scripts/jvm_keystore_oracle/KeystoreOracle.scala".asJson,
      "mnemonic" -> phrase.asJson, "password" -> password.asJson, "seed" -> hex(seed).asJson,
      "eip3_public_key" -> hex(ExtendedSecretKey.deriveMasterKey(seed, false).derive(eip3Path).publicImage.pkBytes).asJson,
      "legacy_eip3_public_key" -> hex(ExtendedSecretKey.deriveMasterKey(seed, true).derive(eip3Path).publicImage.pkBytes).asJson,
      "vectors" -> vectors.asJson).spaces2)
  }
}

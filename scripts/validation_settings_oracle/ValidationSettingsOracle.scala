//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7
//> using dep org.ergoplatform::ergo-core:6.0.7
import io.circe.Json
import org.ergoplatform.settings.{ErgoValidationSettings, ErgoValidationSettingsSerializer, ErgoValidationSettingsUpdate, ErgoValidationSettingsUpdateSerializer, ValidationRules}
import scorex.util.encode.Base16
import sigma.validation.{ChangedRule, ReplacedRule}
import scala.util.Try

object ValidationSettingsOracle {
  def main(args: Array[String]): Unit = {
    val chunks = Seq(0, 63, 64, 65, 127, 128, 129).map { size =>
      val update = if (size == 0) ErgoValidationSettingsUpdate.empty else {
        (0 to size).map { n => ErgoValidationSettingsUpdate(Seq.empty, Seq(1002.toShort -> ChangedRule(Array.fill(n)(1.toByte)))) }
          .find(u => ErgoValidationSettingsUpdateSerializer.toBytes(u).length == size).get
      }
      val settings = ErgoValidationSettings.initial.updated(update)
      val bytes = ErgoValidationSettingsSerializer.toBytes(settings)
      val fields = settings.toExtensionCandidate.fields.map { case (k, v) => Json.obj("key" -> Json.fromString(Base16.encode(k)), "value" -> Json.fromString(Base16.encode(v))) }
      Json.obj("size" -> Json.fromInt(size), "update" -> Json.fromString(Base16.encode(bytes)), "fields" -> Json.arr(fields: _*))
    }
    val statuses = Seq(1000, 1011, 1015, 1016, 1017, 1018, 1019, 1020).map { id =>
      val update = ErgoValidationSettingsUpdate(Seq.empty, Seq(id.toShort -> ReplacedRule(1000.toShort)))
      val bytes = ErgoValidationSettingsUpdateSerializer.toBytes(update)
      val parsedUpdate = Try(ErgoValidationSettingsUpdateSerializer.parseBytes(bytes))
      val parsedSettings = Try(ErgoValidationSettingsSerializer.parseBytes(bytes))
      Json.obj("id" -> Json.fromInt(id), "update" -> Json.fromString(Base16.encode(bytes)),
        "update_accept" -> Json.fromBoolean(parsedUpdate.isSuccess), "settings_accept" -> Json.fromBoolean(parsedSettings.isSuccess),
        "error" -> parsedSettings.failed.toOption.map(e => Json.fromString(e.getClass.getName)).getOrElse(Json.Null))
    }
    val out = Json.obj("ergo_core" -> Json.fromString("6.0.7"), "sigma_state" -> Json.fromString("6.0.7"),
      "disableable" -> Json.arr(ValidationRules.rulesSpec.toSeq.filter(_._2.mayBeDisabled).map(_._1.toInt).sorted.map(Json.fromInt): _*),
      "initial_sigma_ids" -> Json.arr(ErgoValidationSettings.initial.sigmaSettings.iterator.toSeq.map(_._1.toInt).sorted.map(Json.fromInt): _*),
      "soft_fork_1016" -> Json.fromBoolean(ErgoValidationSettings.initial.sigmaSettings.isSoftFork(sigma.validation.ValidationException("method", org.ergoplatform.validation.ValidationRules.CheckAndGetMethodV6, Seq.empty))),
      "core_soft_fork_1016" -> Json.fromBoolean(sigma.VersionContext.withVersions(3.toByte, 3.toByte) {
        org.ergoplatform.validation.ValidationRules.currentSettings.updated(1016.toShort, ReplacedRule(1000.toShort))
          .isSoftFork(sigma.validation.ValidationException("method", org.ergoplatform.validation.ValidationRules.CheckAndGetMethodV6, Seq.empty))
      }),
      "chunks" -> Json.arr(chunks: _*), "statuses" -> Json.arr(statuses: _*))
    java.nio.file.Files.write(java.nio.file.Paths.get(args(0)), out.spaces2.getBytes("UTF-8"))
  }
}

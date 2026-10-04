// Selected unchanged methods from pinned Ergo v6.0.5; Sigma settings/JitCost use the actual 6.0.6 jar.
import sigma.validation.{RuleStatus => SigmaRuleStatus, _}
import sigma.ast.JitCost
case class RuleStatus(isActive: Boolean)
case class ErgoValidationSettingsUpdate(rulesToDisable: Seq[Short],
                                        statusUpdates: Seq[(Short, sigma.validation.RuleStatus)]) {

  def ++(that: ErgoValidationSettingsUpdate): ErgoValidationSettingsUpdate = {
    val newRules = (rulesToDisable ++ that.rulesToDisable).distinct.sorted
    val nonReplacedStatusUpdates = statusUpdates.filter(s => !that.statusUpdates.exists(_._1 == s._1))
    val newStatusUpdates = (nonReplacedStatusUpdates ++ that.statusUpdates).sortBy(_._1)
    ErgoValidationSettingsUpdate(newRules, newStatusUpdates)
  }
}
case class ErgoValidationSettings(rules: Map[Short, RuleStatus], sigmaSettings: SigmaValidationSettings, updateFromInitial: ErgoValidationSettingsUpdate) {
  def updated(u: ErgoValidationSettingsUpdate): ErgoValidationSettings = {
    val newSigmaSettings = u.statusUpdates.foldLeft(sigmaSettings)((s, u) => s.updated(u._1, u._2))
    val newRules = updateRules(rules, u.rulesToDisable)
    val totalUpdate = updateFromInitial ++ u

    ErgoValidationSettings(newRules, newSigmaSettings, totalUpdate)
  }

  /**
    * Disable sequence of rules
    */
  private def updateRules(rules: Map[Short, RuleStatus],
                          toDisable: Seq[Short]): Map[Short, RuleStatus] = if (toDisable.nonEmpty) {
    rules.map { currentRule =>
      if (toDisable.contains(currentRule._1)) {
        currentRule._1 -> currentRule._2.copy(isActive = false)
      } else {
        currentRule
      }
    }
  } else {
    rules
  }


}
object CaptureValidationContext extends App {
  def status(s: SigmaRuleStatus): String = s match {
    case EnabledRule => "enabled"
    case DisabledRule => "disabled"
    case ReplacedRule(id) => "replaced:" + id
    case ChangedRule(bytes) => "changed:" + bytes.map(b => f"${b & 255}%02x").mkString
  }
  val initial = ErgoValidationSettings(Map(215.toShort -> RuleStatus(true), 409.toShort -> RuleStatus(true)), org.ergoplatform.validation.ValidationRules.currentSettings, ErgoValidationSettingsUpdate(Seq(), Seq()))
  val first = initial.updated(ErgoValidationSettingsUpdate(Seq(215.toShort), Seq(1007.toShort -> DisabledRule, 1008.toShort -> ChangedRule(Array[Byte](10,11)))))
  val empty = first.updated(ErgoValidationSettingsUpdate(Seq(), Seq()))
  val replaced = first.updated(ErgoValidationSettingsUpdate(Seq(409.toShort), Seq(1007.toShort -> ReplacedRule(1017.toShort), 1011.toShort -> DisabledRule)))
  Seq("first" -> first, "empty" -> empty, "replaced" -> replaced).foreach { case (name, value) =>
    val changes = value.updateFromInitial.statusUpdates.map { case (id, s) => id + "=" + status(s) }.mkString(",")
    val actual = value.updateFromInitial.statusUpdates.map { case (id, _) => id + "=" + status(value.sigmaSettings.getStatus(id).get) }.mkString(",")
    require(changes == actual)
    println("settings\t" + name + "\t" + value.updateFromInitial.rulesToDisable.mkString(",") + "\t" + changes)
  }
  Seq(8001091, 8001092, 214748364, 214748365).foreach { cap =>
    val result = try { JitCost.fromBlockCost(cap).value.toString } catch { case _: ArithmeticException => "overflow" }
    println("jit-cap\t" + cap + "\t" + result)
  }
}

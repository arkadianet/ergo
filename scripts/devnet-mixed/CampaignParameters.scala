//> using scala 2.12
//> using dep org.ergoplatform::ergo-core:6.0.5
//> using dep org.scorexfoundation::sigma-state:6.0.6
//> using repository ivy2Local
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
package org.ergoplatform.settings

/** Private campaign genesis only; validation and accounting remain the pinned JVM code. */
object Devnet60LaunchParameters extends Parameters(height = 0,
  parametersTable = Parameters.DefaultParameters
    .updated(Parameters.BlockVersion, org.ergoplatform.modifiers.history.header.Header.Interpreter60Version.toInt)
    .updated(4.toByte, 37509),
  proposedUpdate = ErgoValidationSettingsUpdate.empty)

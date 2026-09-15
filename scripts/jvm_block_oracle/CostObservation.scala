package org.ergoplatform.nodeView.state

import org.ergoplatform.validation.ValidationResult

/** Observes the production return value without modifying validation or cost. */
object CostObservation {
  var results: Vector[ValidationResult[Long]] = Vector.empty

  def observe(result: ValidationResult[Long]): ValidationResult[Long] = {
    results :+= result
    result
  }

  def reset(): Unit = { results = Vector.empty }
}

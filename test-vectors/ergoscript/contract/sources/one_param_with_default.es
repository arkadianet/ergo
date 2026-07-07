/**
 * Height-locked contract with a default.
 * @param threshold the minimum height
 */
@contract def heightLock(threshold: Int = 1000) = sigmaProp(HEIGHT > threshold)

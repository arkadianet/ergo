/**
 * Height-locked contract.
 * @param threshold the minimum height
 */
@contract def heightLock(threshold: Int) = sigmaProp(HEIGHT > threshold)

/**
 * A returns tag carrying text — a reference reject.
 * @returns a sigma proposition
 */
@contract def retText(threshold: Int) = sigmaProp(HEIGHT > threshold)

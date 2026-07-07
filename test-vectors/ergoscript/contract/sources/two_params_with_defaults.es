/**
 * Range check with default bounds.
 * @param lo lower bound
 * @param hi upper bound
 */
@contract def rangeCheck(lo: Int = 100, hi: Int = 1000) = sigmaProp(HEIGHT > lo && HEIGHT < hi)

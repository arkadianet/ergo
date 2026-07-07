/**
 * Range check on HEIGHT.
 * @param lo lower bound
 * @param hi upper bound
 */
@contract def rangeCheck(lo: Int, hi: Int) = sigmaProp(HEIGHT > lo && HEIGHT < hi)

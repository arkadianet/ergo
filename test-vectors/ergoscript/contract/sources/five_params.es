/**
 * Five params — exercises the deferred HashMap-order path.
 * @param a a
 * @param b b
 * @param c c
 * @param d d
 * @param e e
 */
@contract def gate5(a: Int, b: Int, c: Int, d: Int, e: Int) = sigmaProp(a + b + c + d + e > 0)

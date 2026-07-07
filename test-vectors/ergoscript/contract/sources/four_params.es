/**
 * Four-parameter arithmetic gate.
 * @param a first
 * @param b second
 * @param c third
 * @param d fourth
 */
@contract def gate4(a: Int, b: Int, c: Int, d: Int) = sigmaProp(a + b + c + d > 0)

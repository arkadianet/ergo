/**
 * Four params; only `d` is read twice, in two sibling `&&` right arms.
 */
@contract def reuseAnd4(a: Int, b: Int, c: Int, d: Int) = sigmaProp(a > 0 && b > 1 && c + d > 0 && d > 1)

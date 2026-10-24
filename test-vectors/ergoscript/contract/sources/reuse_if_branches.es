/**
 * One param read in both branches of an `if` (each branch is its own thunk).
 */
@contract def reuseIf(a: Int) = sigmaProp(if (HEIGHT > 5) a > 1 else a < 9)

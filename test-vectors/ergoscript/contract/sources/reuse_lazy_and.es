/**
 * One param read in two sibling `&&` right arms: Scala builds the placeholder
 * at the root, so both arms share it and it becomes one ValDef.
 */
@contract def reuseAnd(a: Int) = sigmaProp(HEIGHT > 0 && a > 1 && a < 9)

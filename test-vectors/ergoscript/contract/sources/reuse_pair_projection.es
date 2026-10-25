/**
 * A tuple param projected in two sibling `&&` right arms: the shared
 * placeholder is the projections' receiver.
 */
@contract def reusePair(x: Int, pair: (Int, Long)) = sigmaProp(x > 0 && pair._1 > 0 && pair._2 > 0L)

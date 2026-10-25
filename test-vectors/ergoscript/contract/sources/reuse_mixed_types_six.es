/**
 * Six params of richer types; the tuple param is projected in two sibling
 * `&&` right arms.
 */
@contract def reuseTypes6(ge: GroupElement, bi: BigInt, pair: (Int, Long), nested: Coll[Coll[Byte]], b: Byte, sh: Short) = proveDlog(ge) && sigmaProp(bi > 0.toBigInt && pair._1 > 0 && pair._2 > 0L && nested.size > 0 && b > 0.toByte && sh > 0.toShort)

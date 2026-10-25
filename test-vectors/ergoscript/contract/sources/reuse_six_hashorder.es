/**
 * Six params, three of them read twice, one only across `&&` right arms
 * (`echo`); exercises the shared-placeholder ValDefs under Scala 2.12
 * HashTrieMap placeholder order.
 */
@contract def reuse6(alpha: Int, bravo: Int, charlie: Int, delta: Int, echo: Int, foxtrot: Int) = sigmaProp(foxtrot > alpha && alpha > foxtrot - 1 && bravo + charlie + delta + echo > 0 && echo > 1)

/**
 * Two parameters share a name — Scala rejects (uniqueness require).
 */
@contract def dupNames(a: Int, a: Long) = sigmaProp(HEIGHT > a)

/**
 * One defaulted, one not.
 * @param base base value
 * @param delta the increment
 */
@contract def mixed(base: Long, delta: Long = 5L) = sigmaProp(base + delta > 0L)

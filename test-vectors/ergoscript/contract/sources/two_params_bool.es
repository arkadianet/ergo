/**
 * Combines a parameter flag with a height check.
 * @param enabled whether the lock is active
 * @param threshold the minimum height
 */
@contract def flagLock(enabled: Boolean, threshold: Int) = sigmaProp(enabled && HEIGHT > threshold)

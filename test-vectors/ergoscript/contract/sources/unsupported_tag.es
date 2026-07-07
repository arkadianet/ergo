/**
 * Uses an unsupported tag.
 * @author someone
 * @param threshold the minimum height
 * @returns
 */
@contract def tagged(threshold: Int) = sigmaProp(HEIGHT > threshold)

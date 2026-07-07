/**
 * String default containing a comma.
 * @param s a label
 */
@contract def strComma(s: String = "a,b") = sigmaProp(HEIGHT > 1000)

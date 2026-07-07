/**
 * Mixed params with a string default carrying a comma and paren.
 */
@contract def strMulti(a: Int = 1, s: String = "x,y)", b: Int = 2) = sigmaProp(HEIGHT > a && HEIGHT > b)

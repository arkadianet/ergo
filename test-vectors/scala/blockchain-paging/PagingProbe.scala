//> using scala "2.12.20"

// Source-only route-expression probe, not a running node or consensus oracle.
// Ergo v6.0.5, BlockchainApiRoute.scala getTxRange/getBoxRange:
// base = global counter - offset; numeric index = base - limit + i; reverse.
object PagingProbe extends App {
  def indices(counter: Long, offset: Int, limit: Int): Seq[Long] = {
    val base: Long = counter - offset
    val ids = new Array[Long](limit)
    var i = 0
    while (i < limit) {
      ids(i) = base - limit + i
      i += 1
    }
    ids.reverse.toSeq
  }
  val cases = Seq((10L, 0, 3), (10L, 2, 3), (3L, 0, 3), (3L, 1, 2), (2L, 0, 2), (2L, 1, 1), (2L, 0, 0))
  val json = cases.map { case (counter, offset, limit) =>
    s"""{"counter":$counter,"offset":$offset,"limit":$limit,"indices":[${indices(counter, offset, limit).mkString(",") }]}"""
  }.mkString("[", ",", "]")
  println(json)
}

// Finite adapter: unchanged methods selected from pinned v6.0.5 source.
// IDs use hex strings, with equality/contains supplied by ordinary Scala collections.
object AdapterTypes { type ModifierId = String }
import AdapterTypes._
sealed trait PeerChainStatus
case object Equal extends PeerChainStatus
case object Older extends PeerChainStatus
case object Younger extends PeerChainStatus
case object Fork extends PeerChainStatus
case class ErgoSyncInfoV1(lastHeaderIds: Seq[String])
object PreGenesisHeader { val id = "00" * 32 }
object ErgoSyncInfo { val MaxBlockIds = 1000 }
class ReferenceCompare(val bestHeaderIdOpt: Option[String], val known: Set[String]) {
  def contains(id: String): Boolean = known.contains(id)
  def compareV1(info: ErgoSyncInfoV1): PeerChainStatus = {
    bestHeaderIdOpt match {
      case Some(id) if info.lastHeaderIds.lastOption.contains(id) =>
        //Our best header is the same as other node best header
        Equal
      case Some(id) if info.lastHeaderIds.contains(id) =>
        //Our best header is in other node best chain, but not at the last position
        Older
      case Some(_) if info.lastHeaderIds.isEmpty =>
        //Other history is empty, our contain some headers
        Younger
      case Some(_) =>
        if (info.lastHeaderIds.view.reverse.exists(m => contains(m) || m == PreGenesisHeader.id)) {
          //We are on different forks now.
          Fork
        } else {
          //We don't have any of id's from other's node sync info in history.
          //We don't know whether we can sync with it and what blocks to send in Inv message.
          //Assume it is older and far ahead from us
          Older
        }
      case None if info.lastHeaderIds.isEmpty =>
        //Both nodes do not keep any blocks
        Equal
      case None =>
        //Our history is empty, other contain some headers
        Older
    }
  }
}
class ReferenceProducer(val headersHeight: Int) {
  def bestHeaderIdAtHeight(h: Int): Option[String] = Some(f"$h%064x")
  def isEmpty: Boolean = headersHeight == 0
  def syncInfoV1: ErgoSyncInfoV1 = {
    /*
     * Return last count headers from best headers chain if exist or chain up to genesis otherwise
     */
    def lastHeaderIds(count: Int): IndexedSeq[ModifierId] = {
      val currentHeight = headersHeight
      val from = Math.max(currentHeight - count + 1, 1)
      val res = (from to currentHeight).flatMap{h =>
        bestHeaderIdAtHeight(h)
      }
      if(from == 1) {
        PreGenesisHeader.id +: res
      } else {
        res
      }
    }

    if (isEmpty) {
      ErgoSyncInfoV1(Nil)
    } else {
      ErgoSyncInfoV1(lastHeaderIds(ErgoSyncInfo.MaxBlockIds))
    }
  }
}
object CaptureCompareV1 {
  def main(args: Array[String]): Unit = {
    val our = "05" * 32
    val cases = Seq(
      ("tip_last", Seq("01" * 32, our), Set.empty[String]),
      ("local_tip_at_oldest_endpoint", Seq(our, "09" * 32), Set.empty[String]),
      ("local_tip_interior", Seq("01" * 32, our, "09" * 32), Set.empty[String]),
      ("known_fork", Seq("01" * 32, "09" * 32), Set("01" * 32)),
      ("no_overlap", Seq("09" * 32), Set.empty[String]),
      ("empty_peer", Seq.empty[String], Set.empty[String]),
      ("pregenesis_overlap", Seq(PreGenesisHeader.id, "09" * 32), Set.empty[String])
    )
    cases.foreach { case (name, ids, known) =>
      val status = new ReferenceCompare(Some(our), known).compareV1(ErgoSyncInfoV1(ids))
      println(Seq(name, ids.mkString(","), our, known.toSeq.sorted.mkString(","), status.toString).mkString("\t"))
    }
    Seq(0, 3, 1000, 1001).foreach { height =>
      val ids = new ReferenceProducer(height).syncInfoV1.lastHeaderIds
      println(Seq("producer", height.toString, ids.length.toString, ids.headOption.getOrElse("-"), ids.lastOption.getOrElse("-")).mkString("\t"))
    }
  }
}

object CaptureVotingThresholds {
  def main(args: Array[String]): Unit = {
    println("network\tvoting_length\tsoft_fork_epochs\tthreshold\tvotes_zero\tminus\tat\tplus")
    for ((network, length) <- Seq(("mainnet", 1024), ("testnet", 128), ("devnet", 33554432), ("custom", 100000000))) {
      val settings = org.ergoplatform.settings.VotingSettings(length, 32, 32, 0, "")
      val threshold = length * 32 * 9 / 10
      println(Seq(network, length, 32, threshold, settings.softForkApproved(0),
        settings.softForkApproved(threshold - 1), settings.softForkApproved(threshold),
        settings.softForkApproved(threshold + 1)).mkString("\t"))
    }
  }
}

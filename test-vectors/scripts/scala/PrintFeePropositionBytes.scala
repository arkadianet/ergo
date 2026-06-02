//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0

// Regeneration helper for `test-vectors/mainnet/fee_proposition.hex`.
//
// Emits the exact bytes of `ErgoTreePredef.feeProposition(delta)` as
// defined at
//   sigmastate-interpreter/interpreter/shared/src/main/scala/org/ergoplatform/ErgoTreePredef.scala:62
// and relied upon by `MonetarySettings.feePropositionBytes`
// (interpreter/shared/src/main/scala/org/ergoplatform/settings/MonetarySettings.scala).
//
// Mainnet uses `delta = 720` (the default). Pass a different int on
// the command line for testnet / integration test corpora.
//
// Usage (the cd matters — the redirection path is relative to this
// script's directory):
//   cd test-vectors/scripts/scala
//   scala-cli run PrintFeePropositionBytes.scala > ../../mainnet/fee_proposition.hex
//
// The Rust side in `ergo-mempool/src/validator.rs` pins a byte-for-
// byte equal constant and has a unit test asserting
// `MAINNET_FEE_PROPOSITION_BYTES == read(fee_proposition.hex)`.
// Regenerating this file without updating the Rust constant will
// cause that unit test to fail — which is the intended guard: if
// Scala's serialization of feeProposition ever changes, we find out
// immediately instead of silently diverging.

import org.ergoplatform.ErgoTreePredef
import scorex.util.encode.Base16

object PrintFeePropositionBytes {
  def main(args: Array[String]): Unit = {
    val delta: Int = args.headOption.map(_.toInt).getOrElse(720)
    val tree = ErgoTreePredef.feeProposition(delta)
    // `tree.bytes` is the canonical ErgoTree serialization — same
    // bytes MonetarySettings exposes as `feePropositionBytes` and
    // same bytes ErgoMemPool.process compares outputs against.
    println(Base16.encode(tree.bytes))
  }
}

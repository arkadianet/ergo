// Independent sigma-state 6.0.7 proof verification oracle.
// Usage: scala-cli run SigmaProofOracle.scala --server=false --jvm system -- cases <file.tsv>
//   file lines: name<TAB>prop_hex<TAB>proof_hex<TAB>msg_hex   (prop = SigmaBoolean.serializer bytes)
//   output:     name<TAB>verifySignature<TAB>diag
//        ge <hex> ...        -> GroupElementSerializer.parse + re-encode
//        exp <hex33> <dec>   -> CGroupElement.exp(k) encoding
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7

import org.ergoplatform.ErgoLikeInterpreter
import scorex.util.encode.Base16
import sigma.data.{CBigInt, CGroupElement, SigmaBoolean}
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import sigmastate.{NoProof, UncheckedSigmaTree}
import sigmastate.FiatShamirTree
import sigmastate.crypto.CryptoFunctions
import sigmastate.interpreter.CErgoTreeEvaluator
import sigma.serialization.SigSerializer
import sigma.util.CollectionUtil
import scala.util.{Failure, Success, Try}
import scala.io.Source

object SigmaProofOracle {
  object V extends ErgoLikeInterpreter
  implicit val E: CErgoTreeEvaluator = null

  def hex(s: String): Array[Byte] = if (s.isEmpty) Array.emptyByteArray else Base16.decode(s).get

  def diag(sb: SigmaBoolean, proof: Array[Byte], msg: Array[Byte]): String = {
    Try {
      SigSerializer.parseAndComputeChallenges(sb, proof) match {
        case NoProof => "NoProof"
        case sp: UncheckedSigmaTree =>
          val newRoot = V.computeCommitments(sp).get.asInstanceOf[UncheckedSigmaTree]
          val fs = FiatShamirTree.toBytes(newRoot)
          val expected = CryptoFunctions.hashFn(CollectionUtil.concatArrays(fs, msg))
          s"rootChallenge=${Base16.encode(newRoot.challenge.toArray)} expected=${Base16.encode(expected)} fs=${Base16.encode(fs)}"
      }
    } match {
      case Success(s) => s
      case Failure(t) => s"EXC ${t.getClass.getName}: ${t.getMessage}"
    }
  }

  def main(args: Array[String]): Unit = args(0) match {
    case "misc" =>
      for (line <- Source.fromFile(args(1)).getLines() if line.trim.nonEmpty && !line.startsWith("#")) {
        main(line.trim.split("\\s+"))
      }
    case "cases" =>
      for (line <- Source.fromFile(args(1)).getLines() if line.trim.nonEmpty && !line.startsWith("#")) {
        val parts = line.split("\t", -1)
        val name = parts(0)
        val res = Try {
          val sb = SigmaBoolean.serializer.parse(SigmaSerializer.startReader(hex(parts(1))))
          val proof = hex(parts(2)); val msg = hex(parts(3))
          val stdout = System.out
          val (ok, diagnostics) = try {
            System.setOut(System.err)
            Console.withOut(System.err) {
              (V.verifySignature(sb, msg, proof), diag(sb, proof, msg))
            }
          } finally System.setOut(stdout)
          s"$ok\t$diagnostics"
        } match {
          case Success(s) => s
          case Failure(t) => s"EXC\t${t.getClass.getName}: ${t.getMessage}"
        }
        System.out.println(s"$name\t$res")
      }
    case "ge" =>
      for (h <- args.drop(1)) {
        val r = Try {
          val p = GroupElementSerializer.parse(SigmaSerializer.startReader(hex(h)))
          Base16.encode(GroupElementSerializer.toBytes(p))
        } match {
          case Success(s) => s"OK $s"
          case Failure(t) => s"EXC ${t.getClass.getName}: ${t.getMessage}"
        }
        println(s"$h\t$r")
      }
    case "exp" =>
      val p = GroupElementSerializer.parse(SigmaSerializer.startReader(hex(args(1))))
      val k = new java.math.BigInteger(args(2))
      val r = Try(Base16.encode(CGroupElement(p).exp(CBigInt(k)).getEncoded.toArray)) match {
        case Success(s) => s"OK $s"; case Failure(t) => s"EXC ${t.getClass.getName}: ${t.getMessage}"
      }
      println(s"exp ${args(1)} ${args(2)}\t$r")
    case "mul" =>
      val p = GroupElementSerializer.parse(SigmaSerializer.startReader(hex(args(1))))
      val q = GroupElementSerializer.parse(SigmaSerializer.startReader(hex(args(2))))
      println(s"mul\t${Base16.encode(CGroupElement(p).multiply(CGroupElement(q)).getEncoded.toArray)}")
  }
}

// Fixture helper: compile ErgoScript snippets with sigma-state 6.0.7 and print bytes.
// Usage: scala-cli run Compile.scala -- <specfile>
// Spec file lines: <mode>\t<name>\t<version>\t<code>
//   mode = tree   -> ErgoTree bytes (header version <version>; size flag set when version>0)
//   mode = treeseg-> ErgoTree bytes with constant segregation
//   mode = value  -> ValueSerializer bytes of the compiled expression (no header)
//> using repository "ivy2Local"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.7

import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.ast._
import sigma.ast.syntax._
import sigma.serialization.{ErgoTreeSerializer, ValueSerializer}
import scorex.util.encode.Base16
import sigma.VersionContext
import scala.util.{Try, Success, Failure}

object CompileSerializationFixtures {
  def main(args: Array[String]): Unit = {
    val lines = scala.io.Source.fromFile(args(0)).getLines().filter(l => l.nonEmpty && !l.startsWith("#")).toVector
    lines.foreach { line =>
      val parts = line.split("\t", 4)
      val (mode, name, version, code) = (parts(0), parts(1), parts(2).toByte, parts(3))
      val res = Try {
        VersionContext.withVersions(3, version) {
          implicit val IR = new CompiletimeIRContext
          val compiler = new SigmaCompiler(0.toByte)
          val tree = compiler.compile(Map.empty, code).buildTree
          mode match {
            case "value" => Base16.encode(ValueSerializer.serialize(tree))
            case "tree" =>
              val header0 = ErgoTree.headerWithVersion(ErgoTree.ZeroHeader, version)
              val header = if (version > 0) ErgoTree.setSizeBit(header0) else header0
              val et = ErgoTree.fromProposition(header, tree.asSigmaProp)
              Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(et))
            case "treeseg" =>
              val header0 = ErgoTree.headerWithVersion(ErgoTree.ZeroHeader, version)
              val header = if (version > 0) ErgoTree.setSizeBit(header0) else header0
              val et = ErgoTree.withSegregation(header, tree.asSigmaProp)
              Base16.encode(ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(et))
          }
        }
      }
      res match {
        case Success(hex) => println(s"$name\t$hex")
        case Failure(e) => println(s"$name\tERROR\t${e.getClass.getName}: ${e.getMessage}")
      }
    }
  }
}

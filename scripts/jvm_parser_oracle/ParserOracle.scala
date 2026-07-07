// JVM reference PARSER oracle for the ergo-compiler M1 corpus-parity test.
//
// Reads `parse <hex-of-utf8-source>` lines on stdin and, for each, runs the REAL
// Scala reference parser (`sigmastate.lang.SigmaParser`, sigma-state 6.0.2 — the
// version the consensus node runs) and prints one line:
//   ACCEPT               the source parsed to a Value AST
//   REJECT <line>:<col>  the source was refused; 1-based position of the failure
//   ERR    <message>     the oracle could not handle the line (bad hex / bad verb)
//
// The Rust harness (ergo-compiler/tests/corpus_smoke.rs) feeds the same UTF-8
// source bytes (hex-encoded) to its own `ergo_compiler::parse(src, 3)` and diffs
// the verdicts. An ACCEPT/REJECT mismatch — or a matching REJECT at a different
// line:col — is a parser divergence to fix in parse.rs/token.rs.
//
// ── artifact resolution (resolved empirically 2026-07) ────────────────────────
// `sigmastate.lang.SigmaParser` lives in sigma-state's `parsers` sub-module. In
// the reference checkout that module carries `publish / skip := true`, but the
// PUBLISHED `org.scorexfoundation::sigma-state:6.0.2` artifact on Maven Central
// DOES ship the parsers classes — a bare dep on sigma-state:6.0.2 exposes
// `SigmaParser`, `sigma.ast.SourceContext`, and `sigma.exceptions.CompilerException`
// with NO local publishLocal and NO extra source roots. So (unlike ErgoSerdeOracle,
// which needs ergo-core published locally) this oracle needs only sigma-state and
// resolves entirely from Maven Central. The GitLab repository directive is retained
// for parity with ErgoSerdeOracle.scala:19-22 but is not required here.
//
// Position semantics mirror sc/.../SigmaCompiler.scala:67 exactly:
//   Parsed.Failure f            -> SourceContext.fromParserFailure(f)   (line:col)
//   thrown ParserException      -> its Option[SourceContext] when present, else 0:0
//   thrown NumberFormatException / MatchError / other -> 0:0
// The reference reports 1-based (line, column); ergo_compiler::ParseError::line_col
// is the twin.
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2

import scala.io.StdIn
import scorex.util.encode.Base16
import sigmastate.lang.SigmaParser
import sigma.VersionContext
import sigma.ast.SourceContext
import sigma.exceptions.CompilerException
import fastparse.Parsed

object ParserOracle {
  private def loc(sc: SourceContext): String = sc.line + ":" + sc.column

  // Run the parser under the SAME version the Rust twin uses: ergo_compiler
  // parses the corpus with `parse(src, tree_version = 3)`, so the type grammar's
  // predef table must be the v6 set. `SType.allPredefTypes` returns the v6 set
  // (which includes SUnsignedBigInt) iff `VersionContext.current.isV3OrLater-
  // ErgoTreeVersion` — i.e. ergoTreeVersion >= 3 (SType.scala:116-118). WITHOUT
  // this the parser runs at the DEFAULT context (activated=1, ergoTree=1, v4.x),
  // where `UnsignedBigInt` is not a predef type and resolves to "Unsupported
  // type" — a false REJECT vs the Rust `parse(src, 3)`, e.g. on the v6 contract
  // CurveTreeVerifier-v6.es. activatedVersion must be >= ergoTreeVersion (the
  // VersionContext invariant), so both are 3.
  private val V6: (Byte, Byte) = (3.toByte, 3.toByte)

  def handle(hexStr: String): String =
    Base16.decode(hexStr) match {
      case scala.util.Failure(_) => "ERR not-hex"
      case scala.util.Success(bytes) =>
        val source = new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
        try
          // SigmaParser appends `~ End`, so trailing input is a Failure, not a
          // partial ACCEPT. Build actions (mkUnaryOp/mkBinaryOp/...) throw
          // ParserException mid-parse, so the call itself may throw — caught below.
          VersionContext.withVersions(V6._1, V6._2) {
            SigmaParser(source) match {
              case _: Parsed.Success[_] => "ACCEPT"
              case f: Parsed.Failure    => "REJECT " + loc(SourceContext.fromParserFailure(f))
            }
          }
        catch {
          case e: CompilerException =>
            e.source match {
              case Some(sc) => "REJECT " + loc(sc)
              case None     => "REJECT 0:0"
            }
          // NumberFormatException (literal overflow), MatchError (unhandled build
          // shape), and any other throwable are refusals with no position.
          case _: Throwable => "REJECT 0:0"
        }
    }

  def main(args: Array[String]): Unit = {
    var line = StdIn.readLine()
    while (line != null) {
      val t = line.trim
      if (t.nonEmpty) {
        val parts = t.split("\\s+", 2)
        println(
          if (parts.length == 2 && parts(0) == "parse") handle(parts(1))
          else "ERR bad-line"
        )
      }
      line = StdIn.readLine()
    }
  }
}

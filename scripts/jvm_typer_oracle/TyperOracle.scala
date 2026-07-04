// JVM reference TYPER oracle for the ergo-compiler M2 typed-tree parity test.
//
// Reads verb lines on stdin and, for each, runs the REAL Scala reference
// binder+typer (sigma-state 6.0.2 — the version the consensus node runs) and
// prints ONE line:
//   OK <sexpr>                        typed tree (canonical s-expression, see §4 below)
//   REJECT <line>:<col> <ExClass>     binder/typer refused (1-based pos, else 0:0)
//   ERR <message>                     the oracle could not handle the line
//
// Verbs (hex is Base16 of the UTF-8 source):
//   tc  <hex>     typecheck with an EMPTY script env
//   tce <hex>     typecheck with the DEMO env (free vars a,b,col1,col2,g1,g2,g3,n1,bb1,bb2)
//   tcs <hex>     typecheck with the SigmaTyperTest env (LangTests.scala:52-69):
//                 x,y:Int; c1,c2:Boolean; height1,height2:Long; b1,b2:Byte;
//                 arr1,arr2:Coll[Byte]; col1,col2:Coll[Long]; g1,g2:GroupElement;
//                 p1,p2:SigmaProp; n1,n2:BigInt
//   cc  <hex>     compile (source→ErgoTree) with an EMPTY script env, reply
//                 `OK <tree_hex> <p2s_address> <p2sh_address>` (mirrors
//                 ScriptApiRoute.compileSource: header is ALWAYS
//                 defaultHeaderWithVersion(0), ORACLE_TREE_VERSION only gates
//                 method visibility, not the header)
//   cce <hex>     compile with the DEMO env (same free vars as tce)
//   ccs <hex>     compile with the SigmaTyperTest env (same free vars as tcs)
//
// ── batch mode (from worktree root) ────────────────────────────────────────────
//   python3 scripts/jvm_typer_oracle/gen_inputs.py | \
//     ORACLE_TREE_VERSION=3 scala-cli run scripts/jvm_typer_oracle 2>/dev/null
//
// ── fresh-JVM mode (for REJECT line:col grading; one JVM per source) ──────────
//   Use the tc1.sh wrapper in the same directory (see tc1.sh for details).
//   tc1.sh isolates each typecheck in its own process, preventing the write-once
//   sourceContext contamination on case-object singletons (Risk R1, see below).
//
// ── version axis ───────────────────────────────────────────────────────────────
// ORACLE_TREE_VERSION env var (default 3) → both activatedVersion and ergoTreeVersion.
// V=3 enables the v6 predef types (SUnsignedBigInt) and v6 method tables (fromBig-
// EndianBytes, deserializeTo, none/some with explicit type args). Set V=2 to verify
// that those methods reject (MethodNotFound). Must match the Rust twin's tree_version.
// ORACLE_NETWORK env var (default testnet) — only affects PK("base58addr") decoding.
//
// ── pipeline (mirrors SigmaCompiler.typecheck exactly) ─────────────────────────
// parse  = SigmaParser(src)                                    → SValue (untyped)
// bind   = new SigmaBinder(env, builder, net, predef).bind(parsed)
// type   = new SigmaTyper(builder, predef, typeEnv, lowerMethodCalls=true).typecheck(bound)
// with builder = TransformingSigmaBuilder (default). lowerMethodCalls=true means
// methods WITH an irBuilder are replaced by their specialized IR node (e.g. Append,
// MapCollection, Filter, ForAll, Slice, Fold, Exponentiate, MultiplyGroup, ByIndex …).
// methods WITH the generic MethodCallIrBuilder survive as MethodCall; methods with NO irBuilder survive as Select; custom builders lower
//
// § Canonical s-expression format (diff target for the Rust typed_print.rs) ────
//
// node   := "(" productPrefix ":" tpe.toTermString ( " " field )* ")"
// field  := node                      child expression (Value[SType])
//         | "[" node* "]"             Seq/Array of Values (space-separated)
//         | "#" tpe.toTermString      SType-valued field (e.g. ConcreteCollection.elemType)
//         | "%" Owner.name            SMethod (MethodCall.method): objType.typeName + "." + name
//         | "{" (k "->" v ",")* "}"   sorted Map (MethodCall.typeSubst)
//         | "'" text "'"              String field (Ident.name, Select.field, ValNode.name)
//         | "@" lit                   scalar: Byte/Short/Int/Long/Boolean/BigInteger/other
//         | "<" el* ">"               sigma.Coll payload (Constant payloads), space-sep
//         | "None"                    empty Option or sigma.data.Nullable
//         | name ":#" tpe             (String,SType) pair (Lambda.args entries)
//
// NORMALIZATION (oracle AND Rust twin MUST apply identically):
//  N1. Every node is annotated with ":" + tpe.toTermString.
//  N2. A field is SKIPPED iff its unwrapped value is an SType structurally == the
//      node's own tpe. "Unwrapped" means: bare SType, Option[SType] (unwrap Some),
//      or sigma.data.Nullable[SType] (unwrap non-empty) — applied BEFORE rendering.
//      Effect: drops the redundant resType carried by Select (Option[SType]), Upcast,
//      ConstantNode, Ident, and similar nodes where the field equals the node's tpe.
//      (E6 extension vs prototype: prototype only stripped bare SType; this version
//      also strips Option-wrapped and Nullable-wrapped self-types, fixing the R4 gap.)
//  N3. Handled by renderField: Option/Nullable are always unwrapped; empty → "None".
//  N4. Map entries (typeSubst) are sorted by their rendered-key string.
//  N5. Field order = case-class constructor order (productIterator), deterministic.
//
// Risk R1 — CRITICAL for REJECT position grading in batch mode:
// Height/Inputs/Outputs/Self/Context/Global/MinerPubkey/LastBlockUtxoRootHash are
// Scala case OBJECTS whose _sourceContext is write-once (values.scala:81-90). In
// a single JVM a prior `HEIGHT > 0` at col 1 contaminates later sources that
// reference HEIGHT: their REJECT positions report the stale col 1 even if the error
// sits at col 5. ACCEPT outputs are UNAFFECTED. For reject-position grading use tc1.sh
// (fresh JVM per source). For accept grading and exception-class comparison, batch mode
// is fine. The golden_seed.txt documents fresh-JVM positions for reject cases.
//
// Risk R3 — Constant payload canonicalization (GroupElement/AvlTree/SigmaProp/BigInt)
// uses Scala's toString (non-canonical). Byte arrays print as decimal element lists
// "<@1 @2>". Full payload parity is M3 scope; M2 grades structure + types + scalars.
//
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2

import scala.io.StdIn
import scorex.util.encode.Base16
import sigma.VersionContext
import sigma.ast._
import sigma.ast.syntax.SValue
import sigma.compiler.SigmaCompiler
import sigma.compiler.ir.CompiletimeIRContext
import sigma.exceptions.CompilerException
import sigma.serialization.ErgoTreeSerializer
import sigmastate.interpreter.Interpreter.ScriptEnv
import org.ergoplatform.{ErgoAddressEncoder, Pay2SAddress, Pay2SHAddress}
import org.ergoplatform.ErgoAddressEncoder.{MainnetNetworkPrefix, TestnetNetworkPrefix}

object TyperOracle {

  // ----- version / network knobs -----
  private val V: Byte =
    sys.env.get("ORACLE_TREE_VERSION").map(_.trim.toByte).getOrElse(3.toByte)
  private val NET: Byte =
    sys.env.get("ORACLE_NETWORK").map(_.trim.toLowerCase) match {
      case Some("mainnet") => MainnetNetworkPrefix
      case _               => TestnetNetworkPrefix
    }
  private val compiler = new SigmaCompiler(NET)

  // Route parity for the `cc`/`cce`/`ccs` verbs (mirrors ScriptApiRoute's
  // implicit addressEncoder, which is built from the same NET prefix used to
  // decode PK(...) addresses).
  private val addressEncoder = new ErgoAddressEncoder(NET)

  // ----- demo env for `tce` (free typed variables bound to concrete VALUES) -----
  // The binder substitutes an Ident for the env value via SigmaBinder.scala:39-40
  // (`liftAny` → SigmaBuilder.scala:219 `case v: SValue => Nullable(v)`), so these
  // stand in as typed leaves in the typed tree.
  // Types: a,b: Coll[Byte]; col1,col2: Coll[Long]; g1,g2,g3: GroupElement;
  //        n1: BigInt; bb1,bb2: Byte.
  private val demoEnv: ScriptEnv = {
    val dlog = sigma.crypto.CryptoConstants.dlogGroup
    val g  = dlog.generator
    val ge = sigma.data.CSigmaDslBuilder.GroupElement(g)
    // g3 = g^7 (7 !== 1 mod group-order, so this is a fixed NON-generator point,
    // computed the same way sigmaTyperEnv derives g2 = g^2 below via
    // BcDlogGroup.exponentiate). D-T6's decompress needs a second, distinct point.
    val g3ecp = dlog.exponentiate(g, java.math.BigInteger.valueOf(7))
    val ge3   = sigma.data.CSigmaDslBuilder.GroupElement(g3ecp)
    Map[String, Any](
      "a"    -> ByteArrayConstant(Array[Byte](1, 2)),
      "b"    -> ByteArrayConstant(Array[Byte](3, 4)),
      "col1" -> LongArrayConstant(Array[Long](1L, 2L)),
      "col2" -> LongArrayConstant(Array[Long](3L, 4L)),
      "g1"   -> GroupElementConstant(ge),
      "g2"   -> GroupElementConstant(ge),
      "g3"   -> GroupElementConstant(ge3),
      "n1"   -> BigIntConstant(BigInt(5).bigInteger),
      "bb1"  -> ByteConstant(1.toByte),
      "bb2"  -> ByteConstant(2.toByte)
    )
  }

  // ----- SigmaTyperTest env for the `tcs` verb -----
  // Mirrors LangTests.scala:52-69 exactly (the `env` used across SigmaTyperTest),
  // restricted to the entries any SigmaTyperTest property references.  Values are
  // written as the SValue constants that `Platform.liftToConstant` produces from the
  // LangTests raw values (CAnyValue(10) → IntConstant(10), etc.), so the bound tree is
  // byte-identical to the reference test.  `big`/`bigIntArr1` are omitted (never
  // referenced by any typer property).
  private val sigmaTyperEnv: ScriptEnv = {
    val dlog = sigma.crypto.CryptoConstants.dlogGroup
    val ecp1 = dlog.generator
    val ecp2 = dlog.multiplyGroupElements(ecp1, ecp1)
    val ge1  = sigma.data.CSigmaDslBuilder.GroupElement(ecp1)
    val ge2  = sigma.data.CSigmaDslBuilder.GroupElement(ecp2)
    Map[String, Any](
      "x"       -> IntConstant(10),
      "y"       -> IntConstant(11),
      "c1"      -> TrueLeaf,
      "c2"      -> FalseLeaf,
      "height1" -> LongConstant(100L),
      "height2" -> LongConstant(200L),
      "b1"      -> ByteConstant(1.toByte),
      "b2"      -> ByteConstant(2.toByte),
      "arr1"    -> ByteArrayConstant(Array[Byte](1, 2)),
      "arr2"    -> ByteArrayConstant(Array[Byte](10, 20)),
      "col1"    -> ConcreteCollection.fromItems(LongConstant(1), LongConstant(2)),
      "col2"    -> ConcreteCollection.fromItems(LongConstant(10), LongConstant(20)),
      "g1"      -> GroupElementConstant(ge1),
      "g2"      -> GroupElementConstant(ge2),
      "p1"      -> SigmaPropConstant(sigma.data.ProveDlog(ecp1)),
      "p2"      -> SigmaPropConstant(sigma.data.ProveDlog(ecp2)),
      "n1"      -> BigIntConstant(BigInt(10).bigInteger),
      "n2"      -> BigIntConstant(BigInt(20).bigInteger)
    )
  }

  // ===== canonical s-expression printer over the typed Value[SType] tree =====

  private def typeTerm(t: SType): String = t.toTermString

  private def renderMethod(m: SMethod): String = m.objType.typeName + "." + m.name

  // N2 unwrapping: extract the SType from a field value (if it is one) for the
  // redundant-self-type check. Returns Some(t) when the field is:
  //   - a bare SType
  //   - Some(t: SType)          (Option-wrapped, E6 extension)
  //   - Nullable(t: SType)      (sigma.data.Nullable-wrapped, E6 extension)
  // Returns None for anything else (field is NOT a bare-or-wrapped SType).
  private def extractSType(f: Any): Option[SType] = f match {
    case t: SType                          => Some(t)
    case Some(t: SType)                    => Some(t)
    case n: sigma.data.Nullable[_]
      if !n.isEmpty && n.get.isInstanceOf[SType] => Some(n.get.asInstanceOf[SType])
    case _                                 => None
  }

  private def renderNode(v: Value[SType]): String = {
    val nm = v.productPrefix
    val tp = typeTerm(v.tpe)
    val fields = v.productIterator.toList.flatMap { f =>
      // N2 (extended by E6): skip any field whose unwrapped SType == this node's tpe.
      extractSType(f) match {
        case Some(t) if t == v.tpe => None   // redundant self-type — drop
        case _                     => Some(renderField(f))
      }
    }
    if (fields.isEmpty) s"($nm:$tp)" else s"($nm:$tp ${fields.mkString(" ")})"
  }

  private def renderField(f: Any): String = f match {
    case null                          => "null"
    case t: SType                      => "#" + typeTerm(t)
    case m: SMethod                    => "%" + renderMethod(m)
    case v: Value[_]                   => renderNode(v.asInstanceOf[Value[SType]])
    case n: sigma.data.Nullable[_]     => if (n.isEmpty) "None" else renderField(n.get)  // N3
    case o: Option[_]                  => o.map(renderField).getOrElse("None")           // N3
    case (s: String, t: SType)         => s + ":#" + typeTerm(t)
    case (x, y)                        => "(" + renderField(x) + " . " + renderField(y) + ")"
    case m: scala.collection.Map[_, _] =>
      // N4: sort map entries by rendered key
      val es = m.toList.map { case (k, vv) => renderField(k) + "->" + renderField(vv) }.sorted
      es.mkString("{", ",", "}")
    case c: sigma.Coll[_]              => c.toArray.map(renderField).mkString("<", " ", ">")
    case it: Iterable[_]               => it.map(renderField).mkString("[", " ", "]")
    case a: Array[_]                   => a.map(renderField).mkString("[", " ", "]")
    case s: String                     => "'" + s + "'"
    case b: Boolean                    => "@" + b.toString
    case b: Byte                       => "@" + b.toString
    case s: Short                      => "@" + s.toString
    case i: Int                        => "@" + i.toString
    case l: Long                       => "@" + l.toString
    case bi: java.math.BigInteger      => "@" + bi.toString
    case p: Product                    =>
      // fallback: SigmaNode-like product without a tpe (e.g. internal STypeParam)
      val inner = p.productIterator.map(renderField).mkString(" ")
      s"(${p.productPrefix} $inner)"
    case other                         => "@" + other.toString
  }

  // ----- driver -----
  private def loc(sc: SourceContext): String = sc.line + ":" + sc.column

  private def handle(env: ScriptEnv, hexStr: String): String =
    Base16.decode(hexStr) match {
      case scala.util.Failure(_) => "ERR not-hex"
      case scala.util.Success(bytes) =>
        val source = new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
        try
          VersionContext.withVersions(V, V) {
            "OK " + renderNode(compiler.typecheck(env, source))
          }
        catch {
          case e: CompilerException =>
            val pos = e.source match { case Some(sc) => loc(sc); case None => "0:0" }
            "REJECT " + pos + " " + e.getClass.getSimpleName
          case e: Throwable =>
            "REJECT 0:0 " + e.getClass.getSimpleName
        }
    }

  // ----- compile driver for `cc`/`cce`/`ccs` -----
  //
  // Mirrors ScriptApiRoute.compileSource (pinned checkout ergo/.../ScriptApiRoute.scala:56-67)
  // EXACTLY: the emitted ErgoTree header is ALWAYS defaultHeaderWithVersion(0),
  // regardless of ORACLE_TREE_VERSION — the route never forwards its treeVersion
  // param into the header either; VersionContext.withVersions(V, V) only gates
  // method visibility during typecheck/compile. Root SSigmaProp -> fromProposition
  // directly; root SBoolean -> .toSigmaProp first; anything else -> REJECT (same
  // catch-all as the `tc` path, so the reply grammar is identical).
  private def compileVerb(env: ScriptEnv, hexStr: String): String =
    Base16.decode(hexStr) match {
      case scala.util.Failure(_) => "ERR not-hex"
      case scala.util.Success(bytes) =>
        val source = new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
        try
          VersionContext.withVersions(V, V) {
            val header = ErgoTree.defaultHeaderWithVersion(0.toByte)
            val result = compiler.compile(env, source)(new CompiletimeIRContext)
            val tree = result.buildTree match {
              case s: Value[SSigmaProp.type @unchecked] if s.tpe == SSigmaProp =>
                ErgoTree.fromProposition(header, s)
              case b: Value[SBoolean.type @unchecked] if b.tpe == SBoolean =>
                ErgoTree.fromProposition(header, b.toSigmaProp)
              case other =>
                throw new Exception(s"non-Bool/SigmaProp root: ${other.tpe}")
            }
            val treeBytes = ErgoTreeSerializer.DefaultSerializer.serializeErgoTree(tree)
            val p2s  = Pay2SAddress(tree)(addressEncoder).toString
            // P2SH must hash the constant-INLINED proposition, not the tree bytes.
            val prop = tree.toProposition(replaceConstants = tree.isConstantSegregation)
            val p2sh = Pay2SHAddress(prop)(addressEncoder).toString
            "OK " + treeBytes.map("%02x".format(_)).mkString + " " + p2s + " " + p2sh
          }
        catch {
          case e: CompilerException =>
            val pos = e.source match { case Some(sc) => loc(sc); case None => "0:0" }
            "REJECT " + pos + " " + e.getClass.getSimpleName
          case e: Throwable =>
            "REJECT 0:0 " + e.getClass.getSimpleName
        }
    }

  def main(args: Array[String]): Unit = {
    var line = StdIn.readLine()
    while (line != null) {
      val t = line.trim
      if (t.nonEmpty) {
        val out = t.split("\\s+", 2) match {
          case Array("tc",  hex) => handle(Map.empty, hex)
          case Array("tce", hex) => handle(demoEnv, hex)
          case Array("tcs", hex) => handle(sigmaTyperEnv, hex)
          case Array("cc",  hex) => compileVerb(Map.empty, hex)
          case Array("cce", hex) => compileVerb(demoEnv, hex)
          case Array("ccs", hex) => compileVerb(sigmaTyperEnv, hex)
          case _                 => "ERR bad-line"
        }
        println(out)
      }
      line = StdIn.readLine()
    }
  }
}

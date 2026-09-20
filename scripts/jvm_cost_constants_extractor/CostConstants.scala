//> using scala 2.12
//> using options -Xfatal-warnings
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-wallet:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2
//> using dep io.circe::circe-core:0.13.0
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import io.circe.{Json, Printer}
import sigma.VersionContext
import sigma.ast._
import sigma.data.DataValueComparer
import sigma.serialization.{SigSerializer, ValueSerializer}
import sigmastate.interpreter.{CErgoTreeEvaluator, Interpreter}
import sigmastate.FiatShamirTree
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import org.ergoplatform.wallet.protocol.Constants
import org.ergoplatform.settings.Parameters
import scala.sys.process._

/** JVM declarations only; no Rust cost implementation participates in extraction. */
object CostConstants {
  private val script = "scripts/jvm_cost_constants_extractor/CostConstants.scala"
  private val output = "test-vectors/ergo-sigma/cost-ledger/scala-constants.json"
  private val printer = Printer.spaces2.copy(sortKeys = true)
  private def str(s: String): Json = Json.fromString(s)
  private def num(n: Int): Json = Json.fromInt(n)
  private def arr(xs: Seq[Json]): Json = Json.arr(xs: _*)
  private def sha(bytes: Array[Byte]): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).map(b => f"${b & 255}%02x").mkString
  private def command(args: String*): String = Process(args).!!.trim

  private def cost(value: => CostKind): Json = {
    def descriptor(kind: String, base: Json = Json.Null, perChunk: Json = Json.Null,
                   chunkSize: Json = Json.Null): Json = Json.obj(
      "kind" -> str(kind), "base" -> base, "perChunk" -> perChunk, "chunkSize" -> chunkSize)
    try {
      value match {
        case null => descriptor("NotSupported").deepMerge(Json.obj(
          "reason" -> str("SMethod.costKind is null (no standalone cost descriptor)")))
        case FixedCost(c) => descriptor("Fixed", num(c.value))
        case PerItemCost(b, p, s) => descriptor("PerItem", num(b.value), num(p.value), num(s))
        case t: TypeBasedCost => descriptor("TypeBased").deepMerge(Json.obj(
          "class" -> str(t.getClass.getName)))
        case DynamicCost => descriptor("Dynamic")
        case PowHitCostKind => descriptor("Dynamic").deepMerge(Json.obj(
          "class" -> str(PowHitCostKind.getClass.getName)))
      }
    } catch {
      // This is the precise exception raised by Value.notSupportedError.
      case e: IllegalArgumentException
          if e.getMessage.startsWith("Method costKind is not supported for node ") =>
        descriptor("NotSupported").deepMerge(Json.obj("reason" -> str(e.getMessage)))
    }
  }

  /** Getter return types discover all operation descriptors, including crypto helpers. */
  private def operations(owner: AnyRef, prefix: String): Seq[(String, Json)] =
    owner.getClass.getMethods.toSeq.filter(m => m.getParameterCount == 0 &&
      classOf[OperationCostInfo[_]].isAssignableFrom(m.getReturnType)).sortBy(_.getName).map { m =>
      val info = m.invoke(owner).asInstanceOf[OperationCostInfo[CostKind]]
      s"$prefix.${m.getName}" -> Json.obj("costKind" -> cost(info.costKind), "source" -> str("reflection"))
    }

  private def scalar(value: Long, units: String): Json = Json.obj(
    "value" -> Json.fromLong(value), "units" -> str(units), "source" -> str("jvm"))

  // JitCost is an Int-backed value class, with checked Int arithmetic.
  private def bound(value: Long, units: String): Json = scalar(value, units).deepMerge(Json.obj(
    "source" -> str("jvm-derived"),
    "scala" -> str("sigmastate v6.0.2 data/shared/src/main/scala/sigma/ast/JitCost.scala:10-39")))

  private def artifact(owner: AnyRef): Json = {
    val path = Paths.get(owner.getClass.getProtectionDomain.getCodeSource.getLocation.toURI)
    Json.obj("file" -> str(path.getFileName.toString), "sha256" -> str(sha(Files.readAllBytes(path))))
  }

  def main(args: Array[String]): Unit = {
    require(args.length == 2 && args(0).matches("[0-9a-f]{40}"),
      "Usage: CostConstants <provenance-git-sha> <ISO-8601-timestamp>; run from the repository root (see README.md)")
    val revision = args(0)
    val timestamp = java.time.Instant.parse(args(1)).toString
    val sourceState = if (command("git", "show", s"$revision:$script") ==
      new String(Files.readAllBytes(Paths.get(script)), UTF_8).trim) "committed" else "working-tree"
    val opcodes = VersionContext.withVersions(3.toByte, 3.toByte) {
      (0 to 255).flatMap { code => ValueSerializer.serializers.get(code.toByte).map { serializer =>
        Json.obj("opcode" -> num(code), "name" -> str(serializer.opDesc.typeName),
          "costKind" -> cost(serializer.opDesc.costKind))
      }}
    }
    val snapshots = (0 to 3).map { version =>
      VersionContext.withVersions(version.toByte, version.toByte) {
        (0 to 255).filter(id => MethodsContainer.contains(id.toByte)).map { id =>
          val container = MethodsContainer(id.toByte)
          (version, id, container.toString, SType.types.contains(id.toByte), container.methods.map { m =>
            Json.obj("typeId" -> num(id), "methodId" -> num(m.methodId & 255),
              "name" -> str(m.name), "costKind" -> cost(m.costKind))
          })
        }
      }
    }.flatten
    val containers = snapshots.groupBy(_._2).toSeq.sortBy(_._1).map { case (id, versions) =>
      Json.obj("typeId" -> num(id), "name" -> str(versions.head._3),
        "versions" -> arr(versions.map(v => num(v._1))),
        "wireReceiverVersions" -> arr(versions.filter(_._4).map(v => num(v._1))))
    }
    val methods = snapshots.flatMap { case (version, _, _, _, ms) => ms.map(_ -> version) }
      .groupBy { case (m, _) => printer.print(m) }.values.toSeq.map { versions =>
        versions.head._1.deepMerge(Json.obj("minVersion" -> num(versions.map(_._2).min),
          "versions" -> arr(versions.map(_._2).sorted.map(num))))
      }.sortBy { m =>
        val c = m.hcursor
        (c.get[Int]("typeId").toOption.get, c.get[Int]("methodId").toOption.get,
          c.get[Int]("minVersion").toOption.get)
      }
    // Tuple accessors are synthesized by getTupleMethod, not MethodsContainer.methods.
    // Enumerate every arity/version, then group identical declarations without losing
    // their reachability denominator. Inherited size/apply retain collection IDs.
    val tupleSnapshots = for {
      version <- 0 to 3
      arity <- 2 to sigma.data.SigmaConstants.MaxTupleLength.value
      name <- Seq("size", "apply") ++ (1 to arity).map(i => s"_$i")
    } yield VersionContext.withVersions(version.toByte, version.toByte) {
      val method = STupleMethods.getTupleMethod(STuple(Vector.fill(arity)(SInt)), name).get
      val declaration = Json.obj("name" -> str(method.name),
        "typeId" -> num(method.objType.ownerType.typeId & 255),
        "methodId" -> num(method.methodId & 255), "costKind" -> cost(method.costKind))
      (declaration, arity, version)
    }
    val tupleMethods = tupleSnapshots.groupBy(t => printer.print(t._1)).values.toSeq.map { group =>
      val arities = group.map(_._2).distinct.sorted
      require(arities == (arities.head to arities.last), "Tuple arity domain must be contiguous")
      group.head._1.deepMerge(Json.obj(
        "minArity" -> num(arities.head), "maxArity" -> num(arities.last),
        "versions" -> arr(group.map(_._3).distinct.sorted.map(num))))
    }.sortBy(_.hcursor.get[String]("name").right.get)
    // CostPerTreeByte and CostPerByteDeserialized are instance vals on Interpreter.
    val interpreter = new Interpreter { override type CTX = org.ergoplatform.ErgoLikeContext }
    val constants = operations(DataValueComparer, "DataValueComparer") ++
      operations(Interpreter, "Interpreter") ++ operations(SigSerializer, "SigSerializer") ++
      operations(FiatShamirTree, "FiatShamirTree") ++ Seq(
        "Interpreter.CostPerTreeByte" -> scalar(interpreter.CostPerTreeByte, "block/byte"),
        "Interpreter.CostPerByteDeserialized" -> scalar(interpreter.CostPerByteDeserialized, "block/byte"),
        "Interpreter.interpreterInitCost" -> scalar(Interpreter.interpreterInitCost, "block"),
        "Interpreter.ProveDlogVerificationCost" -> scalar(Interpreter.ProveDlogVerificationCost.value, "jit"),
        "Interpreter.ProveDHTupleVerificationCost" -> scalar(Interpreter.ProveDHTupleVerificationCost.value, "jit"),
        "ErgoInterpreter.interpreterInitCost" -> scalar(ErgoInterpreter.interpreterInitCost, "block"),
        "Constants.StorageContractCost" -> scalar(Constants.StorageContractCost, "block"),
        "Parameters.TokenAccessCostDefault" -> scalar(Parameters.TokenAccessCostDefault, "block"),
        "Parameters.InputCostDefault" -> scalar(Parameters.InputCostDefault, "block"),
        "Parameters.DataInputCostDefault" -> scalar(Parameters.DataInputCostDefault, "block"),
        "Parameters.OutputCostDefault" -> scalar(Parameters.OutputCostDefault, "block"),
        "Parameters.MaxBlockCostDefault" -> scalar(Parameters.MaxBlockCostDefault, "block"),
        "DataValueComparer.CostOf_MatchType" -> scalar(DataValueComparer.CostOf_MatchType, "jit"),
        "CErgoTreeEvaluator.DataBlockSize" -> scalar(CErgoTreeEvaluator.DataBlockSize, "bytes"),
        "JitCost.MinValue" -> bound(Int.MinValue, "jit"),
        "JitCost.MaxValue" -> bound(Int.MaxValue, "jit"),
        "JitCost.Scale" -> scalar(JitCost.fromBlockCost(1).value, "jit/block"),
        "JitCost.MaxBlockCost" -> bound(Int.MaxValue / JitCost.fromBlockCost(1).value, "block"))
    require(constants.map(_._1).distinct.size == constants.size, "Duplicate constant names")
    val payload = Json.obj("opcodes" -> arr(opcodes), "containers" -> arr(containers),
      "methods" -> arr(methods), "tupleMethods" -> arr(tupleMethods), "constants" -> Json.obj(constants: _*))
    val count = opcodes.size + methods.size + tupleMethods.size + constants.size
    val manifest = Json.obj(
      "scala" -> Json.obj("ergo_version" -> str("6.0.2"), "sigmastate_version" -> str("6.0.2"),
        "node_app_version" -> Json.Null, "source_shas" -> Json.obj(
          "sigmastate" -> str("23dd29f612249c169d09fae9bca76d7cc02e144c"),
          "ergo" -> str("2cdbb8cf09d7ccbc060e1022e3c15bcf6a9991b1"))),
      "rust" -> Json.obj("git_sha" -> str(revision), "toolchain" -> str(command("rustc", "--version")),
        "features" -> Json.arr()),
      "tool" -> Json.obj("script" -> str(script), "git_sha" -> str(revision),
        "script_sha256" -> str(sha(Files.readAllBytes(Paths.get(script)))),
        "source_state" -> str(sourceState),
        "scala_cli_version" -> str(command("scala-cli", "version", "--cli-version")),
        "scala_version" -> str(util.Properties.versionNumberString),
        "jvm_version" -> str(System.getProperty("java.runtime.version"))),
      "context" -> Json.obj("network" -> str("source-constants"), "height_range" -> Json.Null,
        "devnet_chain_id" -> Json.Null, "activated_script_version" -> arr((0 to 3).map(num)),
        "ergo_tree_version" -> arr((0 to 3).map(num)), "block_version" -> Json.Null,
        "voted_params" -> Json.obj((4 to 8).map(id => id.toString -> Json.Null): _*)),
      "run" -> Json.obj("command_line" -> str(s"scala-cli run $script --server=false --jvm system -- $revision $timestamp"),
        "seeds" -> Json.arr(), "timestamp" -> str(timestamp),
        "timestamp_basis" -> str("explicit capture timestamp; reuse for byte-identical regeneration"),
        "selected" -> num(count), "executed" -> num(count), "skipped" -> num(0), "failed" -> num(0)),
      "evidence" -> Json.obj("input_vectors" -> Json.arr(),
        "artifacts" -> arr(Seq(artifact(Interpreter), artifact(ErgoInterpreter), artifact(Parameters), artifact(Json))),
        "output" -> Json.obj("file" -> str(output), "sha256" -> str(sha(printer.print(payload).getBytes(UTF_8))),
          "hash_scope" -> str("UTF-8 circe spaces2 sorted-key JSON excluding manifest and final newline (avoids self-reference)"))),
      "excluded" -> Json.arr())
    Files.write(Paths.get(output), (printer.print(payload.deepMerge(Json.obj("manifest" -> manifest))) + "\n").getBytes(UTF_8))
    println(s"selected=$count executed=$count skipped=0 failed=0; opcodes=${opcodes.size} methods=${methods.size} tupleMethods=${tupleMethods.size} containers=${containers.size} constants=${constants.size}")
  }
}

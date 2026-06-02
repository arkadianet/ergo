//> using scala 2.12
//> using dep org.ergoplatform::ergo-wallet:6.1.0
//> using dep io.circe::circe-parser:0.14.5

// Validates mainnet transactions using the real Scala sigmastate-interpreter
// and outputs per-tx block-cost values for differential testing against Rust.
//
// Connects to a running Ergo node API to fetch blocks and resolve input boxes.
// Requires: node running with extraIndex enabled.
//
// Usage: scala-cli run ComputeTransactionCosts.scala -- <start_height> <end_height>
//
// Output: JSON array to stdout:
//   [{"tx_id":"...","height":N,"block_cost":N}, ...]
//
// Params are loaded from the most recent epoch boundary extension on startup,
// then refreshed at each subsequent epoch boundary. This ensures correct
// activatedScriptVersion and cost constants across voting-param changes.

import org.ergoplatform._
import org.ergoplatform.sdk.JsonCodecs
import org.ergoplatform.sdk.CBlockchainParameters
import org.ergoplatform.wallet.interpreter.ErgoInterpreter
import io.circe.parser._
import io.circe._
import scorex.util.encode.Base16
import sigma.Colls
import sigma.data.{AvlTreeData, AvlTreeFlags, CGroupElement}
import sigma.serialization.{GroupElementSerializer, SigmaSerializer}
import org.ergoplatform.validation.ValidationRules
import sigmastate.eval.CPreHeader
import sigmastate.interpreter.Interpreter

import java.io._
import java.net._
import java.nio.ByteBuffer
import scala.collection.mutable
import scala.util.{Try, Success, Failure}

object ComputeTransactionCosts extends JsonCodecs {

  val NODE_URL: String = sys.env.getOrElse("NODE_URL", "http://localhost:9053")

  // Mainnet voting epoch length (Parameters.votingLength in chainSettings)
  val VOTING_EPOCH_LENGTH = 1024

  val INTERPRETER_INIT_COST = 10000L

  // Parameter byte IDs matching Scala Parameters.scala constants.
  // System params are stored in extension fields with 2-byte keys: 0x00 ++ paramId
  val PARAM_STORAGE_FEE_FACTOR: Byte = 1
  val PARAM_MIN_VALUE_PER_BYTE: Byte  = 2
  val PARAM_MAX_BLOCK_SIZE: Byte      = 3
  val PARAM_MAX_BLOCK_COST: Byte      = 4
  val PARAM_TOKEN_ACCESS_COST: Byte   = 5
  val PARAM_INPUT_COST: Byte          = 6
  val PARAM_DATA_INPUT_COST: Byte     = 7
  val PARAM_OUTPUT_COST: Byte         = 8
  val PARAM_BLOCK_VERSION: Byte       = 123.toByte // 0x7b

  // Active voted parameters — defaults match mainnet initial state.
  // activatedScriptVersion = blockVersion - 1 (JIT cost model since EIP-37 ~h417792)
  case class ActiveParams(
    storageFeeFactor: Int = 1250000,
    minValuePerByte:  Int = 360,
    maxBlockSize:     Int = 524288,
    tokenAccessCost:  Int = 100,
    inputCost:        Int = 2000,
    dataInputCost:    Int = 100,
    outputCost:       Int = 100,
    maxBlockCost:    Long = 1000000L,
    blockVersion:     Int = 2
  )

  // Parse system parameters from extension fields.
  // Returns Some(updated) if the extension contains a BlockVersion field (epoch start),
  // None if this is a non-epoch block (no system params present).
  def parseParamsFromExtension(
      fields: Vector[(String, String)],
      prev: ActiveParams
  ): Option[ActiveParams] = {
    val paramMap = mutable.Map[Byte, Int]()
    for ((keyHex, valHex) <- fields) {
      val keyBytes = Base16.decode(keyHex).getOrElse(Array.empty[Byte])
      val valBytes = Base16.decode(valHex).getOrElse(Array.empty[Byte])
      if (keyBytes.length == 2 && valBytes.length == 4 && keyBytes(0) == 0.toByte) {
        paramMap(keyBytes(1)) = ByteBuffer.wrap(valBytes).getInt()
      }
    }
    if (!paramMap.contains(PARAM_BLOCK_VERSION)) None
    else Some(ActiveParams(
      storageFeeFactor = paramMap.getOrElse(PARAM_STORAGE_FEE_FACTOR, prev.storageFeeFactor),
      minValuePerByte  = paramMap.getOrElse(PARAM_MIN_VALUE_PER_BYTE,  prev.minValuePerByte),
      maxBlockSize     = paramMap.getOrElse(PARAM_MAX_BLOCK_SIZE,      prev.maxBlockSize),
      tokenAccessCost  = paramMap.getOrElse(PARAM_TOKEN_ACCESS_COST,   prev.tokenAccessCost),
      inputCost        = paramMap.getOrElse(PARAM_INPUT_COST,          prev.inputCost),
      dataInputCost    = paramMap.getOrElse(PARAM_DATA_INPUT_COST,     prev.dataInputCost),
      outputCost       = paramMap.getOrElse(PARAM_OUTPUT_COST,         prev.outputCost),
      maxBlockCost     = paramMap.getOrElse(PARAM_MAX_BLOCK_COST,      prev.maxBlockCost.toInt).toLong,
      blockVersion     = paramMap(PARAM_BLOCK_VERSION)
    ))
  }

  def makeInterpreter(p: ActiveParams): ErgoInterpreter =
    new ErgoInterpreter(CBlockchainParameters(
      storageFeeFactor       = p.storageFeeFactor,
      minValuePerByte        = p.minValuePerByte,
      maxBlockSize           = p.maxBlockSize,
      tokenAccessCost        = p.tokenAccessCost,
      inputCost              = p.inputCost,
      dataInputCost          = p.dataInputCost,
      outputCost             = p.outputCost,
      maxBlockCost           = p.maxBlockCost.toInt,
      softForkStartingHeight = None,
      softForkVotesCollected = None,
      blockVersion           = p.blockVersion.toByte
    ))

  // Extract extension fields as (keyHex, valueHex) pairs from a block JSON cursor.
  def extensionFields(cursor: HCursor): Vector[(String, String)] =
    cursor.downField("extension").downField("fields").focus
      .flatMap(_.asArray)
      .getOrElse(Vector.empty)
      .flatMap(_.asArray.flatMap {
        case v if v.size == 2 =>
          for { k <- v(0).asString; vv <- v(1).asString } yield (k, vv)
        case _ => None
      })

  def httpGet(path: String): String = {
    val url  = new URL(s"$NODE_URL$path")
    val conn = url.openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    conn.setConnectTimeout(10000)
    conn.setReadTimeout(60000)
    conn.setRequestProperty("Accept", "application/json")
    val code = conn.getResponseCode
    if (code != 200) throw new RuntimeException(s"HTTP $code for $path")
    val reader = new BufferedReader(new InputStreamReader(conn.getInputStream))
    val sb = new StringBuilder
    var line: String = null
    while ({ line = reader.readLine(); line != null }) sb.append(line)
    reader.close()
    conn.disconnect()
    sb.toString()
  }

  // Build AvlTreeData from a 33-byte stateRoot hex (header.stateRoot from API).
  // Ergo's UTXO tree allows all operations; keyLength=32 (box IDs).
  def stateRootToAvlTree(stateRootHex: String): AvlTreeData =
    AvlTreeData(
      Colls.fromArray(Base16.decode(stateRootHex).get),
      AvlTreeFlags.AllOperationsAllowed,
      32
    )

  def fetchExtensionFields(height: Int): Option[Vector[(String, String)]] = Try {
    val ids = parse(httpGet(s"/blocks/at/$height")).getOrElse(Json.arr())
      .asArray.getOrElse(Vector.empty).flatMap(_.asString)
    if (ids.isEmpty) None
    else {
      val blockJson = parse(httpGet(s"/blocks/${ids.head}")).getOrElse(Json.Null)
      Some(extensionFields(blockJson.hcursor))
    }
  }.toOption.flatten

  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      System.err.println("Usage: ComputeTransactionCosts <start_height> <end_height>")
      System.exit(1)
    }

    val startHeight = args(0).toInt
    val endHeight   = args(1).toInt

    // Seed params from the most recent epoch start so activatedScriptVersion is correct
    // even if we start mid-epoch.
    var activeParams: ActiveParams = ActiveParams()
    var interpreter: ErgoInterpreter = makeInterpreter(activeParams)

    val initEpochStart = (startHeight / VOTING_EPOCH_LENGTH) * VOTING_EPOCH_LENGTH
    if (initEpochStart >= VOTING_EPOCH_LENGTH) {
      System.err.println(s"Seeding params from epoch start h=$initEpochStart ...")
      fetchExtensionFields(initEpochStart)
        .flatMap(f => parseParamsFromExtension(f, activeParams))
        .foreach { p =>
          activeParams = p
          interpreter  = makeInterpreter(activeParams)
          System.err.println(s"  blockVersion=${p.blockVersion} maxBlockCost=${p.maxBlockCost} inputCost=${p.inputCost}")
        }
    }

    // Seed lastBlockUtxoRoot from block at startHeight-1 so that scripts which check
    // CONTEXT.LastBlockUtxoRootHash get the correct AVL tree digest.
    var prevStateRoot: AvlTreeData = AvlTreeData.dummy
    if (startHeight > 0) Try {
      val prevIds = parse(httpGet(s"/blocks/at/${startHeight - 1}")).getOrElse(Json.arr())
        .asArray.getOrElse(Vector.empty).flatMap(_.asString)
      if (prevIds.nonEmpty) {
        val prevBlock = parse(httpGet(s"/blocks/${prevIds.head}")).getOrElse(Json.Null)
        prevBlock.hcursor.downField("header").get[String]("stateRoot").toOption
          .foreach { sr =>
            prevStateRoot = stateRootToAvlTree(sr)
            System.err.println(s"Seeded prevStateRoot from h=${startHeight - 1}: ${sr.take(12)}...")
          }
      }
    }

    val results   = mutable.ArrayBuffer[String]()
    var passCount = 0
    var failCount = 0

    val boxCache = mutable.Map[String, ErgoBox]()

    for (height <- startHeight to endHeight) {
      try {
        val blockIdsJson = parse(httpGet(s"/blocks/at/$height")).getOrElse(Json.arr())
        val blockIds     = blockIdsJson.asArray.getOrElse(Vector.empty).flatMap(_.asString)

        if (blockIds.nonEmpty) {
          val blockId  = blockIds.head
          val blockJson = parse(httpGet(s"/blocks/$blockId")).getOrElse(Json.Null)
          val cursor   = blockJson.hcursor

          // Refresh params at epoch boundaries.
          parseParamsFromExtension(extensionFields(cursor), activeParams) match {
            case Some(parsed) if parsed != activeParams =>
              System.err.println(
                s"  h=$height: params updated — blockVersion=${parsed.blockVersion} maxBlockCost=${parsed.maxBlockCost}")
              activeParams = parsed
              interpreter  = makeInterpreter(activeParams)
            case _ => ()
          }

          // activatedScriptVersion = blockVersion - 1 per Ergo consensus spec
          val activatedScriptVersion = (activeParams.blockVersion - 1).toByte

          val headerCursor = cursor.downField("header")
          val headerVersion = headerCursor.get[Int]("version")
            .getOrElse(activeParams.blockVersion).toByte
          val timestamp  = headerCursor.get[Long]("timestamp").getOrElse(0L)
          val nBits      = headerCursor.get[Long]("nBits").getOrElse(0L)
          val minerPkHex = headerCursor.downField("powSolutions")
            .get[String]("pk").getOrElse("")

          if (minerPkHex.isEmpty) {
            System.err.println(s"  Skip h=$height: no minerPk in header")
          } else {
            val minerPkBytes = Base16.decode(minerPkHex).get
            val minerPkEcp   = GroupElementSerializer.parse(SigmaSerializer.startReader(minerPkBytes))
            val minerPkGe    = CGroupElement(minerPkEcp)

            val txsArray = cursor.downField("blockTransactions")
              .downField("transactions").focus
              .flatMap(_.asArray).getOrElse(Vector.empty)

            for (txJson <- txsArray) {
              val txId = txJson.hcursor.get[String]("id").getOrElse("unknown")

              val txResult: Try[Long] = Try {
                val tx = txJson.as[ErgoLikeTransaction](ergoLikeTransactionDecoder)
                  .getOrElse(throw new RuntimeException("tx decode failed"))

                val inputBoxes: IndexedSeq[ErgoBox] = tx.inputs.map { input =>
                  val boxIdHex = Base16.encode(input.boxId)
                  boxCache.getOrElseUpdate(boxIdHex, {
                    decode[ErgoBox](httpGet(s"/blockchain/box/byId/$boxIdHex"))(ergoBoxDecoder)
                      .getOrElse(throw new RuntimeException(s"box decode failed: $boxIdHex"))
                  })
                }.toIndexedSeq

                val dataBoxes: IndexedSeq[ErgoBox] = tx.dataInputs.map { di =>
                  val boxIdHex = Base16.encode(di.boxId)
                  boxCache.getOrElseUpdate(boxIdHex, {
                    decode[ErgoBox](httpGet(s"/blockchain/box/byId/$boxIdHex"))(ergoBoxDecoder)
                      .getOrElse(throw new RuntimeException(s"data box decode failed: $boxIdHex"))
                  })
                }.toIndexedSeq

                val initCost: Long = INTERPRETER_INIT_COST +
                  inputBoxes.size.toLong          * activeParams.inputCost +
                  dataBoxes.size.toLong           * activeParams.dataInputCost +
                  tx.outputCandidates.size.toLong * activeParams.outputCost

                val (inNum, inDistinct)   = countTokens(inputBoxes)
                val (outNum, outDistinct) = countTokensCandidates(tx.outputCandidates)
                val tokenCost = ((inNum + outNum) + (inDistinct + outDistinct)) * activeParams.tokenAccessCost

                var totalCost: Long = initCost + tokenCost
                val messageToSign   = tx.messageToSign

                for ((box, idx) <- inputBoxes.zipWithIndex) {
                  val input = tx.inputs(idx)

                  val preHeader = CPreHeader(
                    version  = headerVersion,
                    parentId = Colls.fromArray(Array.fill(32)(0.toByte)),
                    timestamp = timestamp,
                    nBits    = nBits,
                    height   = height,
                    minerPk  = minerPkGe,
                    votes    = Colls.fromArray(Array.fill(3)(0.toByte))
                  )

                  // Remaining approximations (documented limitations):
                  //   headers = empty  (scripts that index CONTEXT.headers may differ)
                  //   ValidationRules = current (sigma validation settings; stable on mainnet)
                  val ctx = new ErgoLikeContext(
                    prevStateRoot,
                    Colls.emptyColl,
                    preHeader,
                    dataBoxes,
                    inputBoxes,
                    tx,
                    idx,
                    input.spendingProof.extension,
                    ValidationRules.currentSettings,
                    activeParams.maxBlockCost - totalCost,
                    0L,
                    activatedScriptVersion
                  )

                  val verifyResult = interpreter.verify(
                    Interpreter.emptyEnv,
                    box.ergoTree,
                    ctx,
                    input.spendingProof.proof,
                    messageToSign
                  ).get

                  val (isValid, scriptCost) = verifyResult
                  if (!isValid) throw new RuntimeException(s"proof rejected at input $idx")
                  totalCost += scriptCost
                }

                totalCost
              }

              txResult match {
                case Success(cost) =>
                  results += s"""  {"tx_id": "$txId", "height": $height, "block_cost": $cost}"""
                  passCount += 1
                case Failure(e) =>
                  failCount += 1
                  if (!e.getMessage.contains("HTTP 404"))
                    System.err.println(s"  FAIL h=$height tx=$txId: ${e.getMessage}")
              }
            }
          }
          // Advance prevStateRoot to this block's output state for the next iteration.
          cursor.downField("header").get[String]("stateRoot").toOption
            .foreach(sr => prevStateRoot = stateRootToAvlTree(sr))
        }
      } catch {
        case e: Exception =>
          System.err.println(s"  ERROR at height $height: ${e.getMessage}")
      }

      if (height % 10 == 0)
        System.err.println(s"  h=$height: $passCount passed, $failCount failed")
    }

    System.err.println(s"\nDone: $passCount passed, $failCount failed")
    System.err.println(s"Box cache size: ${boxCache.size}")

    println("[")
    println(results.mkString(",\n"))
    println("]")
  }

  private def countTokens(boxes: IndexedSeq[ErgoBox]): (Long, Long) = {
    var total = 0L
    val distinct = mutable.Set[mutable.WrappedArray[Byte]]()
    boxes.foreach { b =>
      b.additionalTokens.toArray.foreach { case (id, _) =>
        total += 1
        distinct += mutable.WrappedArray.make(id)
      }
    }
    (total, distinct.size.toLong)
  }

  private def countTokensCandidates(candidates: IndexedSeq[ErgoBoxCandidate]): (Long, Long) = {
    var total = 0L
    val distinct = mutable.Set[mutable.WrappedArray[Byte]]()
    candidates.foreach { c =>
      c.additionalTokens.toArray.foreach { case (id, _) =>
        total += 1
        distinct += mutable.WrappedArray.make(id)
      }
    }
    (total, distinct.size.toLong)
  }
}

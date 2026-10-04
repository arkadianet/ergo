//> using scala 2.12.20
//> using dep org.scorexfoundation::sigma-state:6.0.6
import sigma.VersionContext
import sigma.serialization.SigmaSerializer
import org.ergoplatform.ErgoBox
import scorex.util.encode.Base16

/** Compare ordinary serialization of an existing serializer-audit fixture. */
object AuditBoxReference {
  def main(args: Array[String]): Unit = {
    val fixture = "c0843d00d17f0100001d823ee9ea823cc80232a19181efad41d66849c33ed5d0d6c5750b8d60f1d66400"
    Seq(1, 2, 3).foreach { activation =>
      VersionContext.withVersions(activation.toByte, 0.toByte) {
        val reader = SigmaSerializer.startReader(Base16.decode(fixture).get)
        val box = ErgoBox.sigmaSerializer.parse(reader)
        val reconstructed = new ErgoBox(box.value, box.ergoTree, box.additionalTokens,
          box.additionalRegisters, box.transactionId, box.index, box.creationHeight)
        println(s"activation=$activation consumed=${reader.position} inputBytes=${fixture.length / 2} cached=${Base16.encode(box.bytes)} serialized=${Base16.encode(ErgoBox.sigmaSerializer.toBytes(box))} id=${Base16.encode(box.id)} reconstructedBytes=${Base16.encode(reconstructed.bytes)} reconstructedId=${Base16.encode(reconstructed.id)} treeCached=${box.ergoTree.bytesHex}")
      }
    }
  }
}

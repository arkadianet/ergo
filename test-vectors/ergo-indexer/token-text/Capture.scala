//> using scala "2.12.20"
// Finite observation of IndexedToken.scala v6.0.5 register expressions.
import java.nio.charset.StandardCharsets
object Capture {
  def main(args: Array[String]): Unit = {
    val cases = Seq("", "ed a0 80", "e2 82", "c0 af", "ef bc 99", "d9 a9", "db b9", "e0 a5 af", "e2 81 b9", "ef bc 8b ef bc 99", "2b ef bc 99", "2d ef bc 99", "20 39", "39 20", "30 39", "2b", "2d", "32 31 34 37 34 38 33 36 34 37", "32 31 34 37 34 38 33 36 34 38", "2d 32 31 34 37 34 38 33 36 34 38", "2d 32 31 34 37 34 38 33 36 34 39", "f0 9d 9f 97", "41", "39 2e 30", "39 00", "2d 30")
    val rows = cases.map { hex =>
      val bytes = if (hex.isEmpty) Array.emptyByteArray else hex.split(" ").map(Integer.parseInt(_, 16).toByte)
      val text = new String(bytes, "UTF-8")
      val parsed = try text.toInt.toString catch { case _: NumberFormatException => "null" }
      "{\"hex\":\"" + hex.replace(" ", "") + "\",\"codepoints\":" + text.codePoints().toArray.mkString("[", ",", "]") + ",\"parsed\":" + parsed + "}"
    }
    val digits = (0 to 65535).flatMap { code =>
      val digit = Character.digit(code.toChar, 10)
      if (digit >= 0) Some("[" + code + "," + digit + "]") else None
    }
    println("{\"cases\":" + rows.mkString("[", ",", "]") + ",\"bmp_digits\":" + digits.mkString("[", ",", "]") + "}")
    Seq("java.runtime.version", "java.vendor", "java.class.path", "file.encoding").foreach { key =>
      System.err.println("TOKEN_TEXT_RUNTIME " + key + "=" + System.getProperty(key, ""))
    }
  }
}

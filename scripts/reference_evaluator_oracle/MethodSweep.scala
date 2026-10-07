//> using scala 2.12.21
//> using dep org.scorexfoundation::sigma-state:6.0.7
import sigma.VersionContext
import sigma.ast._
import scala.util.{Try, Success, Failure}
object MethodSweep {
 def main(args: Array[String]): Unit = {
  for (v <- 0 to 3) VersionContext.withVersions(3.toByte, v.toByte) {
   for (id <- 0 to 255 if MethodsContainer.contains(id.toByte)) {
    val c=MethodsContainer(id.toByte)
    println(s"CONTAINER\t$v\t$id\t${c.typeName}\t${c.methods.size}")
    for (m <- c.methods) {
     val target=Try { m.costKind match {
      case _: FixedCost => if (m.userDefinedInvoke.isDefined) "custom" else {m.javaMethod; "fixed-reflection"}
      case _ => m.evalMethod; "eval-reflection"
     }} match {case Success(s) => s;case Failure(e)=>"unresolved:"+e.getClass.getSimpleName+":"+e.getMessage}
     println(s"METHOD\t$v\t$id\t${m.methodId & 255}\t${m.name}\t$target\t${m.stype}\t${m.costKind}")
    }
   }
  }
 }
}

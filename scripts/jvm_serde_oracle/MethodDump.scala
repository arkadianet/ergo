// Ground-truth enumeration of every SMethod the Scala reference registers, for
// the MethodCall typechecker-registry verification harness (ergo-difftest).
//
// Prints one TSV line per (typeId, methodId): the template result type, whether
// that result is EXACTLY SSigmaProp, whether it is/contains a type variable (so
// the specialized result is receiver/arg-dependent and a SigmaProp instantiation
// must be probed by the tree-diff), the domain arity, and whether the method
// takes explicit type args (which must be serialized in the MethodCall).
//
// Run: scala-cli run scripts/jvm_serde_oracle/MethodDump.scala
//
//> using repository "https://gitlab.com/api/v4/projects/61211221/packages/maven"
//> using scala 2.12
//> using dep org.scorexfoundation::sigma-state:6.0.2
//> using dep org.ergoplatform::ergo-core:6.0.2

import sigma.VersionContext
import sigma.ast._

object MethodDump {
  private val containers: Seq[MethodsContainer] = Seq(
    SByteMethods, SShortMethods, SIntMethods, SLongMethods, SBigIntMethods,
    SBooleanMethods, SStringMethods, SGroupElementMethods, SSigmaPropMethods,
    SBoxMethods, SAvlTreeMethods, SHeaderMethods, SPreHeaderMethods,
    SGlobalMethods, SContextMethods, SCollectionMethods, SOptionMethods,
    STupleMethods, SUnitMethods, SAnyMethods, SUnsignedBigIntMethods
  )

  /** True if `t` is or transitively contains a type variable — i.e. the result is
    * polymorphic and its concrete form depends on the receiver / arg types. */
  private def hasTypeVar(t: SType): Boolean = t match {
    case _: STypeVar              => true
    case c: SCollectionType[_]    => hasTypeVar(c.elemType)
    case o: SOption[_]            => hasTypeVar(o.elemType)
    case f: SFunc                 => f.tDom.exists(hasTypeVar) || hasTypeVar(f.tRange)
    case tup: STuple              => tup.items.exists(hasTypeVar)
    case _                        => false
  }

  def main(args: Array[String]): Unit = {
    VersionContext.withVersions(3.toByte, 3.toByte) {
      println("typeId\tmethodId\tname\tresultType\tisSigmaProp\thasTypeVar\tarity\texplicitTypeArgs")
      for (c <- containers; m <- c.methods) {
        val res = m.stype match {
          case f: SFunc => f.tRange
          case t        => t
        }
        val cols = Seq(
          m.objType.typeId & 0xff,
          m.methodId & 0xff,
          m.name,
          res.toString,
          res == SSigmaProp,
          hasTypeVar(res),
          m.stype.tDom.length,
          m.explicitTypeArgs.length
        )
        println(cols.mkString("\t"))
      }
    }
  }
}

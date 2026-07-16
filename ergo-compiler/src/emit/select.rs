use ergo_ser::opcode::{Expr, Payload};

use crate::stype::SType;
use crate::typed::{node_tpe, TypedExpr};
use crate::typer::unify::numeric_index;

use super::*;

impl Scope {
    /// Residual `Select` lowering — the no-irBuilder methods the typer leaves
    /// as `Select` (methods.rs `v5s` entries), lowered exactly where Scala's
    /// GraphBuilding lowers them:
    ///
    /// - numeric casts `toByte`..`toBigInt` → same-type unwrap / `Downcast` /
    ///   `Upcast` by ladder order (GraphBuilding.scala:555-563);
    /// - `.size` on a collection-like receiver → `SizeOf` (:520-525);
    /// - `SigmaProp.isProven`/`.propBytes` → dedicated nodes (:527-533);
    /// - Box properties → the `Extract*` family (:541-549) and
    ///   `R0`..`R9[T]` → `ExtractRegisterAs` (:536-539) with the INNER type
    ///   on the wire (`putType(obj.tpe.elemType)`,
    ///   ExtractRegisterAsSerializer.scala serialize);
    /// - tuple `_i` → `SelectField` (:551-553);
    /// - anything else → [`EmitError::UnsupportedNode`] naming the field.
    pub(crate) fn emit_select(
        &mut self,
        obj: &TypedExpr,
        field: &str,
        res_type: Option<&SType>,
        tpe: &SType,
    ) -> Result<Expr, EmitError> {
        let obj_tpe = node_tpe(obj);

        // Numeric casts (GraphBuilding.scala:555-563): the match requires a
        // numeric receiver and a numeric result (resType when the typer set
        // one, else the node type — §1.5 sets both identically for casts).
        if matches!(
            field,
            "toByte" | "toShort" | "toInt" | "toLong" | "toBigInt"
        ) {
            let target = res_type.unwrap_or(tpe);
            if let (Some(src), Some(dst)) = (numeric_index(obj_tpe), numeric_index(target)) {
                let input = self.emit(obj)?;
                return match src.cmp(&dst) {
                    // Same type: `eval(numValue)` — the cast disappears.
                    std::cmp::Ordering::Equal => Ok(input),
                    // `(numValue.tpe max tRes) == numValue.tpe` → Downcast.
                    std::cmp::Ordering::Greater => node(
                        0x7D,
                        Payload::NumericCast {
                            input: Box::new(input),
                            tpe: map_type(target)?,
                        },
                    ),
                    std::cmp::Ordering::Less => node(
                        0x7E,
                        Payload::NumericCast {
                            input: Box::new(input),
                            tpe: map_type(target)?,
                        },
                    ),
                };
            }
        }

        // `col.size` → SizeOf (GraphBuilding.scala:520-525; STuple extends
        // SCollection[SAny], SType.scala:822-825, so tuples are
        // collection-like).
        if field == "size" && matches!(obj_tpe, SType::SColl(_) | SType::STuple(_)) {
            return node(0xB1, self.one(obj)?);
        }

        if matches!(obj_tpe, SType::SSigmaProp) {
            match field {
                "isProven" => return node(0xCF, self.one(obj)?),
                "propBytes" => return node(0xD0, self.one(obj)?),
                _ => {}
            }
        }

        if matches!(obj_tpe, SType::SBox) {
            match field {
                "value" => return node(0xC1, self.one(obj)?),
                "propositionBytes" => return node(0xC2, self.one(obj)?),
                "bytes" => return node(0xC3, self.one(obj)?),
                "bytesWithoutRef" => return node(0xC4, self.one(obj)?),
                "id" => return node(0xC5, self.one(obj)?),
                "creationInfo" => return node(0xC7, self.one(obj)?),
                _ => {}
            }
            // `box.R$i[T]` with a resolved Option result → ExtractRegisterAs.
            // A bare `SELF.R4` (no `[T]`) keeps its polymorphic SFunc type and
            // falls through to the UnsupportedNode below, matching Scala's
            // graph-build error for an unresolved register read.
            if let Some(reg_digit) = field.strip_prefix('R') {
                if let (Ok(reg_id), Some(SType::SOption(inner))) =
                    (reg_digit.parse::<u8>(), res_type)
                {
                    if reg_id <= 9 {
                        return node(
                            0xC6,
                            Payload::ExtractRegisterAs {
                                input: Box::new(self.emit(obj)?),
                                reg_id,
                                tpe: map_type(inner)?,
                            },
                        );
                    }
                }
            }
        }

        // Tuple component `_i` → SelectField, 1-based (GraphBuilding.scala:
        // 551-553 `fn.substring(1).toByte`).
        if let SType::STuple(items) = obj_tpe {
            if let Some(idx_str) = field.strip_prefix('_') {
                if let Ok(idx) = idx_str.parse::<u8>() {
                    if idx == 0 || usize::from(idx) > items.len() {
                        return Err(EmitError::InvalidShape(
                            "tuple field index outside the tuple arity",
                        ));
                    }
                    return node(
                        0x8C,
                        Payload::SelectField {
                            input: Box::new(self.emit(obj)?),
                            field_idx: idx,
                        },
                    );
                }
            }
        }

        Err(EmitError::UnsupportedNode(format!(
            "Select '{field}' on a receiver of type {obj_tpe:?}"
        )))
    }
}

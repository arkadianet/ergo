//! Type reads and constructor checks for the deserialize-substitution pass.
//!
//! A type read can fail even when construction succeeded (for example Filter).
//! Keep that failure as metadata until a constructor or substitution requests it.
//! Source: <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/transformers.scala>.

use crate::ergo_tree::root_type::{infer_node_type, ValDefTypeStore};
use crate::sigma_type::SigmaType;
use ergo_primitives::reader::ReadError;

use super::{Expr, Payload};

/// Failure of a JVM type read or constructor, retaining its exception class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructorError {
    /// Direct ClassCastException, swallowed only inside the rewrite rule.
    ClassCast,
    /// A constructor's require failed (IllegalArgumentException).
    Require,
    /// Tuple field selection is outside its bounds.
    Bounds,
}

impl ConstructorError {
    pub(crate) fn into_read_error(self) -> ReadError {
        match self {
            Self::ClassCast => ReadError::ClassCast("AST constructor/type read".into()),
            Self::Require => ReadError::HardReject("AST constructor require failed".into()),
            Self::Bounds => ReadError::HardReject("AST tuple field out of bounds".into()),
        }
    }
}

/// Cached outcome of reading a node's Scala Value.tpe. None means unknown.
pub type ConstructorType = Result<Option<SigmaType>, ConstructorError>;

/// Computes types from already visited children; never walks a subtree again.
#[derive(Default)]
pub struct ConstructorTypes {
    store: ValDefTypeStore,
}

impl ConstructorTypes {
    /// FuncValue arguments enter the flat parse-order store before its body.
    pub fn bind_args(&mut self, args: &[(u32, Option<SigmaType>)]) {
        for (id, tpe) in args {
            self.store.bindings.insert(*id, tpe.clone());
        }
    }

    /// Derive this node's type, preserving failures of deferred type reads.
    pub fn node_type(&mut self, expr: &Expr, children: &[ConstructorType]) -> ConstructorType {
        let mut iter = children.iter();
        let inferred = infer_node_type(expr, &mut self.store, &[], true, true, &mut |_, _, _| {
            iter.next().and_then(|t| t.as_ref().ok()).cloned().flatten()
        });
        let Expr::Op(node) = expr else {
            return Ok(inferred);
        };
        let child = |i: usize| children.get(i).cloned().unwrap_or(Ok(None));
        match &node.payload {
            Payload::TaggedVar { tpe, .. } => Ok(tpe.clone()),
            Payload::Tuple { .. } => {
                let types = children.iter().cloned().collect::<Result<Vec<_>, _>>()?;
                Ok(types
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .map(SigmaType::STuple))
            }
            Payload::BlockValue { .. } => child(children.len().saturating_sub(1)),
            Payload::ValDef { .. } | Payload::FunDef { .. } => child(0),
            Payload::FuncValue { .. } | Payload::FuncApply { .. } => {
                child(0)?;
                Ok(inferred)
            }
            Payload::ByIndex { .. } => match child(0)? {
                Some(SigmaType::SColl(elem)) => Ok(Some(*elem)),
                // Deliberately preserve real SAny, rather than the conservative
                // root gate's imprecision sentinel: STuple extends SCollection[SAny].
                Some(SigmaType::STuple(_)) => Ok(Some(SigmaType::SAny)),
                Some(_) => Err(ConstructorError::ClassCast),
                None => Ok(None),
            },
            Payload::SelectField { field_idx, .. } => match child(0)? {
                Some(SigmaType::STuple(items)) => {
                    let index = (*field_idx as i8 as isize) - 1;
                    items
                        .get(index as usize)
                        .cloned()
                        .map(Some)
                        .ok_or(ConstructorError::Bounds)
                }
                Some(_) => Err(ConstructorError::ClassCast),
                None => Ok(None),
            },
            Payload::One(_) | Payload::Two(_, _) if matches!(node.opcode, 0xE4 | 0xE5) => {
                match child(0)? {
                    Some(SigmaType::SOption(elem)) => Ok(Some(*elem)),
                    Some(_) => Err(ConstructorError::ClassCast),
                    None => Ok(None),
                }
            }
            Payload::Two(_, _) if node.opcode == 0xAD => match child(1)? {
                Some(SigmaType::SFunc { t_range, .. }) => Ok(Some(SigmaType::SColl(t_range))),
                Some(_) => Err(ConstructorError::ClassCast),
                None => Ok(None),
            },
            Payload::Two(_, _) | Payload::Three(_, _, _) if matches!(node.opcode, 0xB3..=0xB5) => {
                match child(0)? {
                    t @ Some(SigmaType::SColl(_) | SigmaType::STuple(_)) => Ok(t),
                    Some(_) => Err(ConstructorError::ClassCast),
                    None => Ok(None),
                }
            }
            Payload::Three(_, _, _) if node.opcode == 0x95 => child(1),
            Payload::Three(_, _, _) if node.opcode == 0xB0 => child(1),
            Payload::One(_) | Payload::Two(_, _) if matches!(node.opcode, 0x99..=0x9A | 0x9C..=0x9E | 0xA1..=0xA2 | 0xF0..=0xF3 | 0xF5..=0xF8) => {
                child(0)
            }
            _ => Ok(inferred),
        }
    }
}

/// Re-run only the type reads made by a JVM constructor, not builder checks.
/// Reflection rebuilds case classes directly; comparison/equality builders are
/// not called. In particular Eq and SizeOf do not force their children's types.
/// Sources: <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/kiama/rewriting/Rewriter.scala#L215-L319>
/// and <https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/data/shared/src/main/scala/sigma/ast/trees.scala>.
pub fn check_rebuilt_constructor(
    expr: &Expr,
    children: &[ConstructorType],
) -> Result<(), ConstructorError> {
    let Expr::Op(node) = expr else {
        return Ok(());
    };
    let read = |i: usize| children.get(i).cloned().unwrap_or(Ok(None));
    let numeric = |i| -> Result<(), ConstructorError> {
        if let Some(t) = read(i)? {
            if !t.is_numeric() && t != SigmaType::NoType {
                return Err(ConstructorError::Require);
            }
        }
        Ok(())
    };
    match node.opcode {
        // Quadruple.opType and ArithOp.opType are eager vals. These read
        // child types but impose no Boolean/numeric/equal-type constraint.
        0x95 | 0xB7 | 0x99..=0x9A | 0x9C..=0x9E | 0xA1..=0xA2 => {
            for t in children {
                t.as_ref().map_err(|e| *e)?;
            }
        }
        0xF0..=0xF3 | 0xF5..=0xF8 => {
            for i in 0..children.len() {
                numeric(i)?;
            }
        }
        0x7D | 0x7E => {
            if let Some(t) = read(0)? {
                if !t.is_numeric() {
                    return Err(ConstructorError::Require);
                }
            }
        }
        0xE4 | 0xE5 => {
            if let Some(t) = read(0)? {
                if !matches!(t, SigmaType::SOption(_)) {
                    return Err(ConstructorError::ClassCast);
                }
            }
        }
        // These opType vals read the input type but do not cast it to a
        // collection/option or enforce the declared input kind.
        0xCF | 0xD0 | 0xE6 => {
            read(0)?;
        }
        0xB2..=0xB4 => {
            if let Some(t) = read(0)? {
                if !matches!(t, SigmaType::SColl(_) | SigmaType::STuple(_)) {
                    return Err(ConstructorError::ClassCast);
                }
            }
        }
        0xAD => {
            if let Some(t) = read(1)? {
                if !matches!(t, SigmaType::SFunc { .. }) {
                    return Err(ConstructorError::ClassCast);
                }
            }
        }
        0x8C => {
            if let Some(t) = read(0)? {
                let SigmaType::STuple(items) = t else {
                    return Err(ConstructorError::ClassCast);
                };
                if let Payload::SelectField { field_idx, .. } = node.payload {
                    let index = (field_idx as i8 as isize) - 1;
                    if items.get(index as usize).is_none() {
                        return Err(ConstructorError::Bounds);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::reader::VlqReader;

    // ----- oracle parity -----

    #[test]
    fn embedded_constructor_and_deferred_type_failures_match_jvm_607() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/scala/deserialize_constructor_types.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["bytes_hex"].as_str().unwrap()).unwrap();
            let version = case["tree_version"].as_u64().unwrap() as u8;
            let result =
                super::super::parse_body_for_substitution(&mut VlqReader::new(&bytes), version);
            match (
                case["phase"].as_str().unwrap(),
                case["result"].as_str().unwrap(),
            ) {
                ("DECODE_FAIL", "ClassCastException") => assert!(
                    matches!(result, Err(ReadError::ClassCast(_))),
                    "{case}: {result:?}"
                ),
                ("DECODE_FAIL", "IllegalArgumentException") => assert!(
                    matches!(result, Err(ReadError::HardReject(_))),
                    "{case}: {result:?}"
                ),
                ("TYPE_FAIL", "ClassCastException") => assert!(
                    matches!(result, Ok((_, Err(ConstructorError::ClassCast)))),
                    "{case}: {result:?}"
                ),
                ("TYPE", name) => {
                    let (_, tpe) = result.unwrap();
                    let expected = match name {
                        "SAny" => SigmaType::SAny,
                        "SInt$" => SigmaType::SInt,
                        "SBoolean" => SigmaType::SBoolean,
                        "Coll[SInt$]" => SigmaType::SColl(Box::new(SigmaType::SInt)),
                        "SSigmaProp" => SigmaType::SSigmaProp,
                        _ => panic!("unhandled oracle type: {name}"),
                    };
                    assert_eq!(tpe.unwrap(), Some(expected), "{case}");
                }
                _ => panic!("unhandled oracle result: {case}"),
            }
        }
    }
}

//! Structural limits for trees assembled by both recursive and iterative grammar
//! productions. Iterative folds must check each result before wrapping it again.

use crate::{ast::Expr, error::ParseError, span::Pos, stype::SType};

use super::MAX_PARSE_DEPTH;

enum Node<'a> {
    Expr(&'a Expr),
    Type(&'a SType),
}

pub(super) fn check_expr_depth(expr: &Expr) -> Result<(), ParseError> {
    check_depth(Node::Expr(expr), expr.pos())
}

pub(super) fn check_type_depth(tpe: &SType, pos: Pos) -> Result<(), ParseError> {
    check_depth(Node::Type(tpe), pos)
}

fn check_depth(root: Node<'_>, pos: Pos) -> Result<(), ParseError> {
    let mut pending = vec![(root, 1usize)];
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_PARSE_DEPTH {
            return Err(ParseError::TooDeep { pos, depth });
        }
        let child_depth = depth + 1;
        match node {
            Node::Expr(expr) => match expr {
                Expr::IntConst { .. }
                | Expr::LongConst { .. }
                | Expr::BoolConst { .. }
                | Expr::StringConst { .. }
                | Expr::UnitConst { .. } => {}
                Expr::Ident { tpe, .. } => pending.push((Node::Type(tpe), child_depth)),
                Expr::Select { obj, .. } | Expr::MethodCallLike { obj, .. } => {
                    pending.push((Node::Expr(obj), child_depth));
                    if let Expr::MethodCallLike { args, .. } = expr {
                        pending.extend(args.iter().map(|arg| (Node::Expr(arg), child_depth)));
                    }
                }
                Expr::Apply { func, args, .. } => {
                    pending.push((Node::Expr(func), child_depth));
                    pending.extend(args.iter().map(|arg| (Node::Expr(arg), child_depth)));
                }
                Expr::ApplyTypes {
                    input, type_args, ..
                } => {
                    pending.push((Node::Expr(input), child_depth));
                    pending.extend(type_args.iter().map(|tpe| (Node::Type(tpe), child_depth)));
                }
                Expr::Lambda {
                    args,
                    given_res_type,
                    body,
                    ..
                } => {
                    pending.push((Node::Expr(body), child_depth));
                    pending.push((Node::Type(given_res_type), child_depth));
                    pending.extend(args.iter().map(|(_, tpe)| (Node::Type(tpe), child_depth)));
                }
                Expr::Val(val) => {
                    pending.push((Node::Expr(&val.body), child_depth));
                    pending.push((Node::Type(&val.given_type), child_depth));
                }
                Expr::Block {
                    bindings, result, ..
                } => {
                    pending.push((Node::Expr(result), child_depth));
                    for val in bindings {
                        pending.push((Node::Expr(&val.body), child_depth));
                        pending.push((Node::Type(&val.given_type), child_depth));
                    }
                }
                Expr::Tuple { items, .. } => {
                    pending.extend(items.iter().map(|item| (Node::Expr(item), child_depth)));
                }
                Expr::If {
                    condition,
                    true_branch,
                    false_branch,
                    ..
                } => {
                    pending.extend(
                        [condition, true_branch, false_branch]
                            .into_iter()
                            .map(|branch| (Node::Expr(branch), child_depth)),
                    );
                }
                Expr::LogicalNot { input, .. }
                | Expr::Negation { input, .. }
                | Expr::BitInversion { input, .. } => {
                    pending.push((Node::Expr(input), child_depth));
                }
                Expr::Relation { left, right, .. }
                | Expr::ArithOp { left, right, .. }
                | Expr::BitOp { left, right, .. } => {
                    pending.push((Node::Expr(left), child_depth));
                    pending.push((Node::Expr(right), child_depth));
                }
            },
            Node::Type(tpe) => match tpe {
                SType::SColl(inner) | SType::SOption(inner) => {
                    pending.push((Node::Type(inner), child_depth));
                }
                SType::STuple(items) | SType::STypeApply { args: items, .. } => {
                    pending.extend(items.iter().map(|tpe| (Node::Type(tpe), child_depth)));
                }
                SType::SFunc { dom, range, .. } => {
                    pending.push((Node::Type(range), child_depth));
                    pending.extend(dom.iter().map(|tpe| (Node::Type(tpe), child_depth)));
                }
                SType::NoType
                | SType::SBoolean
                | SType::SByte
                | SType::SShort
                | SType::SInt
                | SType::SLong
                | SType::SBigInt
                | SType::SUnsignedBigInt
                | SType::SGroupElement
                | SType::SSigmaProp
                | SType::SAvlTree
                | SType::SContext
                | SType::SGlobal
                | SType::SHeader
                | SType::SPreHeader
                | SType::SString
                | SType::SBox
                | SType::SUnit
                | SType::SAny
                | SType::STypeVar(_) => {}
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse, parse_type};

    // ----- helpers -----

    fn infix(operands: usize) -> String {
        std::iter::repeat_n("1", operands)
            .collect::<Vec<_>>()
            .join(" - ")
    }

    fn too_deep(result: Result<Expr, ParseError>) {
        assert!(matches!(result, Err(ParseError::TooDeep { depth, .. })
            if depth == MAX_PARSE_DEPTH + 1));
    }

    // ----- happy path -----

    #[test]
    fn flat_infix_at_structural_limit_parses_and_drops() {
        let expr = parse(&infix(MAX_PARSE_DEPTH), 3).unwrap();
        check_expr_depth(&expr).unwrap();
        drop(expr);
    }

    #[test]
    fn suffix_and_stable_identifier_at_structural_limit_parse() {
        for suffix in [".x", "()", "[Int]", "().x"] {
            let layers = if suffix == "().x" { 2 } else { 1 };
            let source = format!("f{}", suffix.repeat((MAX_PARSE_DEPTH - 2) / layers));
            let expr = parse(&source, 3).unwrap();
            check_expr_depth(&expr).unwrap();
        }
    }

    // ----- error paths -----

    #[test]
    fn flat_infix_one_past_structural_limit_errors() {
        too_deep(parse(&infix(MAX_PARSE_DEPTH + 1), 3));
    }

    #[test]
    fn suffix_and_stable_identifier_one_past_structural_limit_error() {
        for suffix in [".x", "()", "[Int]", "().x"] {
            too_deep(parse(&format!("f{}", suffix.repeat(MAX_PARSE_DEPTH)), 3));
        }
    }

    #[test]
    fn mixed_nested_and_flat_depth_is_checked_together() {
        let source = format!("if (true) {} else 0", infix(MAX_PARSE_DEPTH));
        too_deep(parse(&source, 3));
        let source = format!("f({})", infix(MAX_PARSE_DEPTH));
        too_deep(parse(&source, 3));
    }

    #[test]
    fn flat_type_folds_reject_both_associativities() {
        for op in [" + ", " +: "] {
            let accepted = std::iter::repeat_n("Int", MAX_PARSE_DEPTH)
                .collect::<Vec<_>>()
                .join(op);
            parse_type(&accepted, 3).unwrap();
            let rejected = format!("{accepted}{op}Int");
            assert!(matches!(parse_type(&rejected, 3),
                Err(ParseError::TooDeep { depth, .. }) if depth == MAX_PARSE_DEPTH + 1));
        }
    }

    #[test]
    fn long_flat_inputs_and_error_cleanup_fit_bounded_stack() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                for source in [infix(4096), format!("f{}", "().x".repeat(4096))] {
                    too_deep(parse(&source, 3));
                    assert!(crate::compile(
                        &crate::ScriptEnv::new(),
                        &source,
                        3,
                        crate::NetworkPrefix::Mainnet
                    )
                    .is_err());
                }
                let accepted = parse(&infix(MAX_PARSE_DEPTH), 3).unwrap();
                drop(accepted);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

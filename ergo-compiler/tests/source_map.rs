//! P5-B: the emit-time source map — compiled IR node (preorder id over the
//! pre-segregation root) → byte offset into the authored source.
//!
//! Design: `docs/ergoscript-compiler-source-map-design.md`. The map is
//! resolved against the FINAL tree (after every rewrite pass), so a
//! consumer's `ergo_ser::opcode::preorder` walk of the parsed tree body
//! agrees with `SourceMap::node_count` by construction.

use ergo_compiler::{compile_with_source_map, NetworkPrefix, ScriptEnv, SourceMap};
use ergo_ser::opcode::{node_opcode, preorder};

fn compile(src: &str) -> (ergo_compiler::CompileResult, SourceMap) {
    compile_with_source_map(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).expect("compiles")
}

/// Offset of the first occurrence of `needle` in `src`.
fn at(src: &str, needle: &str) -> u32 {
    src.find(needle).expect("needle present") as u32
}

// ----- happy path -----

#[test]
fn source_map_cites_each_lowered_node_at_its_source_offset() {
    let src = "sigmaProp(HEIGHT > 100 && OUTPUTS(0).value > 5L)";
    let (out, map) = compile(src);
    let walk: Vec<(u64, u8)> = preorder(&out.ergo_tree.body)
        .map(|(id, e)| (id, node_opcode(e)))
        .collect();
    assert_eq!(map.node_count(), walk.len() as u64);
    // Every opcode tag the map carries matches the walk — the alignment check
    // a consumer runs before citing anything.
    assert!(map.aligns_with(walk.iter().map(|(_, op)| *op)));

    let by_op = |op: u8| {
        walk.iter()
            .find(|(_, o)| *o == op)
            .map(|(id, _)| *id)
            .unwrap()
    };
    // BinAnd (0xED) at `&&`'s left operand? No: the typed node's pos is the
    // BinAnd expression's start, which the parser records at its left operand.
    assert_eq!(map.offset(by_op(0xED)), Some(at(src, "HEIGHT > 100")));
    assert_eq!(map.offset(by_op(0xA3)), Some(at(src, "HEIGHT"))); // Height
    assert_eq!(map.offset(by_op(0xA5)), Some(at(src, "OUTPUTS"))); // Outputs
    assert_eq!(map.offset(by_op(0xC1)), Some(at(src, "OUTPUTS(0).value"))); // ExtractAmount
}

#[test]
fn source_map_offsets_convert_to_line_and_column() {
    let src = "{\n  val h = HEIGHT\n  sigmaProp(h > 100 && OUTPUTS.size == 1)\n}";
    let (out, map) = compile(src);
    let walk: Vec<(u64, u8)> = preorder(&out.ergo_tree.body)
        .map(|(id, e)| (id, node_opcode(e)))
        .collect();
    let outputs = walk.iter().find(|(_, o)| *o == 0xA5).unwrap().0;
    let off = map.offset(outputs).expect("OUTPUTS is cited");
    assert_eq!(off, at(src, "OUTPUTS"));
    assert_eq!(ergo_compiler::span::line_col(src, off), (3, 24));
}

// ----- synthesized nodes are not citable -----

#[test]
fn source_map_leaves_a_folded_constant_uncited() {
    // `1 + 2` folds to `3`: the folded Const has no source construct.
    let src = "sigmaProp(HEIGHT > 1 + 2)";
    let (out, map) = compile(src);
    // After segregation the body holds ConstPlaceholder (0x73) per constant.
    let consts: Vec<u64> = preorder(&out.ergo_tree.body)
        .filter(|(_, e)| matches!(node_opcode(e), 0x00 | 0x73))
        .map(|(id, _)| id)
        .collect();
    assert_eq!(consts.len(), 1, "exactly one constant after folding");
    assert_eq!(map.offset(consts[0]), None);
    // ...while the surrounding nodes stay cited.
    let gt = preorder(&out.ergo_tree.body)
        .find(|(_, e)| node_opcode(e) == 0x91)
        .unwrap()
        .0;
    assert_eq!(map.offset(gt), Some(at(src, "HEIGHT > 1 + 2")));
}

#[test]
fn source_map_cites_a_typer_inserted_upcast_at_its_operand() {
    // Mixed-width comparison: the typer widens `HEIGHT` with an Upcast. The
    // typer pins rebuilt nodes at the node being rewritten (P5-A, Scala's
    // `currentSrcCtx`), so the cast is cited where `HEIGHT` is — not left
    // uncited like an emit-time synthesis would be.
    let src = "sigmaProp(HEIGHT > 5L)";
    let (out, map) = compile(src);
    let upcasts: Vec<u64> = preorder(&out.ergo_tree.body)
        .filter(|(_, e)| node_opcode(e) == 0x7E) // Upcast
        .map(|(id, _)| id)
        .collect();
    assert_eq!(upcasts.len(), 1, "one Upcast expected");
    assert_eq!(map.offset(upcasts[0]), Some(at(src, "HEIGHT")));
}

// ----- identical subexpressions -----

#[test]
fn source_map_cites_identical_subexpressions_at_their_own_offsets() {
    let src = "sigmaProp(SELF.value > 1L && SELF.value > 2L)";
    let (out, map) = compile(src);
    let amounts: Vec<u64> = preorder(&out.ergo_tree.body)
        .filter(|(_, e)| node_opcode(e) == 0xC1) // ExtractAmount
        .map(|(id, _)| id)
        .collect();
    // CSE may hoist `SELF.value` into one ValDef: then one occurrence remains
    // and it is cited at the FIRST spelling; otherwise both are cited in order.
    // A property read's position is its field name (Scala's Select pos).
    let first = at(src, "value > 1L");
    let second = at(src, "value > 2L");
    match amounts.as_slice() {
        [one] => assert_eq!(map.offset(*one), Some(first)),
        [a, b] => {
            assert_eq!(map.offset(*a), Some(first));
            assert_eq!(map.offset(*b), Some(second));
        }
        other => panic!("unexpected ExtractAmount count {}", other.len()),
    }
}

// ----- round-trips -----

#[test]
fn source_map_does_not_change_the_compiled_bytes() {
    let src = "{ val o = OUTPUTS(0); sigmaProp(o.value >= SELF.value && o.propositionBytes == SELF.propositionBytes) }";
    let plain = ergo_compiler::compile(&ScriptEnv::new(), src, 3, NetworkPrefix::Testnet).unwrap();
    let (mapped, _) = compile(src);
    assert_eq!(plain.tree_bytes, mapped.tree_bytes);
}

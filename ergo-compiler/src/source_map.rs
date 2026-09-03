//! P5-B: the emit-time source map — compiled IR node → source offset.
//!
//! Design record: `docs/ergoscript-compiler-source-map-design.md`. What is
//! implemented here differs from that doc's sketch in one way, for a reason
//! the doc did not account for: six rewrite passes run AFTER emit
//! (`tree::graph_build` — cast folds, isProven fusion, constant folding,
//! dead-val pruning, lowering, CSE), so an origin tree built alongside emit
//! describes a tree that no longer exists by the time bytes are written.
//! Threading origins through every pass would touch ~5k lines of
//! oracle-graded code for no parity gain.
//!
//! Instead:
//!
//! 1. **Emit records origins** — for every typed node it lowers, the
//!    serialized bytes of the IR subtree it produced with the typed node's
//!    `pos` ([`Origins`]). After emit, those are pinned onto the emit-time
//!    tree node by node ([`EmitTree`]): on the untouched emit output every
//!    recorded subtree is literally present, so the pinning is exact.
//! 2. **After the pipeline, the emit-time tree is aligned top-down against
//!    the final tree** ([`resolve`]). A final node whose opcode and arity
//!    match its emit-time counterpart is cited at that node's position and
//!    the children are aligned pairwise; so a fold deep in a subtree uncites
//!    only the folded node, never its ancestors. Three rewrite shapes get
//!    their own rule: a `BlockValue` the CSE pass wrapped around the root
//!    (align through its result; each hoisted `ValDef` rhs is found among
//!    the emit-time subtrees by bytes), a `ValUse` standing in for a hoisted
//!    subtree (cited at that spelling when the `ValDef` rhs bytes match),
//!    and an arity change such as an inserted `Upcast` (the node is uncited;
//!    each child is re-found by bytes and aligned from there).
//!
//! Anything the alignment cannot place — a folded constant, an inserted
//! cast, a synthesized `ValDef` — stays uncited, which is the design's
//! "synthesized nodes are not citable" rule. Silent mis-citation in an
//! auditing tool is worse than no citation.
//!
//! The map is keyed by the preorder id over the pre-segregation root, which
//! is also what a consumer gets by parsing the tree body: constant
//! segregation replaces each inline `Const` with a `ConstPlaceholder`
//! one-for-one, so ids and counts are unchanged. `SourceMap` carries the
//! node count and per-id opcode tags so a consumer can check alignment
//! before citing anything.

use std::collections::{BTreeMap, HashMap, VecDeque};

use ergo_primitives::writer::VlqWriter;
use ergo_ser::opcode::{node_opcode, preorder, write_expr, Expr, Payload};

use crate::span::Pos;

/// Emit-time record: `(subtree bytes, source offset)` per lowered typed
/// node, in emit (post-order) sequence.
#[derive(Debug, Default)]
pub(crate) struct Origins {
    entries: Vec<(Vec<u8>, Pos)>,
}

impl Origins {
    pub(crate) fn record(&mut self, produced: &Expr, pos: Pos) {
        // `0` is P5-A's "unset" (Scala's `Nullable.None`, printed `0:0`):
        // synthesized receivers and env constants carry it. Not a citation.
        if pos == 0 {
            return;
        }
        if let Some(bytes) = subtree_bytes(produced) {
            self.entries.push((bytes, pos));
        }
    }
}

/// Serialized form of one IR subtree (constants inline). `None` only for
/// shapes the writer refuses, which never reach a successful compile.
fn subtree_bytes(e: &Expr) -> Option<Vec<u8>> {
    let mut w = VlqWriter::new();
    write_expr(&mut w, e, false).ok()?;
    Some(w.result())
}

/// Compiled-tree node (preorder id) → source offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMap {
    offsets: BTreeMap<u64, Pos>,
    tags: Vec<u8>,
}

impl SourceMap {
    /// Source offset of node `id`, if that node originates from a source
    /// construct (synthesized and ambiguous nodes answer `None`).
    pub fn offset(&self, id: u64) -> Option<Pos> {
        self.offsets.get(&id).copied()
    }

    /// Number of nodes in the tree this map describes — a consumer's
    /// preorder walk must produce exactly this many.
    pub fn node_count(&self) -> u64 {
        self.tags.len() as u64
    }

    /// The opcode tag ([`node_opcode`]) of every node by id.
    pub fn tags(&self) -> &[u8] {
        &self.tags
    }

    /// `true` when `walk` (a consumer's opcode tags in preorder) matches this
    /// map's tree node for node. Check this before citing anything.
    pub fn aligns_with(&self, walk: impl IntoIterator<Item = u8>) -> bool {
        let got: Vec<u8> = walk.into_iter().collect();
        got == self.tags
    }

    /// Every citation, in id order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, Pos)> + '_ {
        self.offsets.iter().map(|(id, p)| (*id, *p))
    }
}

/// The emit-time tree with a source position pinned on each node that
/// originates from a typed node (`None` = synthesized during emit).
struct EmitTree<'a> {
    nodes: Vec<&'a Expr>,
    pos: Vec<Option<Pos>>,
    children: Vec<Vec<usize>>,
    /// Subtree bytes → emit ids in preorder, for re-finding moved subtrees.
    by_bytes: HashMap<Vec<u8>, VecDeque<usize>>,
    /// Emit ids already paired with a final node (structurally or by
    /// bytes). A recovery by bytes must never hand out one of these again.
    consumed: Vec<bool>,
}

impl<'a> EmitTree<'a> {
    fn build(root: &'a Expr, origins: &Origins) -> Self {
        // Recorded (bytes → positions) in emit order; identical disjoint
        // subtrees are recorded left to right, the same order preorder
        // visits them.
        let mut recorded: HashMap<&[u8], VecDeque<Pos>> = HashMap::new();
        for (bytes, pos) in &origins.entries {
            recorded
                .entry(bytes.as_slice())
                .or_default()
                .push_back(*pos);
        }
        let mut nodes = Vec::new();
        let mut pos = Vec::new();
        let mut by_bytes: HashMap<Vec<u8>, VecDeque<usize>> = HashMap::new();
        for (id, e) in preorder(root) {
            nodes.push(e);
            let bytes = subtree_bytes(e).unwrap_or_default();
            pos.push(
                recorded
                    .get_mut(bytes.as_slice())
                    .and_then(|q| q.pop_front()),
            );
            by_bytes.entry(bytes).or_default().push_back(id as usize);
        }
        // Children by id: recompute from the walk order (a child's id is the
        // parent's id + 1 + the sizes of earlier siblings).
        let mut children = vec![Vec::new(); nodes.len()];
        fn fill(e: &Expr, id: &mut usize, children: &mut Vec<Vec<usize>>) {
            let me = *id;
            *id += 1;
            for c in ergo_ser::opcode::children(e) {
                children[me].push(*id);
                fill(c, id, children);
            }
        }
        let mut id = 0;
        fill(root, &mut id, &mut children);
        let consumed = vec![false; nodes.len()];
        EmitTree {
            nodes,
            pos,
            children,
            by_bytes,
            consumed,
        }
    }

    /// Mark an emit node as paired with a final node.
    fn consume(&mut self, id: usize) {
        self.consumed[id] = true;
    }

    /// Take the next unconsumed emit node with exactly these subtree bytes.
    fn find(&mut self, bytes: &[u8]) -> Option<usize> {
        let q = self.by_bytes.get_mut(bytes)?;
        while let Some(id) = q.pop_front() {
            if !self.consumed[id] {
                self.consumed[id] = true;
                return Some(id);
            }
        }
        None
    }
}

/// Opcode and arity: the shallow shape two nodes must share to be aligned.
fn shape(e: &Expr) -> (u8, usize) {
    (node_opcode(e), ergo_ser::opcode::children(e).len())
}

/// Resolve emit-time origins against the final pre-segregation `root`
/// (`emit_root` is the tree emit produced, before any rewrite pass), and tag
/// nodes from `body` — the same final tree after constant segregation (one
/// `ConstPlaceholder` per inline `Const`, identical shape), which is what a
/// consumer parses and walks. For an unsegregated tree pass `root` as `body`.
pub(crate) fn resolve(emit_root: &Expr, root: &Expr, body: &Expr, origins: &Origins) -> SourceMap {
    let mut emit = EmitTree::build(emit_root, origins);

    // Final tree: ids, children, and ValDef id → rhs bytes for the ValUse rule.
    let final_nodes: Vec<&Expr> = preorder(root).map(|(_, e)| e).collect();
    let mut final_children = vec![Vec::new(); final_nodes.len()];
    fn fill(e: &Expr, id: &mut usize, children: &mut Vec<Vec<usize>>) {
        let me = *id;
        *id += 1;
        for c in ergo_ser::opcode::children(e) {
            children[me].push(*id);
            fill(c, id, children);
        }
    }
    let mut id = 0;
    fill(root, &mut id, &mut final_children);
    let mut valdef_rhs_bytes: HashMap<u32, Vec<u8>> = HashMap::new();
    for e in &final_nodes {
        if let Expr::Op(n) = e {
            if let Payload::ValDef { id, rhs, .. } = &n.payload {
                if let Some(b) = subtree_bytes(rhs) {
                    valdef_rhs_bytes.insert(*id, b);
                }
            }
        }
    }

    // Emit-time ValDef id → emit id of its rhs, for the inlined-`val` rule.
    let mut emit_valdef_rhs: HashMap<u32, usize> = HashMap::new();
    for (i, e) in emit.nodes.iter().enumerate() {
        if let Expr::Op(n) = e {
            if let Payload::ValDef { id, .. } = &n.payload {
                emit_valdef_rhs.insert(*id, emit.children[i][0]);
            }
        }
    }
    let valdef_id = |e: &Expr| match e {
        Expr::Op(n) => match &n.payload {
            Payload::ValDef { id, .. } | Payload::FunDef { id, .. } => Some(*id),
            _ => None,
        },
        _ => None,
    };
    let is_block =
        |e: &Expr| matches!(e, Expr::Op(n) if matches!(n.payload, Payload::BlockValue { .. }));

    let mut offsets = BTreeMap::new();
    // FIFO: pairs are processed in preorder, so a left sibling claims its
    // emit node before a right sibling's byte recovery could take it.
    let mut work: VecDeque<(usize, usize)> = VecDeque::from([(0, 0)]); // (emit id, final id)
    while let Some((ei, fi)) = work.pop_front() {
        let (e, f) = (emit.nodes[ei], final_nodes[fi]);
        // A `val` the pipeline inlined: the emit side reads it through a
        // ValUse where the final tree has the rhs itself. Align the rhs.
        if let Expr::Op(n) = e {
            if let Payload::ValUse { id } = &n.payload {
                if !matches!(f, Expr::Op(m) if matches!(m.payload, Payload::ValUse { .. })) {
                    if let Some(&rhs) = emit_valdef_rhs.get(id) {
                        work.push_back((rhs, fi));
                    }
                    continue;
                }
            }
        }
        // Both blocks: results align; items pair by binding id (pruning
        // drops items, CSE adds them — ids are stable across both).
        if is_block(e) && is_block(f) {
            let ek = emit.children[ei].clone();
            let fk = &final_children[fi];
            emit.consume(ei);
            work.push_back((ek[ek.len() - 1], fk[fk.len() - 1]));
            for &fitem in &fk[..fk.len() - 1] {
                let fid = valdef_id(final_nodes[fitem]);
                if let Some(&eitem) = ek[..ek.len() - 1]
                    .iter()
                    .find(|&&ei2| valdef_id(emit.nodes[ei2]) == fid)
                {
                    work.push_back((eitem, fitem));
                } else if let Some(src) = final_children[fitem]
                    .first()
                    .and_then(|&r| subtree_bytes(final_nodes[r]))
                    .and_then(|b| emit.find(&b))
                {
                    work.push_back((src, final_children[fitem][0]));
                }
            }
            continue;
        }
        // An emit-time block the pipeline dissolved (every `val` inlined or
        // pruned): look through it to the result.
        if is_block(e) && !is_block(f) {
            let last = *emit.children[ei].last().expect("a block has a result");
            emit.consume(ei);
            work.push_back((last, fi));
            continue;
        }
        match f {
            // A hoisted subtree's use site: cite at the spelling it stands for.
            Expr::Op(n) if matches!(n.payload, Payload::ValUse { .. }) => {
                if let Payload::ValUse { id } = &n.payload {
                    let same = valdef_rhs_bytes
                        .get(id)
                        .map(|b| Some(b) == subtree_bytes(e).as_ref());
                    if same == Some(true) {
                        emit.consume(ei);
                        if let Some(p) = emit.pos[ei] {
                            offsets.insert(fi as u64, p);
                        }
                    }
                }
                continue;
            }
            // A CSE block wrapped around what emit produced: look through it.
            Expr::Op(n)
                if matches!(n.payload, Payload::BlockValue { .. }) && shape(e).0 != n.opcode =>
            {
                let kids = &final_children[fi];
                let (items, result) = kids.split_at(kids.len() - 1);
                work.push_back((ei, result[0]));
                for &item in items {
                    if let Expr::Op(v) = final_nodes[item] {
                        if let Payload::ValDef { rhs, .. } = &v.payload {
                            if let Some(src) = subtree_bytes(rhs).and_then(|b| emit.find(&b)) {
                                work.push_back((src, final_children[item][0]));
                            }
                        }
                    }
                }
                continue;
            }
            _ => {}
        }
        if shape(e) == shape(f) {
            emit.consume(ei);
            if let Some(p) = emit.pos[ei] {
                offsets.insert(fi as u64, p);
            }
            for (&ec, &fc) in emit.children[ei].iter().zip(&final_children[fi]) {
                work.push_back((ec, fc));
            }
        } else if emit.children[ei].len() == final_children[fi].len() {
            // Rewritten in place (lowering): the node is uncited, its
            // children are very likely untouched.
            emit.consume(ei);
            for (&ec, &fc) in emit.children[ei].iter().zip(&final_children[fi]) {
                work.push_back((ec, fc));
            }
        } else {
            // Arity changed (an inserted cast, a collapsed node): the emit
            // node is NOT consumed — it may be one of the children re-found
            // by bytes below (an inserted cast wraps the very node we hold).
            for &fc in &final_children[fi] {
                if let Some(src) = subtree_bytes(final_nodes[fc]).and_then(|b| emit.find(&b)) {
                    work.push_back((src, fc));
                }
            }
        }
    }

    let tags: Vec<u8> = preorder(body).map(|(_, e)| node_opcode(e)).collect();
    debug_assert_eq!(tags.len(), final_nodes.len());
    SourceMap { offsets, tags }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_ser::opcode::IrNode;
    use ergo_ser::sigma_type::SigmaType;
    use ergo_ser::sigma_value::SigmaValue;

    // ----- helpers -----

    fn height() -> Expr {
        Expr::Op(IrNode {
            opcode: 0xA3,
            payload: Payload::Zero,
        })
    }
    fn int(v: i32) -> Expr {
        Expr::Const {
            tpe: SigmaType::SInt,
            val: SigmaValue::Int(v),
        }
    }
    fn gt(a: Expr, b: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: 0x91,
            payload: Payload::Two(Box::new(a), Box::new(b)),
        })
    }
    fn plus(a: Expr, b: Expr) -> Expr {
        Expr::Op(IrNode {
            opcode: 0x9A,
            payload: Payload::Two(Box::new(a), Box::new(b)),
        })
    }

    // ----- happy path -----

    #[test]
    fn resolve_identical_trees_cite_every_recorded_node() {
        let root = gt(height(), int(3));
        let mut o = Origins::default();
        o.record(&height(), 10);
        o.record(&gt(height(), int(3)), 4);
        let map = resolve(&root, &root, &root, &o);
        assert_eq!(map.node_count(), 3);
        assert_eq!(map.offset(0), Some(4));
        assert_eq!(map.offset(1), Some(10));
        assert_eq!(map.offset(2), None); // `3` was never recorded
        assert!(map.aligns_with([0x91, 0xA3, 0x00]));
    }

    #[test]
    fn resolve_folded_child_uncites_only_that_node() {
        // emit: GT(Height, Plus(1, 2)) → final: GT(Height, 3)
        let emit_root = gt(height(), plus(int(1), int(2)));
        let final_root = gt(height(), int(3));
        let mut o = Origins::default();
        o.record(&int(1), 12);
        o.record(&int(2), 16);
        o.record(&plus(int(1), int(2)), 12);
        o.record(&height(), 3);
        o.record(&emit_root, 3);
        let map = resolve(&emit_root, &final_root, &final_root, &o);
        assert_eq!(map.offset(0), Some(3)); // GT still cited
        assert_eq!(map.offset(1), Some(3)); // Height
        assert_eq!(map.offset(2), None); // the folded 3
    }

    // ----- error paths -----

    #[test]
    fn resolve_byte_recovery_skips_an_already_aligned_duplicate() {
        // emit: GT(Height@10, Height@30) → final: GT(Height, Upcast(Height)).
        // The left Height aligns structurally; the right one is recovered by
        // bytes and must get the SECOND spelling, not the first again.
        let upcast = Expr::Op(IrNode {
            opcode: 0x7E,
            payload: Payload::NumericCast {
                input: Box::new(height()),
                tpe: SigmaType::SLong,
            },
        });
        let emit_root = gt(height(), height());
        let final_root = gt(height(), upcast);
        let mut o = Origins::default();
        o.record(&height(), 10);
        o.record(&height(), 30);
        o.record(&emit_root, 4);
        let map = resolve(&emit_root, &final_root, &final_root, &o);
        assert_eq!(map.offset(1), Some(10));
        assert_eq!(map.offset(2), None); // the cast itself
        assert_eq!(map.offset(3), Some(30));
    }

    #[test]
    fn resolve_arity_change_recovers_children_by_bytes() {
        // emit: GT(Height, 5) → final: GT(Upcast(Height), 5): Upcast uncited,
        // Height re-found.
        let upcast = Expr::Op(IrNode {
            opcode: 0xD8,
            payload: Payload::NumericCast {
                input: Box::new(height()),
                tpe: SigmaType::SLong,
            },
        });
        let emit_root = gt(height(), int(5));
        let final_root = gt(upcast, int(5));
        let mut o = Origins::default();
        o.record(&height(), 10);
        o.record(&emit_root, 4);
        let map = resolve(&emit_root, &final_root, &final_root, &o);
        assert_eq!(map.offset(0), Some(4));
        assert_eq!(map.offset(1), None); // Upcast
        assert_eq!(map.offset(2), Some(10)); // Height inside it
    }
}

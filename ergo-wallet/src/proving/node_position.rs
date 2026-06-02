//! NodePosition — tree-path tracker for sigma-proof hints.
//!
//! Mirrors Scala `sigma.serialization.NodePosition`. Wire format
//! is identical: depth-first child indices from the root.

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePosition {
    pub positions: Vec<u32>,
}

impl NodePosition {
    pub fn crypto_tree_prefix() -> Self {
        Self { positions: vec![0] }
    }
    pub fn child(&self, idx: u32) -> Self {
        let mut next = self.positions.clone();
        next.push(idx);
        Self { positions: next }
    }
}

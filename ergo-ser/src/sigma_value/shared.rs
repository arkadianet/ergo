//! Immutable proposition children. Sharing mirrors Scala's reference-valued
//! propositions without expanding repeated subtrees when evaluator values clone.

use std::{collections::HashSet, fmt, ops::Deref, sync::Arc};

use super::SigmaBoolean;

struct Children {
    values: Vec<SigmaBoolean>,
    size: usize,
}

/// Immutable, shared children of a compound sigma proposition.
///
/// Construct with `Vec<SigmaBoolean>::into()`. Cloning shares the children;
/// iteration and indexing expose borrowed propositions. The cached logical size
/// counts repeated occurrences, even when their storage is shared.
#[derive(Clone)]
pub struct SigmaChildren {
    // Taken only during iterative destruction. Every observable instance has
    // Some; taking ownership prevents recursive Arc destruction of a long DAG.
    inner: Option<Arc<Children>>,
}

impl From<Vec<SigmaBoolean>> for SigmaChildren {
    fn from(values: Vec<SigmaBoolean>) -> Self {
        let size = values
            .iter()
            .fold(0usize, |sum, value| sum.saturating_add(value.size()));
        Self {
            inner: Some(Arc::new(Children { values, size })),
        }
    }
}

impl FromIterator<SigmaBoolean> for SigmaChildren {
    fn from_iter<T: IntoIterator<Item = SigmaBoolean>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl SigmaChildren {
    pub(super) fn size(&self) -> usize {
        self.inner.as_ref().expect("live proposition children").size
    }
}

impl Deref for SigmaChildren {
    type Target = [SigmaBoolean];

    fn deref(&self) -> &Self::Target {
        &self
            .inner
            .as_ref()
            .expect("live proposition children")
            .values
    }
}

impl<'a> IntoIterator for &'a SigmaChildren {
    type Item = &'a SigmaBoolean;
    type IntoIter = std::slice::Iter<'a, SigmaBoolean>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for SigmaChildren {
    type Item = SigmaBoolean;
    type IntoIter = SigmaChildrenIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let end = self.len();
        SigmaChildrenIntoIter {
            children: self,
            start: 0,
            end,
        }
    }
}

/// Owning iterator over immutable proposition children. Each returned value
/// shares its descendants; iteration does not copy the entire child list.
pub struct SigmaChildrenIntoIter {
    children: SigmaChildren,
    start: usize,
    end: usize,
}

impl Iterator for SigmaChildrenIntoIter {
    type Item = SigmaBoolean;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start == self.end {
            return None;
        }
        let child = self.children[self.start].clone();
        self.start += 1;
        Some(child)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.end - self.start;
        (len, Some(len))
    }
}

impl DoubleEndedIterator for SigmaChildrenIntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start == self.end {
            return None;
        }
        self.end -= 1;
        Some(self.children[self.end].clone())
    }
}

impl ExactSizeIterator for SigmaChildrenIntoIter {}
impl std::iter::FusedIterator for SigmaChildrenIntoIter {}

impl fmt::Debug for SigmaChildren {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        list.entries(self.iter().take(16));
        if self.len() > 16 {
            list.entry(&"…");
        }
        list.finish()
    }
}

impl Drop for SigmaChildren {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        // All owners use into_inner: even concurrent final drops leave exactly
        // one owner responsible for iterative destruction. try_unwrap followed
        // by dropping its Err can destroy Children recursively in that race.
        let Some(children) = Arc::into_inner(inner) else {
            return;
        };
        let mut pending = children.values;
        while let Some(mut child) = pending.pop() {
            if let SigmaBoolean::Cand(children)
            | SigmaBoolean::Cor(children)
            | SigmaBoolean::Cthreshold { children, .. } = &mut child
            {
                if let Some(inner) = children.inner.take() {
                    if let Some(children) = Arc::into_inner(inner) {
                        pending.extend(children.values);
                    }
                }
            }
        }
    }
}

impl SigmaBoolean {
    /// Logical Scala `SigmaBoolean.size`. DHT tuples count their four points.
    /// Saturates when the expanded proposition exceeds the platform's size
    /// representation; storage itself remains proportional to the shared graph.
    pub fn size(&self) -> usize {
        match self {
            Self::TrivialProp(_) | Self::ProveDlog(_) => 1,
            Self::ProveDHTuple { .. } => 4,
            Self::Cand(children) | Self::Cor(children) | Self::Cthreshold { children, .. } => {
                children.size().saturating_add(1)
            }
        }
    }
}

impl PartialEq for SigmaBoolean {
    fn eq(&self, other: &Self) -> bool {
        let mut pending = vec![(self, other)];
        let mut compared = HashSet::new();
        while let Some((left, right)) = pending.pop() {
            if !compared.insert((left as *const Self, right as *const Self)) {
                continue;
            }
            let children = match (left, right) {
                (Self::TrivialProp(a), Self::TrivialProp(b)) if a == b => None,
                (Self::ProveDlog(a), Self::ProveDlog(b)) if a == b => None,
                (
                    Self::ProveDHTuple {
                        g: ag,
                        h: ah,
                        u: au,
                        v: av,
                    },
                    Self::ProveDHTuple {
                        g: bg,
                        h: bh,
                        u: bu,
                        v: bv,
                    },
                ) if (ag, ah, au, av) == (bg, bh, bu, bv) => None,
                (Self::Cand(a), Self::Cand(b)) | (Self::Cor(a), Self::Cor(b)) => Some((a, b)),
                (
                    Self::Cthreshold { k: ak, children: a },
                    Self::Cthreshold { k: bk, children: b },
                ) if ak == bk => Some((a, b)),
                _ => return false,
            };
            if let Some((a, b)) = children {
                if a.len() != b.len() {
                    return false;
                }
                if !Arc::ptr_eq(
                    a.inner.as_ref().expect("live children"),
                    b.inner.as_ref().expect("live children"),
                ) {
                    pending.extend(a.iter().zip(b.iter()));
                }
            }
        }
        true
    }
}

impl Eq for SigmaBoolean {}

impl fmt::Debug for SigmaBoolean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn write(
            value: &SigmaBoolean,
            f: &mut fmt::Formatter<'_>,
            remaining: &mut usize,
        ) -> fmt::Result {
            if *remaining == 0 {
                return f.write_str("…");
            }
            *remaining -= 1;
            let (label, children, closing) = match value {
                SigmaBoolean::TrivialProp(value) => return write!(f, "TrivialProp({value})"),
                SigmaBoolean::ProveDlog(value) => return write!(f, "ProveDlog({value:?})"),
                SigmaBoolean::ProveDHTuple { g, h, u, v } => {
                    return write!(
                        f,
                        "ProveDHTuple {{ g: {g:?}, h: {h:?}, u: {u:?}, v: {v:?} }}"
                    )
                }
                SigmaBoolean::Cand(children) => ("Cand", children, "])"),
                SigmaBoolean::Cor(children) => ("Cor", children, "])"),
                SigmaBoolean::Cthreshold { k, children } => {
                    write!(f, "Cthreshold(k={k}, ")?;
                    ("children", children, "]))")
                }
            };
            write!(f, "{label}([").and_then(|()| {
                for (index, child) in children.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write(child, f, remaining)?;
                    if *remaining == 0 {
                        break;
                    }
                }
                f.write_str(closing)
            })
        }
        write(self, f, &mut 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_primitives::group_element::GroupElement;

    // ----- helpers -----

    fn doubling(layers: usize, key: u8) -> SigmaBoolean {
        let mut tree = SigmaBoolean::ProveDlog(GroupElement::from_bytes([key; 33]));
        for _ in 0..layers {
            tree = SigmaBoolean::Cand(vec![tree.clone(), tree].into());
        }
        tree
    }

    // ----- happy path -----

    #[test]
    fn proposition_clone_shares_children_and_keeps_logical_size() {
        let tree = doubling(20, 2);
        assert_eq!(tree.size(), (1 << 21) - 1);
        let clone = tree.clone();
        match (&tree, &clone) {
            (SigmaBoolean::Cand(a), SigmaBoolean::Cand(b)) => {
                assert!(Arc::ptr_eq(
                    a.inner.as_ref().unwrap(),
                    b.inner.as_ref().unwrap()
                ));
                assert_eq!(a[0], a[1]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn shared_graph_equality_and_debug_do_not_expand_occurrences() {
        let tree = doubling(100, 2);
        assert_eq!(tree, doubling(100, 2));
        assert_ne!(tree, doubling(100, 3));
        assert_eq!(tree.size(), usize::MAX);
        let rendered = format!("{tree:?}");
        assert!(rendered.len() < 20_000);
        assert!(rendered.contains('…'));
    }

    #[test]
    fn shared_children_dht_size_counts_four_points() {
        let point = GroupElement::from_bytes([2; 33]);
        let tree = SigmaBoolean::Cand(
            vec![SigmaBoolean::ProveDHTuple {
                g: point,
                h: point,
                u: point,
                v: point,
            }]
            .into(),
        );
        assert_eq!(tree.size(), 5);
    }

    #[test]
    fn unique_and_shared_graph_destruction_fit_bounded_stack() {
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| {
                let mut tree = SigmaBoolean::TrivialProp(true);
                for _ in 0..50_000 {
                    tree = SigmaBoolean::Cand(vec![tree].into());
                }
                let clone = tree.clone();
                drop(tree);
                drop(clone);
                drop(doubling(50_000, 2));
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn concurrent_final_owners_keep_destruction_iterative() {
        for _ in 0..8 {
            let mut tree = SigmaBoolean::TrivialProp(true);
            for _ in 0..10_000 {
                tree = SigmaBoolean::Cand(vec![tree].into());
            }
            let owners = [tree.clone(), tree];
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let threads: Vec<_> = owners
                .into_iter()
                .map(|owner| {
                    let barrier = barrier.clone();
                    std::thread::Builder::new()
                        .stack_size(256 * 1024)
                        .spawn(move || {
                            barrier.wait();
                            drop(owner);
                        })
                        .unwrap()
                })
                .collect();
            for thread in threads {
                thread.join().unwrap();
            }
        }
    }
}

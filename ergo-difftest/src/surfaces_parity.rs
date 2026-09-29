//! Comparison-only Scala parity views. Never feed these views to a codec.
use ergo_ser::{
    ad_proofs::ADProofs,
    autolykos::AutolykosSolution,
    block_transactions::BlockTransactions,
    ergo_box::{ErgoBox, ErgoBoxCandidate},
    ergo_tree::ErgoTree,
    extension::Extension,
    header::Header,
    input::{ContextExtension, Input, SpendingProof, UnsignedInput},
    opcode::{Expr, IrNode, Payload},
    popow_header::PoPowHeader,
    popow_proof::NipopowProof,
    register::{AdditionalRegisters, RegisterValue},
    sigma_type::SigmaType,
    sigma_value::{CollValue, SigmaValue},
    token::Token,
    transaction::{Transaction, UnsignedTransaction},
};

pub(super) trait ParityNormalize {
    fn parity_normalized(&self, after_write: bool) -> impl PartialEq;

    /// Bytes of every retained (opaque) box this value holds, in wire order.
    fn retained_boxes(&self) -> Vec<&[u8]> {
        Vec::new()
    }

    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        Vec::new()
    }

    // Only ErgoTree re-serializes its AST. Containing boxes/transactions/blocks
    // re-emit retained tree bytes verbatim, so every other type keeps false.
    fn has_pending_upcast_strip(&self) -> bool {
        false
    }
}

macro_rules! unchanged {
    ($($ty:ty),* $(,)?) => {$ (
        impl ParityNormalize for $ty {
            fn parity_normalized(&self, _after_write: bool) -> impl PartialEq { self.clone() }
        }
    )*};
}
unchanged!(
    u8,
    u32,
    SigmaType,
    Header,
    ADProofs,
    Token,
    AutolykosSolution,
    Extension,
    PoPowHeader,
    NipopowProof
);

impl<A: ParityNormalize, B: ParityNormalize> ParityNormalize for (A, B) {
    fn retained_boxes(&self) -> Vec<&[u8]> {
        let mut boxes = self.0.retained_boxes();
        boxes.extend(self.1.retained_boxes());
        boxes
    }
    fn parity_normalized(&self, after_write: bool) -> impl PartialEq {
        (
            self.0.parity_normalized(after_write),
            self.1.parity_normalized(after_write),
        )
    }
    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        let mut headers = self.0.header_values();
        headers.extend(self.1.header_values());
        headers
    }
}
impl<T: ParityNormalize> ParityNormalize for Vec<T> {
    fn parity_normalized(&self, after_write: bool) -> impl PartialEq {
        self.iter()
            .map(|v| v.parity_normalized(after_write))
            .collect::<Vec<_>>()
    }
    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        self.iter()
            .flat_map(ParityNormalize::header_values)
            .collect()
    }
    fn retained_boxes(&self) -> Vec<&[u8]> {
        self.iter()
            .flat_map(ParityNormalize::retained_boxes)
            .collect()
    }
}

fn normalize_value(value: &mut SigmaValue) {
    match value {
        SigmaValue::Header(_, id) => *id = [0; 32],
        SigmaValue::Coll(CollValue::Values(items))
        | SigmaValue::Tuple(items)
        | SigmaValue::ConcreteCollection { items, .. } => {
            items.iter_mut().for_each(normalize_value);
        }
        SigmaValue::Opt(Some(inner)) => normalize_value(inner),
        _ => {}
    }
}
impl ParityNormalize for SigmaValue {
    fn retained_boxes(&self) -> Vec<&[u8]> {
        match self {
            SigmaValue::OpaqueBoxBytes(bytes) => vec![bytes.as_slice()],
            SigmaValue::Coll(CollValue::Values(items))
            | SigmaValue::Tuple(items)
            | SigmaValue::ConcreteCollection { items, .. } => items.retained_boxes(),
            SigmaValue::Opt(Some(inner)) => inner.retained_boxes(),
            _ => Vec::new(),
        }
    }
    fn parity_normalized(&self, _after_write: bool) -> impl PartialEq {
        let mut value = self.clone();
        normalize_value(&mut value);
        value
    }
    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        match self {
            SigmaValue::Header(header, id) => vec![(header, *id)],
            SigmaValue::Coll(CollValue::Values(items))
            | SigmaValue::Tuple(items)
            | SigmaValue::ConcreteCollection { items, .. } => items.header_values(),
            SigmaValue::Opt(Some(inner)) => inner.header_values(),
            _ => Vec::new(),
        }
    }
}

fn normalize_expr(expr: &mut Expr, version: u8, after_write: bool) {
    // Test the DIRECT input before descending: Scala strips one level per pass.
    // Collapsing chains to their fixed point would hide lost cast targets or
    // a writer that incorrectly removes multiple levels in a single pass.
    if after_write && version < 3 {
        if let Expr::Op(IrNode {
            opcode: 0x7e,
            payload: Payload::NumericCast { input, .. },
        }) = expr
        {
            if matches!(input.as_ref(), Expr::Const { .. }) {
                *expr = *input.clone();
            }
        }
    }
    let node = match expr {
        Expr::Const { val, .. } => {
            normalize_value(val);
            return;
        }
        Expr::Unparsed(opaque) => {
            opaque.validation_error = None;
            return;
        }
        Expr::Op(node) => node,
    };
    let children: Vec<&mut Expr> = match &mut node.payload {
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => vec![rhs],
        Payload::BlockValue { items, result } => {
            let mut children: Vec<&mut Expr> = items.iter_mut().collect();
            children.push(result);
            children
        }
        Payload::FuncValue { body, .. } => vec![body],
        Payload::MethodCall { obj, args, .. } => {
            let mut children = vec![obj.as_mut()];
            children.extend(args.iter_mut());
            children
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter_mut().collect(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => vec![input],
        Payload::DeserializeRegister { default, .. } => {
            default.as_deref_mut().into_iter().collect()
        }
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut children = vec![input.as_mut(), index.as_mut()];
            children.extend(default.as_deref_mut());
            children
        }
        Payload::FuncApply { func, args } => {
            let mut children = vec![func.as_mut()];
            children.extend(args.iter_mut());
            children
        }
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => vec![],
    };
    for child in children {
        normalize_expr(child, version, after_write);
    }
    // ByIndexSerializer.parse reinserts an Int Upcast for a byte/short index
    // before v3. Model that context after the writer's one-level stripping.
    if after_write && version < 3 {
        if let Payload::ByIndex { index, .. } = &mut node.payload {
            if matches!(
                index.as_ref(),
                Expr::Const {
                    tpe: SigmaType::SByte | SigmaType::SShort,
                    ..
                }
            ) {
                **index = Expr::Op(IrNode {
                    opcode: 0x7e,
                    payload: Payload::NumericCast {
                        input: index.clone(),
                        tpe: SigmaType::SInt,
                    },
                });
            }
        }
    }
}
fn has_pending_strip(expr: &Expr) -> bool {
    let Expr::Op(node) = expr else {
        return false; // Never inspect retained Expr::Unparsed bytes.
    };
    // Exactly the direct-input predicate in ergo-ser opcode/write.rs:183-190.
    if let IrNode {
        opcode: 0x7e,
        payload: Payload::NumericCast { input, .. },
    } = node
    {
        if matches!(input.as_ref(), Expr::Const { .. }) {
            return true;
        }
    }
    let children: Vec<&Expr> = match &node.payload {
        Payload::One(a) => vec![a],
        Payload::Two(a, b) => vec![a, b],
        Payload::Three(a, b, c) => vec![a, b, c],
        Payload::Four(a, b, c, d) => vec![a, b, c, d],
        Payload::ValDef { rhs, .. } | Payload::FunDef { rhs, .. } => vec![rhs],
        Payload::BlockValue { items, result } => {
            let mut children: Vec<&Expr> = items.iter().collect();
            children.push(result);
            children
        }
        Payload::FuncValue { body, .. } => vec![body],
        Payload::MethodCall { obj, args, .. } => {
            let mut children = vec![obj.as_ref()];
            children.extend(args.iter());
            children
        }
        Payload::ConcreteCollection { items, .. }
        | Payload::Tuple { items }
        | Payload::SigmaCollection { items } => items.iter().collect(),
        Payload::SelectField { input, .. }
        | Payload::ExtractRegisterAs { input, .. }
        | Payload::NumericCast { input, .. } => vec![input],
        Payload::DeserializeRegister { default, .. } => default.as_deref().into_iter().collect(),
        Payload::ByIndex {
            input,
            index,
            default,
        } => {
            let mut children = vec![input.as_ref(), index.as_ref()];
            children.extend(default.as_deref());
            children
        }
        Payload::FuncApply { func, args } => {
            let mut children = vec![func.as_ref()];
            children.extend(args.iter());
            children
        }
        Payload::Zero
        | Payload::ValUse { .. }
        | Payload::ConstPlaceholder { .. }
        | Payload::TaggedVar { .. }
        | Payload::BoolCollection { .. }
        | Payload::GetVar { .. }
        | Payload::DeserializeContext { .. }
        | Payload::NoneValue { .. } => vec![],
    };
    children.into_iter().any(has_pending_strip)
}
impl ParityNormalize for ErgoTree {
    fn has_pending_upcast_strip(&self) -> bool {
        self.version < 3 && has_pending_strip(&self.body)
    }

    fn parity_normalized(&self, after_write: bool) -> impl PartialEq {
        normalized_tree(self, after_write)
    }
    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        let mut headers = self.constants.header_values();
        for (_, expr) in ergo_ser::opcode::preorder(&self.body) {
            if let Expr::Const { val, .. } = expr {
                headers.extend(val.header_values());
            }
        }
        headers
    }
    fn retained_boxes(&self) -> Vec<&[u8]> {
        let mut boxes = self.constants.retained_boxes();
        for (_, expr) in ergo_ser::opcode::preorder(&self.body) {
            if let Expr::Const { val, .. } = expr {
                boxes.extend(val.retained_boxes());
            }
        }
        boxes
    }
}

// Explicit views preserve every other field, including private wire caches.
// No rebuilding via serializers: doing so would hide codec bugs.
macro_rules! view {
    ($ty:ty, $v:ident, $body:expr, $headers:expr) => {
        view!($ty, $v, $body, $headers, Vec::new());
    };
    ($ty:ty, $v:ident, $body:expr, $headers:expr, $boxes:expr) => {
        impl ParityNormalize for $ty {
            fn parity_normalized(&self, _after_write: bool) -> impl PartialEq {
                let $v = self;
                $body
            }
            fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
                let $v = self;
                $headers
            }
            fn retained_boxes(&self) -> Vec<&[u8]> {
                let $v = self;
                $boxes
            }
        }
    };
}
view!(
    RegisterValue,
    v,
    (v.tpe.clone(), v.value.parity_normalized(false)),
    v.value.header_values(),
    v.value.retained_boxes()
);
view!(
    AdditionalRegisters,
    v,
    v.registers.parity_normalized(false),
    v.registers.header_values(),
    v.registers.retained_boxes()
);
view!(
    ContextExtension,
    v,
    {
        // IndexMap equality is key/value equality, independent of insertion order.
        let mut entries = v
            .values
            .iter()
            .map(|(key, value)| (*key, value.parity_normalized(false)))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(key, _)| *key);
        entries
    },
    v.values
        .values()
        .flat_map(ParityNormalize::header_values)
        .collect(),
    v.values
        .values()
        .flat_map(ParityNormalize::retained_boxes)
        .collect()
);
view!(
    SpendingProof,
    v,
    (
        v.proof.clone(),
        v.extension().parity_normalized(false),
        v.extension_bytes().to_vec()
    ),
    v.extension().header_values(),
    v.extension().retained_boxes()
);
view!(
    Input,
    v,
    (v.box_id, v.spending_proof.parity_normalized(false)),
    v.spending_proof.header_values(),
    v.spending_proof.retained_boxes()
);
view!(
    UnsignedInput,
    v,
    (v.box_id, v.extension.parity_normalized(false)),
    v.extension.header_values(),
    v.extension.retained_boxes()
);
view!(
    ErgoBoxCandidate,
    v,
    (
        v.value,
        v.ergo_tree().parity_normalized(false),
        v.ergo_tree_bytes().to_vec(),
        v.creation_height,
        v.tokens.clone(),
        v.additional_registers.parity_normalized(false),
        v.register_bytes().to_vec()
    ),
    {
        let mut headers = v.ergo_tree().header_values();
        headers.extend(v.additional_registers.header_values());
        headers
    },
    {
        let mut boxes = v.ergo_tree().retained_boxes();
        boxes.extend(v.additional_registers.retained_boxes());
        boxes
    }
);
view!(
    ErgoBox,
    v,
    (
        v.candidate.parity_normalized(false),
        v.transaction_id,
        v.index
    ),
    v.candidate.header_values(),
    v.candidate.retained_boxes()
);
view!(
    Transaction,
    v,
    (
        v.inputs.parity_normalized(false),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized(false)
    ),
    {
        let mut headers = v.inputs.header_values();
        headers.extend(v.output_candidates.header_values());
        headers
    },
    {
        let mut boxes = v.inputs.retained_boxes();
        boxes.extend(v.output_candidates.retained_boxes());
        boxes
    }
);
view!(
    UnsignedTransaction,
    v,
    (
        v.inputs.parity_normalized(false),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized(false)
    ),
    {
        let mut headers = v.inputs.header_values();
        headers.extend(v.output_candidates.header_values());
        headers
    },
    {
        let mut boxes = v.inputs.retained_boxes();
        boxes.extend(v.output_candidates.retained_boxes());
        boxes
    }
);
view!(
    BlockTransactions,
    v,
    (v.header_id, v.transactions.parity_normalized(false)),
    v.transactions.header_values(),
    v.transactions.retained_boxes()
);

pub(super) fn normalized_tree(tree: &ErgoTree, after_write: bool) -> ErgoTree {
    let mut tree = tree.clone();
    for (_, value) in &mut tree.constants {
        normalize_value(value);
    }
    normalize_expr(&mut tree.body, tree.version, after_write);
    tree
}

/// Verify IDs from independent header-parser boundaries, not re-serialized
/// bytes or the SHeader decoder's own hash calculation. Equal header fields can
/// legitimately occur with different wire hashes: Scala hashes each header's
/// own input slice, so a non-canonical encoding gives the same fields a new
/// ID. Values and spans both arrive in wire order, so within each group of
/// equal headers the value IDs must follow the observed wire hashes in order
/// (a span may back several values). A swapped or invented ID still fails;
/// spans without a value (a header read inside retained box bytes) are
/// skipped.
pub(super) fn header_ids_match_wire(
    value: &impl ParityNormalize,
    reader: &ergo_primitives::reader::VlqReader,
) -> bool {
    let values = value.header_values();
    if values.is_empty() {
        return true;
    }
    let observations: Vec<_> = reader
        .header_spans()
        .iter()
        .filter_map(|&(start, end)| {
            let bytes = reader.data_slice(start, end);
            let mut r = ergo_primitives::reader::VlqReader::new(bytes);
            let header = ergo_ser::header::read_header(&mut r).ok()?;
            if !r.is_empty() {
                return None;
            }
            Some((
                header,
                *ergo_primitives::digest::blake2b256(bytes).as_bytes(),
            ))
        })
        .collect();
    // One span may back several values (a value cloned into a collection
    // and an option), so the cursor stays on the matched span.
    let mut group_cursor: Vec<(&Header, usize)> = Vec::new();
    values.into_iter().all(|(header, id)| {
        let start = group_cursor
            .iter()
            .rev()
            .find(|(h, _)| *h == header)
            .map_or(0, |&(_, at)| at);
        let found = (start..observations.len())
            .find(|&k| observations[k].0 == *header && observations[k].1 == id);
        match found {
            Some(k) => {
                group_cursor.push((header, k));
                true
            }
            None => false,
        }
    })
}

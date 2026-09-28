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
    fn parity_normalized(&self) -> impl PartialEq;

    // Only ErgoTree re-serializes its AST. Containing boxes/transactions/blocks
    // re-emit retained tree bytes verbatim, so every other type keeps false.
    fn has_pending_upcast_strip(&self) -> bool {
        false
    }
}

macro_rules! unchanged {
    ($($ty:ty),* $(,)?) => {$ (
        impl ParityNormalize for $ty {
            fn parity_normalized(&self) -> impl PartialEq { self.clone() }
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
    fn parity_normalized(&self) -> impl PartialEq {
        (self.0.parity_normalized(), self.1.parity_normalized())
    }
}
impl<T: ParityNormalize> ParityNormalize for Vec<T> {
    fn parity_normalized(&self) -> impl PartialEq {
        self.iter()
            .map(ParityNormalize::parity_normalized)
            .collect::<Vec<_>>()
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
    fn parity_normalized(&self) -> impl PartialEq {
        let mut value = self.clone();
        normalize_value(&mut value);
        value
    }
}

fn normalize_expr(expr: &mut Expr, version: u8) {
    let node = match expr {
        Expr::Const { val, .. } => {
            normalize_value(val);
            return;
        }
        Expr::Unparsed(_) => return,
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
        normalize_expr(child, version);
    }
    // ValueSerializer.scala:154-166 and 359-370 strip only Upcast(Const)
    // per serialize pass. Descend first to compare the fixed point of repeated
    // round trips: each pass removes one level of a chain ending in a Const.
    if version < 3 {
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

    fn parity_normalized(&self) -> impl PartialEq {
        normalized_tree(self)
    }
}

// Explicit views preserve every other field, including private wire caches.
// No rebuilding via serializers: doing so would hide codec bugs.
macro_rules! view {
    ($ty:ty, $v:ident, $body:expr) => {
        impl ParityNormalize for $ty {
            fn parity_normalized(&self) -> impl PartialEq {
                let $v = self;
                $body
            }
        }
    };
}
view!(
    RegisterValue,
    v,
    (v.tpe.clone(), v.value.parity_normalized())
);
view!(AdditionalRegisters, v, v.registers.parity_normalized());
view!(ContextExtension, v, {
    // IndexMap equality is key/value equality, independent of insertion order.
    let mut entries = v
        .values
        .iter()
        .map(|(key, value)| (*key, value.parity_normalized()))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| *key);
    entries
});
view!(
    SpendingProof,
    v,
    (
        v.proof.clone(),
        v.extension().parity_normalized(),
        v.extension_bytes().to_vec()
    )
);
view!(Input, v, (v.box_id, v.spending_proof.parity_normalized()));
view!(
    UnsignedInput,
    v,
    (v.box_id, v.extension.parity_normalized())
);
view!(
    ErgoBoxCandidate,
    v,
    (
        v.value,
        v.ergo_tree().parity_normalized(),
        v.ergo_tree_bytes().to_vec(),
        v.creation_height,
        v.tokens.clone(),
        v.additional_registers.parity_normalized(),
        v.register_bytes().to_vec()
    )
);
view!(
    ErgoBox,
    v,
    (v.candidate.parity_normalized(), v.transaction_id, v.index)
);
view!(
    Transaction,
    v,
    (
        v.inputs.parity_normalized(),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized()
    )
);
view!(
    UnsignedTransaction,
    v,
    (
        v.inputs.parity_normalized(),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized()
    )
);
view!(
    BlockTransactions,
    v,
    (v.header_id, v.transactions.parity_normalized())
);

pub(super) fn normalized_tree(tree: &ErgoTree) -> ErgoTree {
    let mut tree = tree.clone();
    for (_, value) in &mut tree.constants {
        normalize_value(value);
    }
    normalize_expr(&mut tree.body, tree.version);
    tree
}

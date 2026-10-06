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

    /// Standalone trees and box candidates start a 4096-byte reader window.
    /// Compact type descriptors can expand beyond it, including in Scala.
    fn wire_position_limit(&self) -> Option<usize> {
        None
    }

    fn is_position_limit_wrap(&self, _bytes: &[u8]) -> bool {
        false
    }

    /// Compact type codes can expand past the independent 6.0.7 read bound.
    fn has_type_depth_expansion(&self) -> bool {
        false
    }

    /// A Boolean leaf becomes a constant whose data read adds one level.
    fn has_depth_expanding_boolean(&self) -> bool {
        false
    }

    /// Bytes of every retained (opaque) box this value holds, in wire order.
    fn retained_boxes(&self) -> Vec<&[u8]> {
        Vec::new()
    }

    fn header_values(&self) -> Vec<(&Header, [u8; 32])> {
        Vec::new()
    }

    // Box readers cache a canonical tree serialization, so containing
    // boxes/transactions/blocks must also follow its one-level cast stripping.
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
    Header,
    ADProofs,
    Token,
    AutolykosSolution,
    Extension,
    PoPowHeader,
    NipopowProof
);

// Diagnostics only: use the actual type writer and reader, so the exception
// requires an existing parsed type whose canonical bytes exceed the JVM limit.
// https://github.com/ergoplatform/sigmastate-interpreter/blob/v6.0.7/core/shared/src/main/scala/sigma/serialization/TypeSerializer.scala#L134-L137
impl ParityNormalize for SigmaType {
    fn parity_normalized(&self, _after_write: bool) -> impl PartialEq {
        self.clone()
    }
    fn has_type_depth_expansion(&self) -> bool {
        let mut w = ergo_primitives::writer::VlqWriter::new();
        if ergo_ser::sigma_type::write_type(&mut w, self).is_err() {
            return false;
        }
        let bytes = w.result();
        let mut r = ergo_primitives::reader::VlqReader::new(&bytes);
        r.set_ergo_tree_version(Some(3));
        matches!(
            ergo_ser::sigma_type::read_type(&mut r),
            Err(ergo_primitives::reader::ReadError::DepthLimitExceeded { max: 8 })
        )
    }
}

fn expr_has_type_depth_expansion(expr: &Expr) -> bool {
    for (_, node) in ergo_ser::opcode::preorder(expr) {
        let found = match node {
            Expr::Const { tpe, val } => {
                tpe.has_type_depth_expansion() || val.has_type_depth_expansion()
            }
            Expr::Op(IrNode { payload, .. }) => match payload {
                Payload::TaggedVar { tpe, .. } => tpe
                    .as_ref()
                    .is_some_and(ParityNormalize::has_type_depth_expansion),
                Payload::ExtractRegisterAs { tpe, .. }
                | Payload::GetVar { tpe, .. }
                | Payload::DeserializeContext { tpe, .. }
                | Payload::DeserializeRegister { tpe, .. }
                | Payload::NoneValue { tpe }
                | Payload::NumericCast { tpe, .. } => tpe.has_type_depth_expansion(),
                Payload::ConcreteCollection { elem_type, .. } => {
                    elem_type.has_type_depth_expansion()
                }
                Payload::MethodCall { type_args, .. } => type_args.has_type_depth_expansion(),
                Payload::FuncValue { args, .. } => args.iter().any(|(_, t)| {
                    t.as_ref()
                        .is_some_and(ParityNormalize::has_type_depth_expansion)
                }),
                Payload::FunDef { tpe_args, .. } => tpe_args.has_type_depth_expansion(),
                _ => false,
            },
            Expr::Unparsed(_) => false,
        };
        if found {
            return true;
        }
    }
    false
}

impl<A: ParityNormalize, B: ParityNormalize> ParityNormalize for (A, B) {
    fn has_type_depth_expansion(&self) -> bool {
        self.0.has_type_depth_expansion() || self.1.has_type_depth_expansion()
    }
    fn has_pending_upcast_strip(&self) -> bool {
        self.0.has_pending_upcast_strip() || self.1.has_pending_upcast_strip()
    }
    fn has_depth_expanding_boolean(&self) -> bool {
        self.0.has_depth_expanding_boolean() || self.1.has_depth_expanding_boolean()
    }
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
    fn has_type_depth_expansion(&self) -> bool {
        self.iter().any(ParityNormalize::has_type_depth_expansion)
    }
    fn has_pending_upcast_strip(&self) -> bool {
        self.iter().any(ParityNormalize::has_pending_upcast_strip)
    }
    fn has_depth_expanding_boolean(&self) -> bool {
        self.iter()
            .any(ParityNormalize::has_depth_expanding_boolean)
    }
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

fn normalize_value(value: &mut SigmaValue, version: u8, after_write: bool) {
    match value {
        SigmaValue::Header(_, id) => *id = [0; 32],
        SigmaValue::CanonicalBoxBytes {
            bytes,
            canonical_bytes,
            legacy_bytes,
        } => {
            // The JVM structured writer canonicalizes the nested box while
            // its received identity remains cached until the next read.
            // Compare that one documented write effect, preserving all others.
            let canonical = if version < 3 {
                legacy_bytes.as_ref().unwrap_or(canonical_bytes)
            } else {
                canonical_bytes
            };
            let received = if after_write {
                canonical.as_ref().unwrap_or(bytes)
            } else {
                bytes
            };
            *value = SigmaValue::OpaqueBoxBytes(received.clone());
        }
        SigmaValue::Coll(CollValue::Values(items))
        | SigmaValue::Tuple(items)
        | SigmaValue::ConcreteCollection { items, .. } => {
            items
                .iter_mut()
                .for_each(|x| normalize_value(x, version, after_write));
        }
        SigmaValue::Opt(Some(inner)) => normalize_value(inner, version, after_write),
        SigmaValue::Unevaluated(expr) => normalize_expr(expr, version, after_write),
        _ => {}
    }
}
impl ParityNormalize for SigmaValue {
    fn has_type_depth_expansion(&self) -> bool {
        match self {
            SigmaValue::OpaqueBoxBytes(bytes) | SigmaValue::CanonicalBoxBytes { bytes, .. } => {
                let mut r =
                    ergo_primitives::reader::VlqReader::new(bytes).with_activated_script_version(3);
                ergo_ser::ergo_box::read_ergo_box(&mut r)
                    .is_ok_and(|b| b.has_type_depth_expansion())
            }
            SigmaValue::Coll(CollValue::Values(items)) | SigmaValue::Tuple(items) => {
                items.has_type_depth_expansion()
            }
            SigmaValue::ConcreteCollection { elem_type, items } => {
                elem_type.has_type_depth_expansion() || items.has_type_depth_expansion()
            }
            SigmaValue::Opt(Some(inner)) => inner.has_type_depth_expansion(),
            SigmaValue::Unevaluated(expr) => expr_has_type_depth_expansion(expr),
            _ => false,
        }
    }
    fn retained_boxes(&self) -> Vec<&[u8]> {
        match self {
            SigmaValue::OpaqueBoxBytes(bytes) | SigmaValue::CanonicalBoxBytes { bytes, .. } => {
                vec![bytes.as_slice()]
            }
            SigmaValue::Coll(CollValue::Values(items))
            | SigmaValue::Tuple(items)
            | SigmaValue::ConcreteCollection { items, .. } => items.retained_boxes(),
            SigmaValue::Opt(Some(inner)) => inner.retained_boxes(),
            _ => Vec::new(),
        }
    }
    fn parity_normalized(&self, after_write: bool) -> impl PartialEq {
        let mut value = self.clone();
        normalize_value(&mut value, 3, after_write);
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
            normalize_value(val, version, after_write);
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
    // MethodCall.companion chooses PropertyCall for an empty argument list.
    if after_write && matches!(&node.payload, Payload::MethodCall { args, .. } if args.is_empty()) {
        node.opcode = 0xdb;
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
    fn has_type_depth_expansion(&self) -> bool {
        self.constants.has_type_depth_expansion() || expr_has_type_depth_expansion(&self.body)
    }
    fn wire_position_limit(&self) -> Option<usize> {
        Some(4096)
    }

    fn is_position_limit_wrap(&self, bytes: &[u8]) -> bool {
        matches!(&self.body, Expr::Unparsed(raw)
            if matches!(raw.validation_error, Some((1014, _))) && raw.bytes == bytes)
    }

    fn has_depth_expanding_boolean(&self) -> bool {
        let mut stack = vec![(&self.body, 0)];
        while let Some((expr, depth)) = stack.pop() {
            if depth == 109
                && matches!(
                    expr,
                    Expr::Const {
                        tpe: SigmaType::SBoolean,
                        ..
                    }
                )
            {
                return true;
            }
            stack.extend(
                ergo_ser::opcode::children(expr)
                    .into_iter()
                    .map(|c| (c, depth + 1)),
            );
        }
        false
    }

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
        view!(
            $ty,
            $v,
            _after_write,
            $body,
            $headers,
            $boxes,
            false,
            None,
            false
        );
    };
    ($ty:ty, $v:ident, $after_write:ident, $body:expr, $headers:expr, $boxes:expr, $pending:expr) => {
        view!(
            $ty,
            $v,
            $after_write,
            $body,
            $headers,
            $boxes,
            $pending,
            None,
            false
        );
    };
    ($ty:ty, $v:ident, $after_write:ident, $body:expr, $headers:expr, $boxes:expr, $pending:expr, $limit:expr) => {
        view!(
            $ty,
            $v,
            $after_write,
            $body,
            $headers,
            $boxes,
            $pending,
            $limit,
            false
        );
    };
    ($ty:ty, $v:ident, $after_write:ident, $body:expr, $headers:expr, $boxes:expr, $pending:expr, $limit:expr, $bools:expr) => {
        view!(
            $ty,
            $v,
            $after_write,
            $body,
            $headers,
            $boxes,
            $pending,
            $limit,
            $bools,
            false
        );
    };
    ($ty:ty, $v:ident, $after_write:ident, $body:expr, $headers:expr, $boxes:expr, $pending:expr, $limit:expr, $bools:expr, $types:expr) => {
        impl ParityNormalize for $ty {
            fn has_type_depth_expansion(&self) -> bool {
                let $v = self;
                let _ = $v;
                $types
            }
            fn wire_position_limit(&self) -> Option<usize> {
                $limit
            }
            fn parity_normalized(&self, $after_write: bool) -> impl PartialEq {
                let $v = self;
                $body
            }
            fn has_pending_upcast_strip(&self) -> bool {
                let $v = self;
                let _ = $v;
                $pending
            }
            fn has_depth_expanding_boolean(&self) -> bool {
                let $v = self;
                let _ = $v;
                $bools
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
    after_write,
    (v.tpe.clone(), v.value.parity_normalized(after_write)),
    v.value.header_values(),
    v.value.retained_boxes(),
    false,
    None,
    false,
    v.tpe.has_type_depth_expansion() || v.value.has_type_depth_expansion()
);
view!(
    AdditionalRegisters,
    v,
    after_write,
    v.registers.parity_normalized(after_write),
    v.registers.header_values(),
    v.registers.retained_boxes(),
    false,
    None,
    false,
    v.registers.has_type_depth_expansion()
);
view!(
    ContextExtension,
    v,
    after_write,
    {
        // IndexMap equality is key/value equality, independent of insertion order.
        let mut entries = v
            .values
            .iter()
            .map(|(key, value)| (*key, value.parity_normalized(after_write)))
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
        .collect(),
    false,
    None,
    false,
    v.values
        .values()
        .any(ParityNormalize::has_type_depth_expansion)
);
view!(
    SpendingProof,
    v,
    after_write,
    (
        v.proof.clone(),
        v.extension().parity_normalized(after_write),
        v.extension_bytes().to_vec()
    ),
    v.extension().header_values(),
    v.extension().retained_boxes(),
    false,
    None,
    false,
    v.extension().has_type_depth_expansion()
);
view!(
    Input,
    v,
    after_write,
    (v.box_id, v.spending_proof.parity_normalized(after_write)),
    v.spending_proof.header_values(),
    v.spending_proof.retained_boxes(),
    false,
    None,
    false,
    v.spending_proof.has_type_depth_expansion()
);
view!(
    UnsignedInput,
    v,
    after_write,
    (v.box_id, v.extension.parity_normalized(after_write)),
    v.extension.header_values(),
    v.extension.retained_boxes(),
    false,
    None,
    false,
    v.extension.has_type_depth_expansion()
);
view!(
    ErgoBoxCandidate,
    v,
    after_write,
    (
        v.value,
        v.ergo_tree().parity_normalized(after_write),
        // Compare the first writer's cache with the second reader's retained
        // bytes. Its new canonical cache may strip the NEXT cast level.
        if after_write {
            v.serialized_ergo_tree_bytes()
        } else {
            v.ergo_tree_bytes()
        }
        .to_vec(),
        v.creation_height,
        v.tokens.clone(),
        v.additional_registers().parity_normalized(after_write),
        v.register_bytes().to_vec()
    ),
    {
        let mut headers = v.ergo_tree().header_values();
        headers.extend(v.additional_registers().header_values());
        headers
    },
    {
        let mut boxes = v.ergo_tree().retained_boxes();
        boxes.extend(v.additional_registers().retained_boxes());
        boxes
    },
    v.ergo_tree().has_pending_upcast_strip(),
    Some(4096),
    v.ergo_tree().has_depth_expanding_boolean(),
    v.ergo_tree().has_type_depth_expansion() || v.additional_registers().has_type_depth_expansion()
);
view!(
    ErgoBox,
    v,
    after_write,
    (
        v.candidate.parity_normalized(after_write),
        v.transaction_id,
        v.index
    ),
    v.candidate.header_values(),
    v.candidate.retained_boxes(),
    v.candidate.has_pending_upcast_strip(),
    None,
    v.candidate.has_depth_expanding_boolean(),
    v.candidate.has_type_depth_expansion()
);
view!(
    Transaction,
    v,
    after_write,
    (
        v.inputs.parity_normalized(after_write),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized(after_write)
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
    },
    v.output_candidates.has_pending_upcast_strip(),
    None,
    v.output_candidates.has_depth_expanding_boolean(),
    v.inputs.has_type_depth_expansion() || v.output_candidates.has_type_depth_expansion()
);
view!(
    UnsignedTransaction,
    v,
    after_write,
    (
        v.inputs.parity_normalized(after_write),
        v.data_inputs.clone(),
        v.output_candidates.parity_normalized(after_write)
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
    },
    v.output_candidates.has_pending_upcast_strip(),
    None,
    v.output_candidates.has_depth_expanding_boolean(),
    v.inputs.has_type_depth_expansion() || v.output_candidates.has_type_depth_expansion()
);
view!(
    BlockTransactions,
    v,
    after_write,
    (v.header_id, v.transactions.parity_normalized(after_write)),
    v.transactions.header_values(),
    v.transactions.retained_boxes(),
    v.transactions.has_pending_upcast_strip(),
    None,
    v.transactions.has_depth_expanding_boolean(),
    v.transactions.has_type_depth_expansion()
);

pub(super) fn normalized_tree(tree: &ErgoTree, after_write: bool) -> ErgoTree {
    let mut tree = tree.clone();
    for (_, value) in &mut tree.constants {
        normalize_value(value, tree.version, after_write);
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

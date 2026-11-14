//! One-level nested-calldata binding and child-call boundary rendering.
//!
//! A `format: calldata` field is not authority to interpret arbitrary bytes.
//! The parent descriptor/deployment/selector/path first has to match one exact
//! firmware enrollment.  Only then does this module derive the sole canonical
//! child interval and callee from the signed parent calldata, select one rooted
//! child descriptor, and preflight the child's complete ABI shape.  No host
//! supplied target, selector, interval, or execution mode enters the binding.

use crate::binding::cross_check_contract;
use crate::bundle::VerifiedDescriptor;
use crate::display::primitives::write_addr_full;
use crate::ir::{Erc7730Ir, FieldEntry, FormatHeader, FormatOp, PathOp};
use crate::proof_set::{VerifiedBundleRef, VerifiedProofSet};
use crate::render::calldata_policy::{
    callee_location, lookup_field, lookup_parent, NestedCalldataEnrollment,
    NestedCalldataExecution, NestedCalldataFieldKey, NestedCalldataParentKey, NestedCalleeLocation,
    ACTIVE_NESTED_CALLDATA_ENROLLMENTS,
};
use crate::render::params::{parse as parse_params, ParamSet};
use crate::render::RenderErr;
use pqsigner_tx_core::eip1559::Eip1559Tx;
use sha2::{Digest, Sha256};

use super::formatters::{
    resolve_dynamic_geometry, validate_contract_calldata_framing, validate_contract_word_guards,
    ContractContainerCtx,
};
use super::{head_bounded_body, Pages};

const NESTED_BINDING_DOMAIN: &[u8] = b"pqsigner/erc7730-nested-call-binding/v1\0";
const CALL_ZERO_VALUE_CODE: u8 = 1;

/// Authenticated catalogue identity of one descriptor leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeafIdentity {
    pub index: u32,
    pub hash: [u8; 32],
}

/// Exact half-open child-data interval relative to byte zero of the signed
/// outer calldata (including its four-byte selector).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalChildInterval {
    pub start: u32,
    pub end: u32,
}

/// Complete independently-derived authority for one scoped child render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NestedCallBinding {
    pub parent_leaf: LeafIdentity,
    pub parent_selector: [u8; 4],
    pub field_ordinal: u8,
    pub field_path: [u8; 5],
    pub interval: CanonicalChildInterval,
    pub child_target: [u8; 20],
    pub child_selector: [u8; 4],
    pub execution: NestedCalldataExecution,
    pub child_value: [u8; 32],
    pub child_leaf: LeafIdentity,
}

/// Domain-separated fixed-width commitment consumed by transcript receipt V2.
#[must_use]
#[inline(never)]
pub fn nested_binding_commitment(binding: &NestedCallBinding) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NESTED_BINDING_DOMAIN);
    hasher.update(binding.parent_leaf.index.to_be_bytes());
    hasher.update(binding.parent_leaf.hash);
    hasher.update(binding.parent_selector);
    hasher.update([binding.field_ordinal]);
    hasher.update(binding.field_path);
    hasher.update(binding.interval.start.to_be_bytes());
    hasher.update(binding.interval.end.to_be_bytes());
    hasher.update(binding.child_target);
    hasher.update(binding.child_selector);
    hasher.update([execution_code(binding.execution)]);
    hasher.update(binding.child_value);
    hasher.update(binding.child_leaf.index.to_be_bytes());
    hasher.update(binding.child_leaf.hash);
    hasher.finalize().into()
}

const fn execution_code(execution: NestedCalldataExecution) -> u8 {
    match execution {
        NestedCalldataExecution::CallZeroValue => CALL_ZERO_VALUE_CODE,
    }
}

/// Internal zero-copy result retained only for the scoped child painter.
pub(super) struct BoundNestedCall<'data, 'ir> {
    pub binding: NestedCallBinding,
    pub child_data: &'data [u8],
    pub child_descriptor: VerifiedDescriptor<'ir>,
    pub child_format: FormatHeader<'ir>,
    pub child_container: ContractContainerCtx,
}

/// Derive the complete nested binding under the build-selected firmware
/// policy. `Ok(None)` means the selected ordinary parent format has no enrolled
/// nested field. A supplied distinct-child bundle in that case is rejected.
pub fn derive_nested_call(
    tx: &Eip1559Tx,
    inner_data: &[u8],
    proof_set: &VerifiedProofSet<'_>,
    device_signer: &[u8; 20],
) -> Result<Option<NestedCallBinding>, RenderErr> {
    derive_bound_with_enrollments(
        tx,
        inner_data,
        proof_set,
        device_signer,
        ACTIVE_NESTED_CALLDATA_ENROLLMENTS,
    )
    .map(|bound| bound.map(|bound| bound.binding))
}

/// Policy-injectable seam used by crate-local tests. Production entry points
/// always call [`derive_nested_call`] or pass the build-selected table.
pub(super) fn derive_bound_with_enrollments<'data, 'ir>(
    tx: &Eip1559Tx,
    inner_data: &'data [u8],
    proof_set: &VerifiedProofSet<'ir>,
    device_signer: &[u8; 20],
    enrollments: &[NestedCalldataEnrollment],
) -> Result<Option<BoundNestedCall<'data, 'ir>>, RenderErr> {
    let parent = proof_set.outer;
    let parent_target = tx.to.ok_or(RenderErr::Reject("7730 nested parent no to"))?;
    cross_check_contract(&parent.descriptor.ir, tx.chain_id, &parent_target)
        .map_err(|_| RenderErr::Reject("7730 nested parent binding"))?;

    let parent_selector = selector(inner_data, "7730 nested parent short selector")?;
    let parent_format = unique_format(&parent.descriptor.ir, &parent_selector)?;
    let parent_container = ContractContainerCtx::outer(
        tx.chain_id,
        parent_target,
        tx.value,
        tx.nonce,
        Some(*device_signer),
    );
    let parent_full_body = inner_data
        .get(4..)
        .ok_or(RenderErr::Reject("7730 nested parent body"))?;
    let parent_head = head_bounded_body(parent_full_body, parent_format.static_head_words)?;
    let parent_mode = validate_contract_calldata_framing(
        &parent.descriptor.ir,
        &parent_format,
        parent_full_body,
        &parent_container,
    )?;
    validate_contract_word_guards(
        &parent.descriptor.ir,
        &parent_format,
        parent_head,
        parent_full_body,
        parent_mode,
        &parent_container,
    )?;

    let parent_key = NestedCalldataParentKey {
        descriptor_hash: &parent.descriptor.ir.descriptor_hash,
        chain_id: tx.chain_id,
        parent_contract: &parent_target,
        parent_selector: &parent_selector,
    };
    let enrollment = lookup_parent(enrollments, parent_key)
        .map_err(|_| RenderErr::Reject("7730 nested ambiguous policy"))?;
    let Some(enrollment) = enrollment else {
        if proof_set.child.is_some() {
            return Err(RenderErr::Reject("7730 unexpected child proof"));
        }
        if format_contains_calldata(&parent_format)? {
            return Err(RenderErr::Reject("7730 unenrolled calldata field"));
        }
        return Ok(None);
    };
    if enrollment.execution != NestedCalldataExecution::CallZeroValue {
        return Err(RenderErr::Reject("7730 nested execution policy"));
    }

    let (field, params, field_path) = enrolled_field(
        &parent.descriptor.ir,
        &parent_format,
        enrollment,
        enrollments,
        parent_key,
    )?;
    let geometry = resolve_dynamic_geometry(
        &parent.descriptor.ir,
        field.path_off,
        parent_full_body,
        parent_format.static_head_words,
        parent_mode,
    )?;
    let interval_start = geometry
        .data_start
        .checked_add(4)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RenderErr::Reject("7730 nested interval overflow"))?;
    let interval_end = geometry
        .data_end
        .checked_add(4)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(RenderErr::Reject("7730 nested interval overflow"))?;

    let callee_path = params
        .nested_callee
        .ok_or(RenderErr::Reject("7730 nested missing callee"))?;
    let child_target = derive_callee(
        callee_path,
        parent_head,
        parent_format.static_head_words,
        parent_target,
    )?;
    let child_data = geometry.data;
    let child_selector = selector(child_data, "7730 nested child short selector")?;
    require_non_reserved_child_selector(&child_selector)?;

    let child_bundle = select_child_bundle(proof_set, tx.chain_id, &child_target)?;
    cross_check_contract(&child_bundle.descriptor.ir, tx.chain_id, &child_target)
        .map_err(|_| RenderErr::Reject("7730 nested child binding"))?;
    let child_format = unique_format(&child_bundle.descriptor.ir, &child_selector)?;
    validate_child_format_paths(&child_bundle.descriptor.ir, &child_format)?;

    let child_container = ContractContainerCtx::child(tx.chain_id, child_target);
    let child_full_body = child_data
        .get(4..)
        .ok_or(RenderErr::Reject("7730 nested child body"))?;
    let child_head = head_bounded_body(child_full_body, child_format.static_head_words)?;
    let child_mode = validate_contract_calldata_framing(
        &child_bundle.descriptor.ir,
        &child_format,
        child_full_body,
        &child_container,
    )?;
    validate_contract_word_guards(
        &child_bundle.descriptor.ir,
        &child_format,
        child_head,
        child_full_body,
        child_mode,
        &child_container,
    )?;

    let binding = NestedCallBinding {
        parent_leaf: leaf_identity(parent),
        parent_selector,
        field_ordinal: enrollment.field_ordinal,
        field_path: *field_path,
        interval: CanonicalChildInterval {
            start: interval_start,
            end: interval_end,
        },
        child_target,
        child_selector,
        execution: enrollment.execution,
        child_value: [0u8; 32],
        child_leaf: leaf_identity(child_bundle),
    };

    // Keep the selected field live through all derivation checks. This also
    // makes an accidental future selection by label rather than ordinal/path a
    // compile-visible change at this boundary.
    let _ = field;
    Ok(Some(BoundNestedCall {
        binding,
        child_data,
        child_descriptor: child_bundle.descriptor,
        child_format,
        child_container,
    }))
}

fn leaf_identity(bundle: VerifiedBundleRef<'_>) -> LeafIdentity {
    LeafIdentity {
        index: bundle.leaf_index,
        hash: bundle.leaf_hash(),
    }
}

fn selector(data: &[u8], reason: &'static str) -> Result<[u8; 4], RenderErr> {
    data.get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RenderErr::Reject(reason))
}

fn unique_format<'ir>(
    ir: &Erc7730Ir<'ir>,
    selector: &[u8; 4],
) -> Result<FormatHeader<'ir>, RenderErr> {
    let mut found = None;
    for entry in ir.format_iter() {
        let format = entry.map_err(|_| RenderErr::Reject("7730 nested bad formats"))?;
        if &format.selector == selector && found.replace(format).is_some() {
            return Err(RenderErr::Reject("7730 nested ambiguous format"));
        }
    }
    found.ok_or(RenderErr::NoFormat)
}

fn format_contains_calldata(format: &FormatHeader<'_>) -> Result<bool, RenderErr> {
    for entry in format.fields() {
        let field = entry.map_err(|_| RenderErr::Reject("7730 nested bad field"))?;
        if field.format_op == FormatOp::Calldata as u8 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(clippy::type_complexity)]
fn enrolled_field<'ir>(
    ir: &Erc7730Ir<'ir>,
    format: &FormatHeader<'ir>,
    enrollment: &NestedCalldataEnrollment,
    enrollments: &[NestedCalldataEnrollment],
    parent_key: NestedCalldataParentKey<'_>,
) -> Result<(FieldEntry<'ir>, ParamSet<'ir>, &'ir [u8; 5]), RenderErr> {
    let mut found = None;
    let mut calldata_count = 0u8;
    for (ordinal, entry) in format.fields().enumerate() {
        let field = entry.map_err(|_| RenderErr::Reject("7730 nested bad field"))?;
        if field.format_op != FormatOp::Calldata as u8 {
            continue;
        }
        calldata_count = calldata_count
            .checked_add(1)
            .ok_or(RenderErr::Reject("7730 nested field overflow"))?;
        let ordinal =
            u8::try_from(ordinal).map_err(|_| RenderErr::Reject("7730 nested ordinal overflow"))?;
        let params = parse_params(ir, field.param_off)?;
        let path = ir
            .path_bytes(field.path_off)
            .map_err(|_| RenderErr::Reject("7730 nested bad field path"))?;
        let path: &[u8; 5] = path
            .try_into()
            .map_err(|_| RenderErr::Reject("7730 nested field path"))?;
        let callee = params
            .nested_callee
            .ok_or(RenderErr::Reject("7730 nested missing callee"))?;
        let exact = lookup_field(
            enrollments,
            NestedCalldataFieldKey {
                parent: parent_key,
                field_ordinal: ordinal,
                field_path: path,
                callee_path: callee,
            },
        )
        .map_err(|_| RenderErr::Reject("7730 nested ambiguous policy"))?;
        if exact == Some(enrollment) && found.replace((field, params, path)).is_some() {
            return Err(RenderErr::Reject("7730 nested duplicate field"));
        }
    }
    if calldata_count != 1 {
        return Err(RenderErr::Reject("7730 nested calldata count"));
    }
    found.ok_or(RenderErr::Reject("7730 nested field policy mismatch"))
}

fn derive_callee(
    path: &[u8; 4],
    parent_head: &[u8],
    static_head_words: u16,
    parent_target: [u8; 20],
) -> Result<[u8; 20], RenderErr> {
    match callee_location(path).ok_or(RenderErr::Reject("7730 nested callee path"))? {
        NestedCalleeLocation::ContainerTo => Ok(parent_target),
        NestedCalleeLocation::StaticWord(slot) => {
            if slot >= static_head_words {
                return Err(RenderErr::Reject("7730 nested callee outside head"));
            }
            let start = usize::from(slot)
                .checked_mul(32)
                .ok_or(RenderErr::Reject("7730 nested callee overflow"))?;
            let word = parent_head
                .get(start..start + 32)
                .ok_or(RenderErr::Reject("7730 nested callee word"))?;
            if word[..12].iter().any(|byte| *byte != 0) {
                return Err(RenderErr::Reject("7730 nested dirty callee"));
            }
            let mut target = [0u8; 20];
            target.copy_from_slice(&word[12..]);
            Ok(target)
        }
    }
}

fn select_child_bundle<'ir>(
    proof_set: &VerifiedProofSet<'ir>,
    chain_id: u64,
    target: &[u8; 20],
) -> Result<VerifiedBundleRef<'ir>, RenderErr> {
    let outer_matches = descriptor_matches(&proof_set.outer.descriptor, chain_id, target);
    match proof_set.child {
        None if outer_matches => Ok(proof_set.outer),
        None => Err(RenderErr::Reject("7730 nested child proof missing")),
        Some(child) => {
            let child_matches = descriptor_matches(&child.descriptor, chain_id, target);
            if !child_matches || outer_matches {
                return Err(RenderErr::Reject("7730 nested child proof selection"));
            }
            Ok(child)
        }
    }
}

fn descriptor_matches(
    descriptor: &VerifiedDescriptor<'_>,
    chain_id: u64,
    target: &[u8; 20],
) -> bool {
    cross_check_contract(&descriptor.ir, chain_id, target).is_ok()
}

fn validate_child_format_paths(
    ir: &Erc7730Ir<'_>,
    format: &FormatHeader<'_>,
) -> Result<(), RenderErr> {
    for entry in format.fields() {
        let field = entry.map_err(|_| RenderErr::Reject("7730 nested bad child field"))?;
        if field.format_op == FormatOp::Calldata as u8 {
            return Err(RenderErr::Reject("7730 nested recursion"));
        }
        if field.path_off != 0 {
            let path = ir
                .path_bytes(field.path_off)
                .map_err(|_| RenderErr::Reject("7730 nested bad child path"))?;
            reject_forbidden_child_container(path)?;
        }
        let params = parse_params(ir, field.param_off)?;
        if params.nested_struct.is_some() {
            return Err(RenderErr::Reject("7730 nested child struct"));
        }
        // The existing secure transcript-state classifier independently
        // derives interpolation authority from the outer format. Keep that
        // classifier exact in the first nested slice: a child may render its
        // authenticated static intent, but cannot introduce a second
        // interpolation publication state implicitly.
        if params.interpolated_intent.is_some() {
            return Err(RenderErr::Reject("7730 nested child interpolation"));
        }
        for path in [
            params.token_path,
            params.nft_collection_path,
            params.nested_callee.map(|path| path.as_slice()),
        ]
        .into_iter()
        .flatten()
        {
            reject_forbidden_child_container(path)?;
        }
    }
    Ok(())
}

/// Parse a path structurally; never reject because the raw byte representation
/// happens to contain a value equal to a container opcode or field index.
fn reject_forbidden_child_container(path: &[u8]) -> Result<(), RenderErr> {
    let root = path
        .first()
        .copied()
        .and_then(|byte| PathOp::try_from(byte).ok())
        .ok_or(RenderErr::Reject("7730 nested child path root"))?;
    if root == PathOp::RootContainer {
        if path.len() != 4 || path[1] != PathOp::FieldIdx as u8 {
            return Err(RenderErr::Reject("7730 nested child container path"));
        }
        let field = u16::from_be_bytes([path[2], path[3]]);
        if matches!(
            field,
            crate::abi::container_field::FROM | crate::abi::container_field::NONCE
        ) {
            return Err(RenderErr::Reject("7730 nested child unbound context"));
        }
        return Ok(());
    }
    if !matches!(root, PathOp::RootStructured | PathOp::RootMetadata) {
        return Err(RenderErr::Reject("7730 nested child path root"));
    }
    let mut cursor = 1usize;
    while cursor < path.len() {
        let op = path
            .get(cursor)
            .copied()
            .and_then(|byte| PathOp::try_from(byte).ok())
            .ok_or(RenderErr::Reject("7730 nested child path op"))?;
        let width = match op {
            PathOp::FieldIdx | PathOp::ArrayIdx => 3,
            PathOp::ArraySlice => 6,
            PathOp::ArrayLast | PathOp::ArrayAll | PathOp::FollowOffset => 1,
            PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata => {
                return Err(RenderErr::Reject("7730 nested child path root"));
            }
        };
        cursor = cursor
            .checked_add(width)
            .ok_or(RenderErr::Reject("7730 nested child path overflow"))?;
        if cursor > path.len() {
            return Err(RenderErr::Reject("7730 nested child path truncated"));
        }
    }
    Ok(())
}

#[must_use]
pub(super) fn is_reserved_child_selector(selector: &[u8; 4]) -> bool {
    matches!(
        *selector,
        pqsigner_proto::APPROVE_HASH_SELECTOR
            | pqsigner_proto::EXEC_TRANSACTION_SELECTOR
            | pqsigner_proto::SET_PRE_SIGNATURE_SELECTOR
            | pqsigner_proto::MULTI_SEND_SELECTOR
    )
}

pub(super) fn require_non_reserved_child_selector(selector: &[u8; 4]) -> Result<(), RenderErr> {
    if is_reserved_child_selector(selector) {
        Err(RenderErr::Reject("7730 nested native child selector"))
    } else {
        Ok(())
    }
}

/// Append the one unmistakable child-call boundary. The complete target uses
/// the common three-row EIP-55 address sink; the label truncates only with an
/// explicit `~` marker.
pub(super) fn render_boundary(
    pages: &mut Pages,
    label: &[u8],
    target: &[u8; 20],
) -> Result<(), RenderErr> {
    let page = pages.push_blank().map_err(|_| RenderErr::PageBudget)?;
    let rows = pages.page_mut(page);
    rows[0][..5].copy_from_slice(b"CALL ");
    const LABEL_ROOM: usize = 11;
    if label.len() <= LABEL_ROOM {
        rows[0][5..5 + label.len()].copy_from_slice(label);
    } else {
        rows[0][5..15].copy_from_slice(&label[..10]);
        rows[0][15] = b'~';
    }
    let [_, row1, row2, row3] = rows;
    write_addr_full(row1, row2, row3, target);
    Ok(())
}

/// Legacy descriptor-only rendering has no independently rooted child proof or
/// expected binding. Keep its historical hard refusal even when a test build
/// parses an enrolled parent; only the proof-set entry point may call the
/// scoped child renderer.
pub(super) fn render(
    _field: &FieldEntry<'_>,
    _pages: &mut Pages,
    _params: &ParamSet<'_>,
) -> Result<(), RenderErr> {
    Err(RenderErr::Reject("7730 nested proof set required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::VerifiedDescriptor;
    use crate::ir::{ContextKind, FormatOp, Visibility, CTX_CONTRACT, HEADER_LEN, SCHEMA_VER};
    use crate::proof_set::{VerifiedBundleRef, VerifiedProofSet};
    use crate::render::calldata_policy::{
        TEST_NESTED_CALLDATA_CALLEE_PATH, TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
        TEST_NESTED_CALLDATA_ENROLLMENTS, TEST_NESTED_CALLDATA_FIELD_PATH,
        TEST_NESTED_CALLDATA_PARENT_CONTRACT, TEST_NESTED_CALLDATA_PARENT_SELECTOR,
    };
    use crate::render::params::{
        DYNAMIC_KIND_BYTES, DYNAMIC_KIND_STRING, PARAM_DYNAMIC_KIND,
        PARAM_DYNAMIC_TAIL_TOPOLOGY, PARAM_NESTED_CALLEE, PARAM_TERMINAL_KIND, PARAM_VISIBILITY,
        PARAM_WORD_GUARD, WORD_GUARD_NE,
    };
    use crate::render::policy::TerminalKind;
    use pqsigner_tx::names::NameResolver;
    use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};

    const TEST_CHAIN_ID: u64 = 31_337;
    const CHILD_TARGET: [u8; 20] = [0x56; 20];
    const CHILD_SELECTOR: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
    const CHILD_DESCRIPTOR_HASH: [u8; 32] = [0x81; 32];

    fn append_pool_entry(pool: &mut std::vec::Vec<u8>, payload: &[u8]) -> u16 {
        let offset = u16::try_from(pool.len()).unwrap();
        pool.push(u8::try_from(payload.len()).unwrap());
        pool.extend_from_slice(payload);
        offset
    }

    fn encoded_field(
        op: FormatOp,
        label: &[u8],
        path_off: u16,
        param_off: u16,
    ) -> std::vec::Vec<u8> {
        let mut field = std::vec![op as u8, u8::try_from(label.len()).unwrap()];
        field.extend_from_slice(label);
        field.extend_from_slice(&path_off.to_be_bytes());
        field.extend_from_slice(&param_off.to_be_bytes());
        field
    }

    fn encoded_format(
        selector: [u8; 4],
        intent: &[u8],
        static_head_words: u16,
        fields: &[std::vec::Vec<u8>],
    ) -> std::vec::Vec<u8> {
        let mut format = std::vec::Vec::new();
        format.extend_from_slice(&selector);
        format.push(u8::try_from(fields.len()).unwrap());
        format.push(u8::try_from(intent.len()).unwrap());
        format.extend_from_slice(&static_head_words.to_be_bytes());
        format.push(0); // nested EIP-712 descents
        format.push(0); // EIP-712 string preimages
        format.extend_from_slice(intent);
        for field in fields {
            format.extend_from_slice(field);
        }
        format
    }

    fn contract_ir_bytes(
        chain_id: u64,
        contract: [u8; 20],
        descriptor_hash: [u8; 32],
        pool: &[u8],
        formats: &[std::vec::Vec<u8>],
        name: &[u8],
    ) -> std::vec::Vec<u8> {
        let mut formats_buf = std::vec![u8::try_from(formats.len()).unwrap()];
        for format in formats {
            formats_buf.extend_from_slice(format);
        }
        let mut bytes = std::vec![0u8; HEADER_LEN];
        bytes[0] = SCHEMA_VER;
        bytes[1] = CTX_CONTRACT;
        bytes[2..10].copy_from_slice(&chain_id.to_be_bytes());
        bytes[10..30].copy_from_slice(&contract);
        bytes[30..62].copy_from_slice(&descriptor_hash);
        bytes[94..94 + name.len()].copy_from_slice(name);
        bytes[110..110 + name.len()].copy_from_slice(name);
        bytes[126..128].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        bytes[128..130].copy_from_slice(&((HEADER_LEN + pool.len()) as u16).to_be_bytes());
        bytes[130..132].copy_from_slice(&(pool.len() as u16).to_be_bytes());
        bytes[132..134].copy_from_slice(&(formats_buf.len() as u16).to_be_bytes());
        bytes.extend_from_slice(pool);
        bytes.extend_from_slice(&formats_buf);
        bytes
    }

    fn outer_ir_bytes() -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let target_path = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let target_params = append_pool_entry(
            &mut pool,
            &[PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8],
        );
        let child_path = append_pool_entry(&mut pool, &TEST_NESTED_CALLDATA_FIELD_PATH);
        let child_params = append_pool_entry(
            &mut pool,
            &[
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_BYTES,
                PARAM_NESTED_CALLEE,
                4,
                TEST_NESTED_CALLDATA_CALLEE_PATH[0],
                TEST_NESTED_CALLDATA_CALLEE_PATH[1],
                TEST_NESTED_CALLDATA_CALLEE_PATH[2],
                TEST_NESTED_CALLDATA_CALLEE_PATH[3],
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::DynamicBytes as u8,
            ],
        );
        let fields = [
            encoded_field(FormatOp::AddressName, b"Target", target_path, target_params),
            encoded_field(FormatOp::Calldata, b"Child call", child_path, child_params),
        ];
        let format = encoded_format(TEST_NESTED_CALLDATA_PARENT_SELECTOR, b"Forward", 2, &fields);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Parent",
        )
    }

    fn multi_tail_outer_ir_bytes() -> std::vec::Vec<u8> {
        use crate::render::calldata_topology::{TAIL_KIND_BLOB, TOPOLOGY_VERSION};

        let mut pool = std::vec![0];
        let target_path = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let topology = [
            TOPOLOGY_VERSION,
            2,
            0,
            1,
            TAIL_KIND_BLOB,
            0,
            2,
            TAIL_KIND_BLOB,
        ];
        let mut target_param_bytes = std::vec![
            PARAM_DYNAMIC_TAIL_TOPOLOGY,
            u8::try_from(topology.len()).unwrap(),
        ];
        target_param_bytes.extend_from_slice(&topology);
        target_param_bytes.extend_from_slice(&[
            PARAM_TERMINAL_KIND,
            1,
            TerminalKind::Address as u8,
        ]);
        let target_params = append_pool_entry(&mut pool, &target_param_bytes);
        let child_path = append_pool_entry(&mut pool, &TEST_NESTED_CALLDATA_FIELD_PATH);
        let child_params = append_pool_entry(
            &mut pool,
            &[
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_BYTES,
                PARAM_NESTED_CALLEE,
                4,
                TEST_NESTED_CALLDATA_CALLEE_PATH[0],
                TEST_NESTED_CALLDATA_CALLEE_PATH[1],
                TEST_NESTED_CALLDATA_CALLEE_PATH[2],
                TEST_NESTED_CALLDATA_CALLEE_PATH[3],
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::DynamicBytes as u8,
            ],
        );
        let memo_path = append_pool_entry(
            &mut pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                2,
                PathOp::FollowOffset as u8,
            ],
        );
        let memo_params = append_pool_entry(
            &mut pool,
            &[
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_STRING,
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::DynamicString as u8,
            ],
        );
        let fields = [
            encoded_field(FormatOp::AddressName, b"Target", target_path, target_params),
            encoded_field(FormatOp::Calldata, b"Child call", child_path, child_params),
            encoded_field(FormatOp::Raw, b"Memo", memo_path, memo_params),
        ];
        let format = encoded_format(TEST_NESTED_CALLDATA_PARENT_SELECTOR, b"Forward", 3, &fields);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            TEST_NESTED_CALLDATA_PARENT_CONTRACT,
            TEST_NESTED_CALLDATA_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Parent",
        )
    }

    fn child_ir_bytes(selector: [u8; 4]) -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let recipient_path = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let recipient_params = append_pool_entry(
            &mut pool,
            &[PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8],
        );
        let field = encoded_field(
            FormatOp::AddressName,
            b"Recipient",
            recipient_path,
            recipient_params,
        );
        let format = encoded_format(selector, b"Transfer", 1, &[field]);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            CHILD_TARGET,
            CHILD_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Child",
        )
    }

    fn dynamic_child_ir_bytes(hidden: bool) -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let path = append_pool_entry(
            &mut pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::FollowOffset as u8,
            ],
        );
        let mut params = std::vec![PARAM_DYNAMIC_KIND, 1, DYNAMIC_KIND_STRING];
        if hidden {
            params.extend_from_slice(&[PARAM_VISIBILITY, 1, Visibility::Never as u8]);
        }
        params.extend_from_slice(&[PARAM_TERMINAL_KIND, 1, TerminalKind::DynamicString as u8]);
        let params = append_pool_entry(&mut pool, &params);
        let field = encoded_field(FormatOp::Raw, b"Memo", path, params);
        let format = encoded_format(CHILD_SELECTOR, b"Message", 1, &[field]);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            CHILD_TARGET,
            CHILD_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Child",
        )
    }

    fn guarded_child_ir_bytes() -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let path = append_pool_entry(
            &mut pool,
            &[PathOp::RootStructured as u8, PathOp::FieldIdx as u8, 0, 0],
        );
        let mut expected = [0u8; 32];
        expected[12..].copy_from_slice(&[0x78; 20]);
        let mut params = std::vec![PARAM_WORD_GUARD, 33, WORD_GUARD_NE];
        params.extend_from_slice(&expected);
        params.extend_from_slice(&[PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8]);
        let params = append_pool_entry(&mut pool, &params);
        let field = encoded_field(FormatOp::AddressName, b"Recipient", path, params);
        let format = encoded_format(CHILD_SELECTOR, b"Transfer", 1, &[field]);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            CHILD_TARGET,
            CHILD_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Child",
        )
    }

    fn recursive_child_ir_bytes() -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let path = append_pool_entry(
            &mut pool,
            &[
                PathOp::RootStructured as u8,
                PathOp::FieldIdx as u8,
                0,
                0,
                PathOp::FollowOffset as u8,
            ],
        );
        let params = append_pool_entry(
            &mut pool,
            &[
                PARAM_DYNAMIC_KIND,
                1,
                DYNAMIC_KIND_BYTES,
                PARAM_NESTED_CALLEE,
                4,
                PathOp::RootContainer as u8,
                PathOp::FieldIdx as u8,
                0,
                crate::abi::container_field::TO as u8,
                PARAM_TERMINAL_KIND,
                1,
                TerminalKind::DynamicBytes as u8,
            ],
        );
        let field = encoded_field(FormatOp::Calldata, b"Again", path, params);
        let format = encoded_format(CHILD_SELECTOR, b"Recurse", 1, &[field]);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            CHILD_TARGET,
            CHILD_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Child",
        )
    }

    fn unchecked_contract_ir(bytes: &[u8]) -> Erc7730Ir<'_> {
        let pool_off = usize::from(u16::from_be_bytes([bytes[126], bytes[127]]));
        let formats_off = usize::from(u16::from_be_bytes([bytes[128], bytes[129]]));
        let pool_len = usize::from(u16::from_be_bytes([bytes[130], bytes[131]]));
        let formats_len = usize::from(u16::from_be_bytes([bytes[132], bytes[133]]));
        Erc7730Ir {
            schema_ver: bytes[0],
            context_kind: ContextKind::Contract,
            chain_id: u64::from_be_bytes(bytes[2..10].try_into().unwrap()),
            contract: bytes[10..30].try_into().unwrap(),
            descriptor_hash: bytes[30..62].try_into().unwrap(),
            domain_separator: bytes[62..94].try_into().unwrap(),
            owner: bytes[94..110].split(|byte| *byte == 0).next().unwrap(),
            contract_name: bytes[110..126].split(|byte| *byte == 0).next().unwrap(),
            pool: &bytes[pool_off..pool_off + pool_len],
            formats: &bytes[formats_off..formats_off + formats_len],
            raw: bytes,
        }
    }

    fn many_raw_child_ir_bytes(raw_fields: usize, address_field: bool) -> std::vec::Vec<u8> {
        let mut pool = std::vec![0];
        let mut fields = std::vec::Vec::new();
        for slot in 0..raw_fields {
            let path = append_pool_entry(
                &mut pool,
                &[
                    PathOp::RootStructured as u8,
                    PathOp::FieldIdx as u8,
                    (slot >> 8) as u8,
                    slot as u8,
                ],
            );
            let params = append_pool_entry(
                &mut pool,
                &[PARAM_TERMINAL_KIND, 1, TerminalKind::FixedBytes as u8],
            );
            fields.push(encoded_field(FormatOp::Raw, b"Word", path, params));
        }
        if address_field {
            let slot = raw_fields;
            let path = append_pool_entry(
                &mut pool,
                &[
                    PathOp::RootStructured as u8,
                    PathOp::FieldIdx as u8,
                    (slot >> 8) as u8,
                    slot as u8,
                ],
            );
            let params = append_pool_entry(
                &mut pool,
                &[PARAM_TERMINAL_KIND, 1, TerminalKind::Address as u8],
            );
            fields.push(encoded_field(
                FormatOp::AddressName,
                b"Recipient",
                path,
                params,
            ));
        }
        let head_words = u16::try_from(raw_fields + usize::from(address_field)).unwrap();
        let format = encoded_format(CHILD_SELECTOR, b"Inspect", head_words, &fields);
        contract_ir_bytes(
            TEST_CHAIN_ID,
            CHILD_TARGET,
            CHILD_DESCRIPTOR_HASH,
            &pool,
            &[format],
            b"Child",
        )
    }

    fn child_calldata(selector: [u8; 4]) -> std::vec::Vec<u8> {
        let mut data = selector.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&[0x78; 20]);
        data
    }

    fn dynamic_child_calldata() -> std::vec::Vec<u8> {
        let mut data = CHILD_SELECTOR.to_vec();
        data.extend_from_slice(&[0u8; 31]);
        data.push(32);
        data.extend_from_slice(&[0u8; 31]);
        data.push(3);
        data.extend_from_slice(b"abc");
        data.resize(data.len() + 29, 0);
        data
    }

    fn many_raw_child_calldata(raw_fields: usize, address_field: bool) -> std::vec::Vec<u8> {
        let mut data = CHILD_SELECTOR.to_vec();
        for value in 1..=raw_fields {
            data.extend_from_slice(&[u8::try_from(value).unwrap(); 32]);
        }
        if address_field {
            data.extend_from_slice(&[0u8; 12]);
            data.extend_from_slice(&[0x78; 20]);
        }
        data
    }

    fn outer_calldata(child: &[u8]) -> std::vec::Vec<u8> {
        let mut data = TEST_NESTED_CALLDATA_PARENT_SELECTOR.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&CHILD_TARGET);
        data.extend_from_slice(&[0u8; 31]);
        data.push(64); // sole canonical dynamic tail begins after the two-word head
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(child.len() as u64).to_be_bytes());
        data.extend_from_slice(child);
        let padding = (32 - child.len() % 32) % 32;
        data.resize(data.len() + padding, 0);
        data
    }

    fn multi_tail_outer_calldata(child: &[u8], memo: &[u8]) -> std::vec::Vec<u8> {
        let head_end = 3 * 32;
        let child_padded = child.len().div_ceil(32) * 32;
        let child_start = head_end;
        let memo_start = child_start + 32 + child_padded;
        let memo_padded = memo.len().div_ceil(32) * 32;
        let mut data = TEST_NESTED_CALLDATA_PARENT_SELECTOR.to_vec();
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&CHILD_TARGET);
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(child_start as u64).to_be_bytes());
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(memo_start as u64).to_be_bytes());
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(child.len() as u64).to_be_bytes());
        data.extend_from_slice(child);
        data.resize(4 + memo_start, 0);
        data.extend_from_slice(&[0u8; 24]);
        data.extend_from_slice(&(memo.len() as u64).to_be_bytes());
        data.extend_from_slice(memo);
        data.resize(4 + memo_start + 32 + memo_padded, 0);
        data
    }

    fn tx() -> Eip1559Tx {
        Eip1559Tx {
            chain_id: TEST_CHAIN_ID,
            nonce: 9,
            gas_limit: 21_000,
            to: Some(TEST_NESTED_CALLDATA_PARENT_CONTRACT),
            value: U256::zero(),
            ..Eip1559Tx::default()
        }
    }

    fn trim(row: &[u8; 16]) -> &[u8] {
        let end = row
            .iter()
            .rposition(|byte| *byte != b' ')
            .map_or(0, |position| position + 1);
        &row[..end]
    }

    fn count_row(pages: &Pages, needle: &[u8]) -> usize {
        pages
            .as_slice()
            .iter()
            .flatten()
            .filter(|row| trim(row) == needle)
            .count()
    }

    #[test]
    fn reserved_selector_gate_is_exact_and_one_byte_misses_pass() {
        for reserved in [
            pqsigner_proto::APPROVE_HASH_SELECTOR,
            pqsigner_proto::EXEC_TRANSACTION_SELECTOR,
            pqsigner_proto::SET_PRE_SIGNATURE_SELECTOR,
            pqsigner_proto::MULTI_SEND_SELECTOR,
        ] {
            assert!(is_reserved_child_selector(&reserved));
            for byte in 0..4 {
                let mut miss = reserved;
                miss[byte] ^= 1;
                assert!(!is_reserved_child_selector(&miss));
            }
        }
    }

    #[test]
    fn nested_commitment_binds_every_record_byte() {
        let binding = NestedCallBinding {
            parent_leaf: LeafIdentity {
                index: 3,
                hash: [0x11; 32],
            },
            parent_selector: [1, 2, 3, 4],
            field_ordinal: 1,
            field_path: [0x10, 0x20, 0, 1, 0x25],
            interval: CanonicalChildInterval {
                start: 100,
                end: 136,
            },
            child_target: [0x22; 20],
            child_selector: [5, 6, 7, 8],
            execution: NestedCalldataExecution::CallZeroValue,
            child_value: [0; 32],
            child_leaf: LeafIdentity {
                index: 7,
                hash: [0x33; 32],
            },
        };
        let baseline = nested_binding_commitment(&binding);

        let mut mutations = binding;
        mutations.parent_leaf.index ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.parent_leaf.hash[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.parent_selector[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.field_ordinal ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.field_path[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.interval.start ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.interval.end ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.child_target[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.child_selector[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.child_value[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.child_leaf.index ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
        mutations = binding;
        mutations.child_leaf.hash[0] ^= 1;
        assert_ne!(nested_binding_commitment(&mutations), baseline);
    }

    #[test]
    fn child_context_path_scan_rejects_only_parsed_from_and_nonce() {
        let from = crate::abi::container_field::FROM.to_be_bytes();
        let nonce = crate::abi::container_field::NONCE.to_be_bytes();
        for field in [from, nonce] {
            assert!(reject_forbidden_child_container(&[
                PathOp::RootContainer as u8,
                PathOp::FieldIdx as u8,
                field[0],
                field[1],
            ])
            .is_err());
        }
        assert!(reject_forbidden_child_container(&[
            PathOp::RootStructured as u8,
            PathOp::FieldIdx as u8,
            PathOp::RootContainer as u8,
            crate::abi::container_field::FROM as u8,
        ])
        .is_ok());
    }

    #[test]
    fn boundary_marks_truncation_and_shows_complete_target() {
        let mut pages = Pages::with_len(0);
        let target = [0xAB; 20];
        render_boundary(&mut pages, b"A very long child field", &target).unwrap();
        assert_eq!(&pages.buf[0][0], b"CALL A very lon~");
        let rendered_hex = pages.buf[0][1..]
            .iter()
            .flatten()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b'x')
            .count();
        assert_eq!(rendered_hex, 41); // leading `0` plus all 40 hex digits
    }

    #[test]
    fn proof_set_derives_exact_child_and_renders_one_scoped_boundary() {
        let outer_bytes = outer_ir_bytes();
        let child_bytes = child_ir_bytes(CHILD_SELECTOR);
        let outer_ir = Erc7730Ir::parse_with_nested_calldata_enrollments(
            &outer_bytes,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap();
        let child_ir = Erc7730Ir::parse(&child_bytes).unwrap();
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor { ir: outer_ir },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                descriptor: VerifiedDescriptor { ir: child_ir },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let child_data = child_calldata(CHILD_SELECTOR);
        let outer_data = outer_calldata(&child_data);
        let signer = [0xA5; 20];
        let bound = derive_bound_with_enrollments(
            &tx(),
            &outer_data,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap()
        .unwrap();

        assert_eq!(bound.child_data, child_data);
        assert_eq!(bound.binding.parent_leaf.index, 3);
        assert_eq!(
            bound.binding.parent_selector,
            TEST_NESTED_CALLDATA_PARENT_SELECTOR
        );
        assert_eq!(bound.binding.field_ordinal, 1);
        assert_eq!(bound.binding.field_path, TEST_NESTED_CALLDATA_FIELD_PATH);
        assert_eq!(
            bound.binding.interval,
            CanonicalChildInterval {
                start: 100,
                end: 136
            }
        );
        assert_eq!(bound.binding.child_target, CHILD_TARGET);
        assert_eq!(bound.binding.child_selector, CHILD_SELECTOR);
        assert_eq!(bound.binding.child_value, [0; 32]);
        assert_eq!(bound.binding.child_leaf.index, 7);

        let binding = bound.binding;
        let mut pages = Pages::with_len(0);
        let receipt =
            super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                pqsigner_tx::erc20::set::Erc20Scope::empty(),
                &NameResolver::default(),
                &signer,
                Some(&binding),
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                &mut pages,
            )
            .unwrap();
        assert_eq!(
            receipt.state_code(),
            super::super::INTENT_PUBLICATION_STATIC
        );
        assert!(receipt.range_matches_with_nested(&pages, 0, &nested_binding_commitment(&binding)));
        assert!(!receipt.range_matches(&pages, 0));
        assert_eq!(count_row(&pages, b"Forward"), 1);
        assert_eq!(count_row(&pages, b"Transfer"), 1);
        assert_eq!(count_row(&pages, b"Network:"), 1);
        assert_eq!(count_row(&pages, b"R=Confirm"), 1);
        let call_pages = pages
            .as_slice()
            .iter()
            .enumerate()
            .filter(|(_, page)| trim(&page[0]).starts_with(b"CALL "))
            .collect::<std::vec::Vec<_>>();
        assert_eq!(call_pages.len(), 1);
        let transfer_page = pages
            .as_slice()
            .iter()
            .position(|page| trim(&page[0]) == b"Transfer")
            .unwrap();
        assert!(call_pages[0].0 < transfer_page);
    }

    #[test]
    fn nested_child_interval_uses_the_authenticated_multi_tail_partition() {
        let outer_bytes = multi_tail_outer_ir_bytes();
        let child_bytes = child_ir_bytes(CHILD_SELECTOR);
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                        &outer_bytes,
                        TEST_NESTED_CALLDATA_ENROLLMENTS,
                    )
                    .unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&child_bytes).unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let child_data = child_calldata(CHILD_SELECTOR);
        let outer_data = multi_tail_outer_calldata(&child_data, b"memo");
        let signer = [0xA5; 20];
        let bound = derive_bound_with_enrollments(
            &tx(),
            &outer_data,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap()
        .unwrap();
        assert_eq!(bound.child_data, child_data);
        assert_eq!(
            bound.binding.interval,
            CanonicalChildInterval {
                start: 132,
                end: 168,
            }
        );

        let mut dirty_later_padding = outer_data.clone();
        *dirty_later_padding.last_mut().unwrap() = 1;
        assert!(derive_bound_with_enrollments(
            &tx(),
            &dirty_later_padding,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .is_err());

        let mut aliased_later_tail = outer_data;
        aliased_later_tail[4 + 64..4 + 96].fill(0);
        aliased_later_tail[4 + 95] = 96;
        assert!(derive_bound_with_enrollments(
            &tx(),
            &aliased_later_tail,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .is_err());
    }

    #[test]
    fn expected_binding_mismatch_rejects_before_painting() {
        let outer_bytes = outer_ir_bytes();
        let child_bytes = child_ir_bytes(CHILD_SELECTOR);
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                        &outer_bytes,
                        TEST_NESTED_CALLDATA_ENROLLMENTS,
                    )
                    .unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&child_bytes).unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let outer_data = outer_calldata(&child_calldata(CHILD_SELECTOR));
        let signer = [0xA5; 20];
        let binding = derive_bound_with_enrollments(
            &tx(),
            &outer_data,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap()
        .unwrap()
        .binding;
        let mut wrong = binding;
        wrong.interval.end -= 1;
        let mut pages = Pages::with_len(0);
        let result = super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
            &tx(),
            &outer_data,
            &proof_set,
            pqsigner_tx::erc20::set::Erc20Scope::empty(),
            &NameResolver::default(),
            &signer,
            Some(&wrong),
            TEST_NESTED_CALLDATA_ENROLLMENTS,
            &mut pages,
        );
        assert!(matches!(
            result,
            Err(RenderErr::Reject("7730 nested expected binding mismatch"))
        ));
        assert_eq!(pages.len, 0);
    }

    #[test]
    fn reserved_child_selectors_reject_even_with_matching_rooted_formats() {
        let outer_bytes = outer_ir_bytes();
        let signer = [0xA5; 20];
        for selector in [
            pqsigner_proto::APPROVE_HASH_SELECTOR,
            pqsigner_proto::EXEC_TRANSACTION_SELECTOR,
            pqsigner_proto::SET_PRE_SIGNATURE_SELECTOR,
            pqsigner_proto::MULTI_SEND_SELECTOR,
        ] {
            let child_bytes = child_ir_bytes(selector);
            let proof_set = VerifiedProofSet {
                raw_payload: &[],
                outer: VerifiedBundleRef {
                    descriptor: VerifiedDescriptor {
                        ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                            &outer_bytes,
                            TEST_NESTED_CALLDATA_ENROLLMENTS,
                        )
                        .unwrap(),
                    },
                    raw_bundle: &[],
                    leaf_index: 3,
                },
                child: Some(VerifiedBundleRef {
                    descriptor: VerifiedDescriptor {
                        ir: Erc7730Ir::parse(&child_bytes).unwrap(),
                    },
                    raw_bundle: &[],
                    leaf_index: 7,
                }),
            };
            let child_data = child_calldata(selector);
            let outer_data = outer_calldata(&child_data);
            let result = derive_bound_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                &signer,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            );
            assert!(matches!(
                result,
                Err(RenderErr::Reject("7730 nested native child selector"))
            ));
        }
    }

    #[test]
    fn nested_geometry_and_callee_are_derived_from_canonical_parent_bytes() {
        let outer_bytes = outer_ir_bytes();
        let child_bytes = child_ir_bytes(CHILD_SELECTOR);
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                        &outer_bytes,
                        TEST_NESTED_CALLDATA_ENROLLMENTS,
                    )
                    .unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&child_bytes).unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let signer = [0xA5; 20];
        let baseline = outer_calldata(&child_calldata(CHILD_SELECTOR));
        for mutation in 0..4 {
            let mut bad = baseline.clone();
            match mutation {
                0 => bad[4] = 1,            // dirty address high padding
                1 => bad[4 + 63] = 0x60,    // non-canonical dynamic offset
                2 => bad[4 + 64 + 31] = 35, // declared length truncates selector/body
                3 => bad.push(0),           // signed suffix outside the sole canonical tail
                _ => unreachable!(),
            }
            assert!(derive_bound_with_enrollments(
                &tx(),
                &bad,
                &proof_set,
                &signer,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            )
            .is_err());
        }
        let mut dirty_padding = baseline;
        *dirty_padding.last_mut().unwrap() = 1;
        assert!(derive_bound_with_enrollments(
            &tx(),
            &dirty_padding,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .is_err());
    }

    #[test]
    fn canonical_child_preflight_failures_publish_no_boundary_or_pages() {
        let outer_bytes = outer_ir_bytes();
        let outer_ir = Erc7730Ir::parse_with_nested_calldata_enrollments(
            &outer_bytes,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap();
        let signer = [0xA5; 20];

        let assert_no_publication = |child_ir: Erc7730Ir<'_>, child_data: &[u8], case: &str| {
            let proof_set = VerifiedProofSet {
                raw_payload: &[],
                outer: VerifiedBundleRef {
                    descriptor: VerifiedDescriptor { ir: outer_ir },
                    raw_bundle: &[],
                    leaf_index: 3,
                },
                child: Some(VerifiedBundleRef {
                    descriptor: VerifiedDescriptor { ir: child_ir },
                    raw_bundle: &[],
                    leaf_index: 7,
                }),
            };
            let outer_data = outer_calldata(child_data);
            let mut pages = Pages::with_len(0);
            let result =
                super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                    &tx(),
                    &outer_data,
                    &proof_set,
                    pqsigner_tx::erc20::set::Erc20Scope::empty(),
                    &NameResolver::default(),
                    &signer,
                    None,
                    TEST_NESTED_CALLDATA_ENROLLMENTS,
                    &mut pages,
                );
            assert!(result.is_err(), "{case} unexpectedly rendered");
            assert_eq!(pages.len, 0, "{case} published parent or child pages");
            assert_eq!(count_row(&pages, b"Transfer"), 0, "{case}");
            assert!(
                !pages
                    .as_slice()
                    .iter()
                    .any(|page| trim(&page[0]).starts_with(b"CALL ")),
                "{case} published a child boundary"
            );
        };

        let static_bytes = child_ir_bytes(CHILD_SELECTOR);
        let static_ir = Erc7730Ir::parse(&static_bytes).unwrap();
        let mut short_head = child_calldata(CHILD_SELECTOR);
        short_head.pop();
        assert_no_publication(static_ir, &short_head, "short child head");
        let mut static_suffix = child_calldata(CHILD_SELECTOR);
        static_suffix.extend_from_slice(&[0u8; 32]);
        assert_no_publication(static_ir, &static_suffix, "static child suffix");

        let dynamic_bytes = dynamic_child_ir_bytes(false);
        let dynamic_ir = Erc7730Ir::parse(&dynamic_bytes).unwrap();
        let canonical_dynamic = dynamic_child_calldata();
        let mut alias = canonical_dynamic.clone();
        alias[4..36].fill(0);
        assert_no_publication(dynamic_ir, &alias, "dynamic child head alias");
        let mut gap = canonical_dynamic.clone();
        gap.splice(36..36, [0u8; 32]);
        gap[4..36].fill(0);
        gap[35] = 64;
        assert_no_publication(dynamic_ir, &gap, "dynamic child gap");
        let mut dirty_padding = canonical_dynamic.clone();
        *dirty_padding.last_mut().unwrap() = 1;
        assert_no_publication(dynamic_ir, &dirty_padding, "dynamic child dirty padding");
        let mut trailing = canonical_dynamic.clone();
        trailing.extend_from_slice(&[0u8; 32]);
        assert_no_publication(dynamic_ir, &trailing, "dynamic child trailing bytes");

        let hidden_bytes = dynamic_child_ir_bytes(true);
        let hidden_ir = Erc7730Ir::parse(&hidden_bytes).unwrap();
        assert_no_publication(hidden_ir, &dirty_padding, "hidden malformed child field");

        let guarded_bytes = guarded_child_ir_bytes();
        let guarded_ir = Erc7730Ir::parse(&guarded_bytes).unwrap();
        assert_no_publication(
            guarded_ir,
            &child_calldata(CHILD_SELECTOR),
            "failed child word guard",
        );
    }

    #[test]
    fn child_calldata_recursion_refuses_before_boundary_publication() {
        let outer_bytes = outer_ir_bytes();
        let recursive_bytes = recursive_child_ir_bytes();
        assert!(
            Erc7730Ir::parse(&recursive_bytes).is_err(),
            "ordinary authenticated IR parsing must not admit a recursive child"
        );
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                        &outer_bytes,
                        TEST_NESTED_CALLDATA_ENROLLMENTS,
                    )
                    .unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                // Exercise the independent runtime recursion belt even if a
                // faulted parser view were to survive the normal IR rejection.
                descriptor: VerifiedDescriptor {
                    ir: unchecked_contract_ir(&recursive_bytes),
                },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let outer_data = outer_calldata(&child_calldata(CHILD_SELECTOR));
        let signer = [0xA5; 20];
        assert!(matches!(
            derive_bound_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                &signer,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            ),
            Err(RenderErr::Reject("7730 nested recursion"))
        ));
        let mut pages = Pages::with_len(0);
        assert!(
            super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                pqsigner_tx::erc20::set::Erc20Scope::empty(),
                &NameResolver::default(),
                &signer,
                None,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                &mut pages,
            )
            .is_err()
        );
        assert_eq!(pages.len, 0);
    }

    #[test]
    fn every_nested_signed_calldata_byte_changes_transcript_or_refuses() {
        let outer_bytes = outer_ir_bytes();
        let child_bytes = child_ir_bytes(CHILD_SELECTOR);
        let proof_set = VerifiedProofSet {
            raw_payload: &[],
            outer: VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse_with_nested_calldata_enrollments(
                        &outer_bytes,
                        TEST_NESTED_CALLDATA_ENROLLMENTS,
                    )
                    .unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 3,
            },
            child: Some(VerifiedBundleRef {
                descriptor: VerifiedDescriptor {
                    ir: Erc7730Ir::parse(&child_bytes).unwrap(),
                },
                raw_bundle: &[],
                leaf_index: 7,
            }),
        };
        let signer = [0xA5; 20];
        let baseline_data = outer_calldata(&child_calldata(CHILD_SELECTOR));
        let baseline_binding = derive_bound_with_enrollments(
            &tx(),
            &baseline_data,
            &proof_set,
            &signer,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap()
        .unwrap()
        .binding;
        let mut baseline_pages = Pages::with_len(0);
        let baseline_receipt =
            super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                &tx(),
                &baseline_data,
                &proof_set,
                pqsigner_tx::erc20::set::Erc20Scope::empty(),
                &NameResolver::default(),
                &signer,
                Some(&baseline_binding),
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                &mut baseline_pages,
            )
            .unwrap();

        let mut changed = 0usize;
        let mut refused = 0usize;
        for index in 0..baseline_data.len() {
            let mut mutated_data = baseline_data.clone();
            mutated_data[index] ^= 1;
            let Ok(Some(mutated)) = derive_bound_with_enrollments(
                &tx(),
                &mutated_data,
                &proof_set,
                &signer,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            ) else {
                refused += 1;
                continue;
            };
            let mut mutated_pages = Pages::with_len(0);
            match super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                &tx(),
                &mutated_data,
                &proof_set,
                pqsigner_tx::erc20::set::Erc20Scope::empty(),
                &NameResolver::default(),
                &signer,
                Some(&mutated.binding),
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                &mut mutated_pages,
            ) {
                Ok(mutated_receipt) => {
                    assert_ne!(
                        baseline_pages.as_slice(),
                        mutated_pages.as_slice(),
                        "signed calldata byte {index} changed silently"
                    );
                    assert!(
                        !baseline_receipt.exact_match(&mutated_receipt),
                        "signed calldata byte {index} preserved the transcript receipt"
                    );
                    changed += 1;
                }
                Err(_) => refused += 1,
            }
        }
        assert!(
            changed > 0,
            "flip matrix needs a successful changed transcript"
        );
        assert!(refused > 0, "flip matrix needs a fail-closed mutation");
        assert_eq!(changed + refused, baseline_data.len());
    }

    #[test]
    fn nested_transcript_page_31_succeeds_and_page_32_refuses_without_confirmation() {
        let outer_bytes = outer_ir_bytes();
        let outer_ir = Erc7730Ir::parse_with_nested_calldata_enrollments(
            &outer_bytes,
            TEST_NESTED_CALLDATA_ENROLLMENTS,
        )
        .unwrap();
        let signer = [0xA5; 20];
        let raw_fields = 12 - super::super::intent::INTENT_BANNER_PAGES;

        let render = |child_bytes: &[u8], child_data: &[u8], pages: &mut Pages| {
            let proof_set = VerifiedProofSet {
                raw_payload: &[],
                outer: VerifiedBundleRef {
                    descriptor: VerifiedDescriptor { ir: outer_ir },
                    raw_bundle: &[],
                    leaf_index: 3,
                },
                child: Some(VerifiedBundleRef {
                    descriptor: VerifiedDescriptor {
                        ir: Erc7730Ir::parse(child_bytes).unwrap(),
                    },
                    raw_bundle: &[],
                    leaf_index: 7,
                }),
            };
            let outer_data = outer_calldata(child_data);
            let binding = derive_bound_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                &signer,
                TEST_NESTED_CALLDATA_ENROLLMENTS,
            )?
            .ok_or(RenderErr::Reject("missing nested fixture"))?
            .binding;
            super::super::render_erc7730_proof_set_pages_with_signer_into_with_enrollments(
                &tx(),
                &outer_data,
                &proof_set,
                pqsigner_tx::erc20::set::Erc20Scope::empty(),
                &NameResolver::default(),
                &signer,
                Some(&binding),
                TEST_NESTED_CALLDATA_ENROLLMENTS,
                pages,
            )
        };

        let fits_bytes = many_raw_child_ir_bytes(raw_fields, false);
        let fits_data = many_raw_child_calldata(raw_fields, false);
        let mut fits = Pages::with_len(0);
        let receipt = render(&fits_bytes, &fits_data, &mut fits).unwrap();
        assert_eq!(fits.len, crate::display::MAX_PAGES);
        assert_eq!(count_row(&fits, b"R=Confirm"), 1);
        assert!(receipt.range_matches_with_nested(
            &fits,
            0,
            &nested_binding_commitment(
                &derive_bound_with_enrollments(
                    &tx(),
                    &outer_calldata(&fits_data),
                    &VerifiedProofSet {
                        raw_payload: &[],
                        outer: VerifiedBundleRef {
                            descriptor: VerifiedDescriptor { ir: outer_ir },
                            raw_bundle: &[],
                            leaf_index: 3,
                        },
                        child: Some(VerifiedBundleRef {
                            descriptor: VerifiedDescriptor {
                                ir: Erc7730Ir::parse(&fits_bytes).unwrap(),
                            },
                            raw_bundle: &[],
                            leaf_index: 7,
                        }),
                    },
                    &signer,
                    TEST_NESTED_CALLDATA_ENROLLMENTS,
                )
                .unwrap()
                .unwrap()
                .binding
            )
        ));

        let overflow_bytes = many_raw_child_ir_bytes(raw_fields, true);
        let overflow_data = many_raw_child_calldata(raw_fields, true);
        let mut overflow = Pages::with_len(0);
        assert_eq!(
            render(&overflow_bytes, &overflow_data, &mut overflow),
            Err(RenderErr::PageBudget)
        );
        assert_eq!(overflow.len, crate::display::MAX_PAGES);
        assert_eq!(count_row(&overflow, b"R=Confirm"), 0);
    }
}

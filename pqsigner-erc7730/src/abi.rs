//! ABI-decoded value tree consumed by the ERC-7730 path-bytecode walker.
//!
//! The walker is deliberately decoupled from any concrete ABI-decoder
//! implementation. The secure-world caller builds an `AbiNode` tree on
//! the stack (typically from `secure::tx::typed_call::abi::walk_shape`)
//! and hands it to the walker; tests build the same tree by hand. The
//! tree is borrowed throughout — the walker allocates nothing and the
//! returned `AbiValue` carries references back into the caller's
//! buffers.
//!
//! ## Field indexing convention
//!
//! `PathOp::FieldIdx` carries a `u16` field index. The host compiler
//! (`dbgen::erc7730::compile_path` → `resolve_field_index`) populates
//! this index in two distinct ways:
//!
//! * **Format-key positional names** (parameters of the function
//!   signature for contract context, or the typed-data top-level
//!   message fields for EIP-712): the index is the field's positional
//!   slot inside `parsed.top_names` / `parsed.inner_names`.
//! * **Container / fallback names** (`@.value`, `@.to`, EIP-712 message
//!   fields that aren't in the format key's `top_names`): the index is
//!   the first two bytes (big-endian) of `keccak256(name)`.
//!
//! Both cases collapse to the same wire shape: a `u16` lookup key. The
//! caller decides which convention to use when building each `Struct`'s
//! `AbiField::idx` list — positional for `#`-rooted structs that
//! mirror the format-key parameter list, keccak-prefix for `@`-rooted
//! containers. The walker simply linear-scans for a matching `idx`.

use crate::ir::IrError;

/// Where a path resolves to once the walker has chased every opcode.
/// The display layer uses this enum to pick the formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiValue<'a> {
    Uint { bits: u16, be32: &'a [u8; 32] },
    Int { bits: u16, be32: &'a [u8; 32] },
    Address(&'a [u8; 20]),
    Bool(bool),
    BytesN { width: u8, bytes: &'a [u8] },
    Bytes(&'a [u8]),
    String(&'a [u8]),
}

/// Internal node in the caller-supplied ABI tree. Mirrors `AbiValue`
/// plus the compound variants (`Struct`, `Array`) that the walker
/// descends into.
#[derive(Clone, Copy, Debug)]
pub enum AbiNode<'a> {
    Uint { bits: u16, be32: &'a [u8; 32] },
    Int { bits: u16, be32: &'a [u8; 32] },
    Address(&'a [u8; 20]),
    Bool(bool),
    BytesN { width: u8, bytes: &'a [u8] },
    Bytes(&'a [u8]),
    String(&'a [u8]),
    /// Struct / tuple. Fields are looked up by `idx`. The order in
    /// the slice does not matter for lookup; storing them in `idx`
    /// order is just convention. Pass `&[]` for an empty struct.
    Struct(&'a [AbiField<'a>]),
    /// Array. Elements are addressed by 0-based position.
    Array(&'a [AbiNode<'a>]),
}

/// One field of an `AbiNode::Struct`. `idx` is the walker lookup key —
/// see the module comment for the dual indexing convention.
#[derive(Clone, Copy, Debug)]
pub struct AbiField<'a> {
    pub idx: u16,
    pub node: AbiNode<'a>,
}

impl<'a> AbiNode<'a> {
    /// Convert a leaf node into the public `AbiValue`. Returns
    /// `IrError::BadField` for compound nodes (struct / array) — those
    /// must be descended into before the walker finishes.
    pub fn into_value(self) -> Result<AbiValue<'a>, IrError> {
        match self {
            AbiNode::Uint { bits, be32 } => Ok(AbiValue::Uint { bits, be32 }),
            AbiNode::Int { bits, be32 } => Ok(AbiValue::Int { bits, be32 }),
            AbiNode::Address(a) => Ok(AbiValue::Address(a)),
            AbiNode::Bool(b) => Ok(AbiValue::Bool(b)),
            AbiNode::BytesN { width, bytes } => {
                Ok(AbiValue::BytesN { width, bytes })
            }
            AbiNode::Bytes(b) => Ok(AbiValue::Bytes(b)),
            AbiNode::String(s) => Ok(AbiValue::String(s)),
            AbiNode::Struct(_) | AbiNode::Array(_) => Err(IrError::BadField),
        }
    }

    /// Descend one struct field by its `u16` index (positional or
    /// keccak-prefix per the module comment). Returns `BadField` if
    /// `self` is not a struct or the index is not present.
    pub fn descend_field(&self, idx: u16) -> Result<AbiNode<'a>, IrError> {
        match self {
            AbiNode::Struct(fields) => fields
                .iter()
                .find(|f| f.idx == idx)
                .map(|f| f.node)
                .ok_or(IrError::BadField),
            _ => Err(IrError::BadField),
        }
    }

    /// Descend one array element by 0-based index. Returns `BadField`
    /// if `self` is not an array or the index is out of range.
    pub fn descend_array_idx(&self, idx: u32) -> Result<AbiNode<'a>, IrError> {
        match self {
            AbiNode::Array(elems) => elems
                .get(idx as usize)
                .copied()
                .ok_or(IrError::BadField),
            _ => Err(IrError::BadField),
        }
    }

    /// Descend the last element of an array.
    pub fn descend_array_last(&self) -> Result<AbiNode<'a>, IrError> {
        match self {
            AbiNode::Array(elems) => elems
                .last()
                .copied()
                .ok_or(IrError::BadField),
            _ => Err(IrError::BadField),
        }
    }
}

/// Caller-supplied view of one ABI-decoded payload (a calldata body
/// after the 4-byte selector, or an EIP-712 typed-data message). For
/// the seed corpus this is always a `Struct` at the top level.
#[derive(Clone, Copy, Debug)]
pub struct AbiView<'a> {
    pub root: AbiNode<'a>,
}

impl<'a> AbiView<'a> {
    pub fn new(root: AbiNode<'a>) -> Self {
        AbiView { root }
    }
}

/// Caller-supplied view of the transaction envelope (the `@` root).
/// Field indices follow the keccak-prefix convention — see the module
/// comment. Constants for the well-known envelope fields are in
/// [`container_field`].
#[derive(Clone, Copy, Debug)]
pub struct ContainerView<'a> {
    pub root: AbiNode<'a>,
}

impl<'a> ContainerView<'a> {
    pub fn new(root: AbiNode<'a>) -> Self {
        ContainerView { root }
    }
}

/// Pre-computed `keccak256(name)[..2]` field indices for the
/// well-known transaction-envelope (`@`) fields. The values are
/// frozen wire constants — host emitter (`dbgen::erc7730`) and
/// on-device walker MUST agree.
///
/// Verified by `dbgen/tests/erc7730_roundtrip.rs::container_indices`
/// against the live keccak256 implementation.
pub mod container_field {
    /// `@.value` — native-token amount being transferred (32 B uint).
    pub const VALUE: u16 = 0x81AF;
    /// `@.to` — destination contract address (20 B).
    pub const TO: u16 = 0x1B56;
    /// `@.from` — sender address; the AA wallet itself (20 B).
    pub const FROM: u16 = 0x45A9;
    /// `@.chainId` — EIP-155 chain id (u64).
    pub const CHAIN_ID: u16 = 0x8ED9;
    /// `@.nonce` — EIP-1559 / AA nonce (32 B uint).
    pub const NONCE: u16 = 0x7AB1;
}

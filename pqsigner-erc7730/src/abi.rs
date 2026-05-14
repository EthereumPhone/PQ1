//! Thin wrapper over `pqsigner-tx::typed_call::abi` for the ERC-7730
//! walker. ERC-7730 specifies path references over an ABI-decoded view
//! of calldata (or an EIP-712 message). The shape pass + value extract
//! that the existing Phase-2 typed-call decoder already performs is
//! exactly what the walker needs — this module exists so the walker
//! talks to a small, stable surface rather than reaching into the
//! typed-call internals directly.
//!
//! Phase-1 stub: define the surface, defer the real wiring to Phase 5
//! when the walker actually runs. The interface here is final so other
//! Phase-1 work (binding, bundle, ir) can compile and test against it.

use crate::ir::IrError;

/// Where a path resolves to once the walker has chased every opcode.
/// The display layer uses this enum to pick the formatter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiValue<'a> {
    /// A static uint of `bits` bits, big-endian. For uint256 the slice
    /// is 32 bytes; smaller widths are still padded to 32 in the ABI
    /// head, but `bits` carries the type-level width.
    Uint { bits: u16, be32: &'a [u8; 32] },
    /// A static int of `bits` bits, two's-complement, big-endian.
    Int { bits: u16, be32: &'a [u8; 32] },
    /// 20-byte EVM address.
    Address(&'a [u8; 20]),
    /// Boolean (last byte of the 32-byte slot).
    Bool(bool),
    /// Fixed-width `bytesN`.
    BytesN { width: u8, bytes: &'a [u8] },
    /// Dynamic-length `bytes`.
    Bytes(&'a [u8]),
    /// Dynamic-length `string` (UTF-8 in the spec; we still display as
    /// ASCII-or-`?` on the OLED per anti-spoof policy).
    String(&'a [u8]),
}

/// A handle to the parsed-shape view of an ABI-decoded payload. The
/// real implementation in Phase 5 will wrap the existing
/// `pqsigner-tx::typed_call::abi::Walked` slices. For Phase 1 this is a
/// placeholder so the walker entry-point compiles.
#[derive(Clone, Copy, Debug)]
pub struct AbiView<'a> {
    /// Calldata head + tail combined (the raw inner-tx data, sans the
    /// 4-byte selector).
    pub body: &'a [u8],
}

impl<'a> AbiView<'a> {
    /// Build an `AbiView` from raw calldata excluding the 4-byte
    /// selector. The walker is the only consumer; nothing else needs
    /// this surface yet.
    pub fn new(body: &'a [u8]) -> Self {
        AbiView { body }
    }
}

/// Resolve a single ABI field by zero-based index into the decoded
/// argument list. Phase-5 wiring will route through the existing
/// `typed_call::abi::walk_shape` pass; Phase 1 stubs as unimplemented
/// so call sites get a typed error rather than a panic.
pub fn field_by_index<'a>(_view: &AbiView<'a>, _index: u16) -> Result<AbiValue<'a>, IrError> {
    // Stub: real implementation lands in Phase 5 alongside the path
    // bytecode interpreter. Returning a typed error keeps callers
    // honest until then.
    Err(IrError::BadField)
}

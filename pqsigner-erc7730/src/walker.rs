//! Path-bytecode interpreter — Phase 1 stub.
//!
//! In Phase 5 the walker resolves a compiled-path opcode sequence
//! against an `AbiView` and yields an `AbiValue` for the formatter
//! layer to render. Today it is a placeholder so the crate's public
//! surface (`Erc7730Ir`, `verify_erc7730_bundle`, `cross_check_*`) is
//! complete and the secure-side re-export shim can compile.
//!
//! The interface is intentionally minimal so the Phase 5 wiring can
//! land without touching call sites elsewhere.

use crate::abi::{AbiValue, AbiView};
use crate::ir::{Erc7730Ir, IrError, PathOp};

/// One step of a compiled path. Read from the metadata pool; produced
/// by the host compiler in `dbgen::erc7730`. The TLV variants encode
/// any per-step arguments (array index, slice bounds, field index).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStep {
    Root(PathOp),
    FieldIdx(u16),
    ArrayIdx(u32),
    ArraySlice { start: u32, end: u32 },
    ArrayLast,
    ArrayAll,
}

/// Resolve a compiled-path bytecode sequence into a single
/// `AbiValue`. Phase 1 stub.
pub fn resolve<'a>(
    _ir: &Erc7730Ir<'a>,
    _view: &AbiView<'a>,
    _steps: &[PathStep],
) -> Result<AbiValue<'a>, IrError> {
    // Phase 5: walk the steps against the view, returning the resolved
    // value. For Phase 1 we return a typed error so callers compile
    // but get a deterministic failure mode until the walker lands.
    Err(IrError::BadField)
}

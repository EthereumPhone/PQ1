//! Path-bytecode interpreter.
//!
//! Resolves a compiled ERC-7730 path program against a caller-supplied
//! ABI tree (`#`-root), transaction-envelope view (`@`-root), or
//! descriptor metadata pool (`$`-root) and yields an `AbiValue` for the
//! Phase 4 formatter layer.
//!
//! ## Wire format
//!
//! Path programs live inside the IR metadata pool. The host emitter
//! (`dbgen::erc7730::compile_path`) writes them as
//!
//! ```text
//!   [u8 prog_len]   // total opcode + arg bytes that follow
//!   [u8 root_op]    // PathOp::Root{Structured,Container,Metadata}
//!   [opcode + args]*
//! ```
//!
//! Operands per opcode:
//!
//! | Op                       | Byte | Args                                   |
//! |--------------------------|------|----------------------------------------|
//! | `RootStructured`  (`#`)  | 0x10 | none                                   |
//! | `RootContainer`   (`@`)  | 0x11 | none                                   |
//! | `RootMetadata`    (`$`)  | 0x12 | none                                   |
//! | `FieldIdx`               | 0x20 | u16 BE                                 |
//! | `ArrayIdx`               | 0x21 | u32 BE                                 |
//! | `ArraySlice`             | 0x22 | u32 BE start, u32 BE end               |
//! | `ArrayLast`              | 0x23 | none                                   |
//! | `ArrayAll`               | 0x24 | none                                   |
//!
//! The first opcode MUST be a Root*. Subsequent opcodes descend.
//!
//! ## Caps
//!
//! * `MAX_NESTING` (`ir::MAX_NESTING = 8`) bounds descent depth. The
//!   walker counts each `FieldIdx` / `ArrayIdx` / `ArrayLast` as one
//!   level; root opcodes don't count.
//! * `MAX_PATH_PROGRAM_LEN` (255) is enforced by the pool length prefix.
//!
//! ## What is NOT supported in Phase 3
//!
//! * `RootMetadata` (`$`) — Phase 2 inlines metadata constants into the
//!   format-table TLVs (parameter offsets), so the walker doesn't have
//!   to chase `$` at runtime. Returns `IrError::BadField` if seen.
//! * `ArraySlice` / `ArrayAll` — these yield multi-value results that
//!   the Phase 4 formatter renders as concatenated bytes; the
//!   single-`AbiValue` return of `resolve_path` can't express them yet.
//!   Reserved opcodes; refused with `IrError::BadField` for now.
//!
//! Both gaps are intentional — the seed corpus contains zero uses of
//! either, and adding multi-value support without alloc requires the
//! Phase 4 renderer to call the walker once per leaf rather than
//! flattening up-front. Captured in the Phase 3 → Phase 4 handoff.

#![allow(clippy::redundant_field_names)]

use core::convert::TryFrom;

use crate::abi::{AbiNode, AbiValue, AbiView, ContainerView};
use crate::ir::{Erc7730Ir, IrError, MAX_NESTING, PathOp};

/// The three views the walker can resolve against. The caller wires
/// only the root(s) it actually has bytes for; missing roots cause
/// `IrError::BadField` if a program tries to descend into them.
#[derive(Clone, Copy, Debug)]
pub struct WalkerCtx<'a> {
    /// `#` — ABI-decoded calldata head (contract context) or
    /// EIP-712 message body. Required for paths starting with `#` or
    /// for bare-name paths (the host compiler defaults to `#`).
    pub structured: Option<AbiView<'a>>,
    /// `@` — transaction envelope (EIP-1559 / AA UserOp). Required
    /// for any path starting with `@`.
    pub container: Option<ContainerView<'a>>,
}

impl<'a> WalkerCtx<'a> {
    /// New context with both roots set.
    pub fn new(structured: AbiView<'a>, container: ContainerView<'a>) -> Self {
        WalkerCtx {
            structured: Some(structured),
            container: Some(container),
        }
    }

    /// New context with only `#` populated. Use when there is no
    /// envelope (host signers, fuzz targets, …).
    pub fn structured_only(view: AbiView<'a>) -> Self {
        WalkerCtx {
            structured: Some(view),
            container: None,
        }
    }
}

/// Reach into the IR's metadata pool to fetch the bytes of a path
/// program at `path_off`. The first byte is the program length; the
/// returned slice covers the opcodes that follow.
///
/// `path_off == 0` is permitted as a "no path" sentinel — returns an
/// empty slice. The caller decides whether that is acceptable for its
/// formatter context.
pub fn path_bytes<'a>(ir: &Erc7730Ir<'a>, path_off: u16) -> Result<&'a [u8], IrError> {
    if path_off == 0 {
        return Ok(&[]);
    }
    let off = path_off as usize;
    let len = *ir.pool.get(off).ok_or(IrError::BadField)? as usize;
    ir.pool
        .get(off + 1..off + 1 + len)
        .ok_or(IrError::BadField)
}

/// Resolve a path program (at `path_off` inside `ir.pool`) against
/// `ctx` and return the final `AbiValue`. The returned value borrows
/// from `ctx`; the IR is consulted only for the program bytes.
pub fn resolve_path<'a, 'b>(
    ir: &Erc7730Ir<'a>,
    ctx: &WalkerCtx<'b>,
    path_off: u16,
) -> Result<AbiValue<'b>, IrError> {
    let prog = path_bytes(ir, path_off)?;
    resolve_program(prog, ctx)
}

/// Lower-level entry point — resolve `prog` (the opcode bytes, NO
/// length prefix) directly. Used by tests and by the secure-side
/// caller when the path bytes have already been extracted.
pub fn resolve_program<'a, 'b>(
    prog: &'a [u8],
    ctx: &WalkerCtx<'b>,
) -> Result<AbiValue<'b>, IrError> {
    if prog.is_empty() {
        return Err(IrError::BadField);
    }

    // 1. Root.
    let mut p = 0;
    let root_op = PathOp::try_from(prog[p])?;
    p += 1;

    let mut cur: AbiNode<'b> = match root_op {
        PathOp::RootStructured => {
            ctx.structured.ok_or(IrError::BadField)?.root
        }
        PathOp::RootContainer => {
            ctx.container.ok_or(IrError::BadField)?.root
        }
        PathOp::RootMetadata => {
            // Phase 3: not implemented. Metadata constants are inlined
            // into format-table TLVs at compile time, so a path that
            // walks `$` at runtime is malformed for Phase 3.
            return Err(IrError::BadField);
        }
        // The first opcode MUST be a Root.
        PathOp::FieldIdx
        | PathOp::ArrayIdx
        | PathOp::ArraySlice
        | PathOp::ArrayLast
        | PathOp::ArrayAll => return Err(IrError::BadField),
    };

    // 2. Descend.
    let mut depth = 0usize;
    while p < prog.len() {
        let op = PathOp::try_from(prog[p])?;
        p += 1;
        match op {
            // Roots inside the descent stream are illegal.
            PathOp::RootStructured | PathOp::RootContainer | PathOp::RootMetadata => {
                return Err(IrError::BadField);
            }
            PathOp::FieldIdx => {
                if p + 2 > prog.len() {
                    return Err(IrError::BadField);
                }
                let idx = u16::from_be_bytes([prog[p], prog[p + 1]]);
                p += 2;
                cur = cur.descend_field(idx)?;
                depth = bump_depth(depth)?;
            }
            PathOp::ArrayIdx => {
                if p + 4 > prog.len() {
                    return Err(IrError::BadField);
                }
                let idx = u32::from_be_bytes([
                    prog[p],
                    prog[p + 1],
                    prog[p + 2],
                    prog[p + 3],
                ]);
                p += 4;
                cur = cur.descend_array_idx(idx)?;
                depth = bump_depth(depth)?;
            }
            PathOp::ArrayLast => {
                cur = cur.descend_array_last()?;
                depth = bump_depth(depth)?;
            }
            PathOp::ArraySlice => {
                // 8 bytes of args we must still consume to keep
                // the cursor aligned, even though we refuse.
                if p + 8 > prog.len() {
                    return Err(IrError::BadField);
                }
                return Err(IrError::BadField);
            }
            PathOp::ArrayAll => {
                return Err(IrError::BadField);
            }
        }
    }

    cur.into_value()
}

#[inline]
fn bump_depth(d: usize) -> Result<usize, IrError> {
    let next = d + 1;
    if next > MAX_NESTING {
        return Err(IrError::OverCap);
    }
    Ok(next)
}

// ─── Compiled-path step enum (re-exported for callers that want to
//     introspect a program without re-running the interpreter — e.g.
//     the formatter visibility pre-pass) ─────────────────────────────

/// One step of a compiled path. Phase 3 keeps this type around for
/// callers that need to introspect a program (e.g. to decide whether
/// it ever touches `$.metadata` and therefore needs the inlined
/// constants). The walker itself does NOT allocate any sequence of
/// these — it advances the byte cursor directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathStep {
    Root(PathOp),
    FieldIdx(u16),
    ArrayIdx(u32),
    ArraySlice { start: u32, end: u32 },
    ArrayLast,
    ArrayAll,
}

/// Backwards-compatible entry point kept from the Phase 1 stub. New
/// callers should prefer [`resolve_path`] or [`resolve_program`].
#[doc(hidden)]
pub fn resolve<'a>(
    _ir: &Erc7730Ir<'a>,
    _view: &AbiView<'a>,
    _steps: &[PathStep],
) -> Result<AbiValue<'a>, IrError> {
    Err(IrError::BadField)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{container_field, AbiField, AbiNode, AbiView, ContainerView};
    use crate::ir::{CTX_CONTRACT, HEADER_LEN, SCHEMA_VER};

    // Helpers ──────────────────────────────────────────────────────

    fn be32(low: u8) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[31] = low;
        buf
    }

    fn build_ir_with_pool(pool: std::vec::Vec<u8>) -> std::vec::Vec<u8> {
        let pool_len = pool.len();
        let mut buf = std::vec![0u8; HEADER_LEN];
        buf[0] = SCHEMA_VER;
        buf[1] = CTX_CONTRACT;
        buf[2..10].copy_from_slice(&1u64.to_be_bytes());
        let metadata_off = HEADER_LEN as u16;
        let formats_off = (HEADER_LEN + pool_len) as u16;
        buf[126..128].copy_from_slice(&metadata_off.to_be_bytes());
        buf[128..130].copy_from_slice(&formats_off.to_be_bytes());
        buf[130..132].copy_from_slice(&(pool_len as u16).to_be_bytes());
        buf[132..134].copy_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&pool);
        buf.push(0u8); // format count
        buf
    }

    // path_bytes ───────────────────────────────────────────────────

    #[test]
    fn path_bytes_zero_off_is_empty() {
        let ir_bytes = build_ir_with_pool(std::vec![]);
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert_eq!(path_bytes(&ir, 0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn path_bytes_reads_prefix() {
        // Pool with a 1-byte filler at offset 0 (so `path_off == 0`
        // stays a "no path" sentinel for the walker) and a 3-opcode
        // path program at offset 1: `[len=3 | 0x10 0x20 0x00]` for
        // `#.field0`. The length byte sits at offset 1; opcodes at 2..5.
        let pool = std::vec![0xFFu8, 3, 0x10, 0x20, 0x00];
        let ir_bytes = build_ir_with_pool(pool);
        let ir = Erc7730Ir::parse(&ir_bytes).unwrap();
        assert_eq!(path_bytes(&ir, 1).unwrap(), &[0x10u8, 0x20, 0x00]);
    }

    // Structured descent ───────────────────────────────────────────

    #[test]
    fn structured_root_top_level_field() {
        // #.field[1] → Address(0x11..)
        let addr = [0x11u8; 20];
        let fields = [
            AbiField {
                idx: 0,
                node: AbiNode::Uint { bits: 256, be32: &be32(0xAA) },
            },
            AbiField {
                idx: 1,
                node: AbiNode::Address(&addr),
            },
        ];
        let view = AbiView::new(AbiNode::Struct(&fields));
        let ctx = WalkerCtx::structured_only(view);

        // Program: [Root=#][FieldIdx][be16 1]
        let prog = [0x10u8, 0x20, 0x00, 0x01];
        let v = resolve_program(&prog, &ctx).unwrap();
        assert_eq!(v, AbiValue::Address(&addr));
    }

    #[test]
    fn structured_nested_struct() {
        // #.params.amountIn — top has one struct field, inner has two.
        let val = be32(0x42);
        let inner = [
            AbiField {
                idx: 0,
                node: AbiNode::Uint { bits: 256, be32: &val },
            },
            AbiField {
                idx: 1,
                node: AbiNode::Uint { bits: 256, be32: &be32(0xFF) },
            },
        ];
        let top = [AbiField {
            idx: 0,
            node: AbiNode::Struct(&inner),
        }];
        let view = AbiView::new(AbiNode::Struct(&top));
        let ctx = WalkerCtx::structured_only(view);

        // Program: [#][FieldIdx 0][FieldIdx 0]
        let prog = [0x10u8, 0x20, 0, 0, 0x20, 0, 0];
        let v = resolve_program(&prog, &ctx).unwrap();
        assert_eq!(v, AbiValue::Uint { bits: 256, be32: &val });
    }

    #[test]
    fn structured_field_not_found() {
        let fields = [AbiField {
            idx: 0,
            node: AbiNode::Bool(true),
        }];
        let view = AbiView::new(AbiNode::Struct(&fields));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x10u8, 0x20, 0, 99];
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    // Container descent ────────────────────────────────────────────

    #[test]
    fn container_value_field() {
        let val = be32(0x77);
        let to_addr = [0xDEu8; 20];
        // Container is a Struct keyed by keccak-prefix per
        // container_field::*.
        let fields = [
            AbiField {
                idx: container_field::VALUE,
                node: AbiNode::Uint { bits: 256, be32: &val },
            },
            AbiField {
                idx: container_field::TO,
                node: AbiNode::Address(&to_addr),
            },
        ];
        let container = ContainerView::new(AbiNode::Struct(&fields));
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::new(view, container);

        // Program: [@][FieldIdx container_field::VALUE]
        let mut prog = std::vec![0x11u8, 0x20];
        prog.extend_from_slice(&container_field::VALUE.to_be_bytes());
        let v = resolve_program(&prog, &ctx).unwrap();
        assert_eq!(v, AbiValue::Uint { bits: 256, be32: &val });

        let mut prog2 = std::vec![0x11u8, 0x20];
        prog2.extend_from_slice(&container_field::TO.to_be_bytes());
        let v2 = resolve_program(&prog2, &ctx).unwrap();
        assert_eq!(v2, AbiValue::Address(&to_addr));
    }

    #[test]
    fn container_missing_yields_bad_field() {
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x11u8]; // @ root with no container set
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    // Array descent ────────────────────────────────────────────────

    #[test]
    fn array_idx_picks_element() {
        let a = be32(0x01);
        let b = be32(0x02);
        let c = be32(0x03);
        let elems = [
            AbiNode::Uint { bits: 256, be32: &a },
            AbiNode::Uint { bits: 256, be32: &b },
            AbiNode::Uint { bits: 256, be32: &c },
        ];
        let top = [AbiField {
            idx: 0,
            node: AbiNode::Array(&elems),
        }];
        let view = AbiView::new(AbiNode::Struct(&top));
        let ctx = WalkerCtx::structured_only(view);

        // #.arr[1]
        let prog = [0x10u8, 0x20, 0, 0, 0x21, 0, 0, 0, 1];
        let v = resolve_program(&prog, &ctx).unwrap();
        assert_eq!(v, AbiValue::Uint { bits: 256, be32: &b });
    }

    #[test]
    fn array_last_picks_tail() {
        let a = be32(0x01);
        let b = be32(0x02);
        let elems = [
            AbiNode::Uint { bits: 256, be32: &a },
            AbiNode::Uint { bits: 256, be32: &b },
        ];
        let top = [AbiField {
            idx: 0,
            node: AbiNode::Array(&elems),
        }];
        let view = AbiView::new(AbiNode::Struct(&top));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x10u8, 0x20, 0, 0, 0x23];
        let v = resolve_program(&prog, &ctx).unwrap();
        assert_eq!(v, AbiValue::Uint { bits: 256, be32: &b });
    }

    #[test]
    fn array_oob_rejected() {
        let a = be32(0x01);
        let elems = [AbiNode::Uint { bits: 256, be32: &a }];
        let top = [AbiField {
            idx: 0,
            node: AbiNode::Array(&elems),
        }];
        let view = AbiView::new(AbiNode::Struct(&top));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x10u8, 0x20, 0, 0, 0x21, 0, 0, 0, 5];
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    // Malformed programs ───────────────────────────────────────────

    #[test]
    fn empty_program_rejected() {
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::structured_only(view);
        assert_eq!(resolve_program(&[], &ctx), Err(IrError::BadField));
    }

    #[test]
    fn root_not_first_rejected() {
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x20u8, 0, 0]; // FieldIdx as first op
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    #[test]
    fn root_inside_descent_rejected() {
        let fields = [AbiField {
            idx: 0,
            node: AbiNode::Bool(true),
        }];
        let view = AbiView::new(AbiNode::Struct(&fields));
        let ctx = WalkerCtx::structured_only(view);
        // [#][FieldIdx 0][#] — second root is illegal
        let prog = [0x10u8, 0x20, 0, 0, 0x10];
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    #[test]
    fn truncated_field_arg_rejected() {
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x10u8, 0x20, 0]; // missing second byte of idx
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    #[test]
    fn metadata_root_unsupported() {
        let view = AbiView::new(AbiNode::Struct(&[]));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x12u8];
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    #[test]
    fn array_all_unsupported() {
        let a = be32(0x01);
        let elems = [AbiNode::Uint { bits: 256, be32: &a }];
        let top = [AbiField {
            idx: 0,
            node: AbiNode::Array(&elems),
        }];
        let view = AbiView::new(AbiNode::Struct(&top));
        let ctx = WalkerCtx::structured_only(view);
        let prog = [0x10u8, 0x20, 0, 0, 0x24];
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::BadField));
    }

    #[test]
    fn descent_depth_capped() {
        // Build a 10-deep struct chain so each FieldIdx step descends
        // into another struct (never hits a leaf). The walker counts
        // each descent and trips `OverCap` when the bumped depth would
        // exceed `MAX_NESTING = 8` — i.e. on the 9th step.
        let leaf = be32(0xFF);
        let n9 = AbiNode::Uint { bits: 256, be32: &leaf };
        let f8 = [AbiField { idx: 0, node: n9 }];
        let n8 = AbiNode::Struct(&f8);
        let f7 = [AbiField { idx: 0, node: n8 }];
        let n7 = AbiNode::Struct(&f7);
        let f6 = [AbiField { idx: 0, node: n7 }];
        let n6 = AbiNode::Struct(&f6);
        let f5 = [AbiField { idx: 0, node: n6 }];
        let n5 = AbiNode::Struct(&f5);
        let f4 = [AbiField { idx: 0, node: n5 }];
        let n4 = AbiNode::Struct(&f4);
        let f3 = [AbiField { idx: 0, node: n4 }];
        let n3 = AbiNode::Struct(&f3);
        let f2 = [AbiField { idx: 0, node: n3 }];
        let n2 = AbiNode::Struct(&f2);
        let f1 = [AbiField { idx: 0, node: n2 }];
        let n1 = AbiNode::Struct(&f1);
        let f0 = [AbiField { idx: 0, node: n1 }];
        let n0 = AbiNode::Struct(&f0);
        let view = AbiView::new(n0);
        let ctx = WalkerCtx::structured_only(view);
        // [#] + 9 × FieldIdx(0) — 9 levels of descent ⇒ OverCap on #9.
        let mut prog = std::vec![0x10u8];
        for _ in 0..9 {
            prog.push(0x20);
            prog.push(0);
            prog.push(0);
        }
        assert_eq!(resolve_program(&prog, &ctx), Err(IrError::OverCap));
    }
}

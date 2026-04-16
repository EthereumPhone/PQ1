//! NS pointer + length bounds checks.
//!
//! Every gateway command receives raw pointers from the non-secure
//! world. Before the secure world touches a single byte of memory
//! those pointers describe, it MUST prove:
//!
//!   1. The target range lies entirely inside a known NS region
//!      (NS SRAM for writes, NS SRAM or NS flash for reads).
//!   2. The range does not alias the shared mailbox — otherwise a
//!      hostile NS could get the secure world to overwrite the very
//!      command word it's still interpreting.
//!   3. The arithmetic `ptr + len` does not overflow.
//!   4. (HIGH-1) On ARMv8-M, the SAU actually classifies every byte
//!      of the range as Non-Secure *right now*. The constant-range
//!      check above uses compile-time constants that go stale if
//!      `memory.x` / `sau.rs` change without everyone updating
//!      `shared/src/lib.rs`. The TT instruction asks the hardware
//!      directly.
//!
//! These helpers are called on every `cmd_*` entry; keeping them in a
//! single tiny file makes the memory-boundary invariants easy to audit.

use sphincs_tz_shared::{
    NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, SHARED_MAILBOX_BASE, SHARED_MAILBOX_END,
};

/// ARMv8-M `TT` (Test Target) — ask the SAU/IDAU for the security
/// attributes of `addr` in the *current* security state. Returns the
/// 32-bit TT response word as described in ARMv8-M Reference Manual.
///
/// Bits of interest:
///   bit 23 S     — 1 if address is Secure, 0 if Non-Secure
///   bit 21 NSR   — 1 if Non-Secure readable from NS
///   bit 22 NSRW  — 1 if Non-Secure read-write from NS
///   bit 20 SRVLD — 1 if SAU region valid
///
/// Only present on real STM32U585 hardware — QEMU mps2-an505 has no
/// real SAU (the workaround there is the shared-mailbox dispatch).
#[cfg(feature = "stm32u585")]
#[inline(always)]
fn tt(addr: u32) -> u32 {
    let r: u32;
    // SAFETY: `tt` is a pure query instruction with no side effects on
    // architectural state; it reads the SAU/IDAU classification of
    // the target address. The `nomem` / `nostack` hints let LLVM reorder
    // around it freely.
    unsafe {
        core::arch::asm!(
            "tt {out}, {addr}",
            out = out(reg) r,
            addr = in(reg) addr,
            options(nomem, nostack, preserves_flags),
        );
    }
    r
}

/// Check that every byte in `[ptr, ptr+len)` is classified as
/// Non-Secure by the SAU, returning `false` otherwise. Stride the TT
/// instruction at 32-byte granularity (SAU regions are always 32-byte
/// aligned, so it's enough to test one byte per aligned block plus
/// the final byte).
#[cfg(feature = "stm32u585")]
fn tt_range_is_ns(ptr: u32, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let end_incl = match ptr.checked_add(len as u32 - 1) {
        Some(e) => e,
        None => return false,
    };

    let s_bit = |r: u32| ((r >> 23) & 1) == 0;
    let nsr_bit = |r: u32| ((r >> 21) & 1) == 1;
    let ok = |r: u32| s_bit(r) && nsr_bit(r);

    if !ok(tt(ptr)) || !ok(tt(end_incl)) {
        return false;
    }
    // Stride through the middle 32-byte blocks.
    let mut cur = (ptr + 32) & !31;
    while cur < end_incl {
        if !ok(tt(cur)) {
            return false;
        }
        cur = match cur.checked_add(32) {
            Some(v) => v,
            None => return false,
        };
    }
    true
}

#[cfg(not(feature = "stm32u585"))]
fn tt_range_is_ns(_ptr: u32, _len: usize) -> bool {
    // QEMU workaround: there is no real SAU in the mps2-an505 path
    // we care about; the constant-window checks below are the only
    // validator. Always allow — the caller guarantees the range
    // was also verified against the constant window.
    true
}

/// Validate that `ptr + len` falls entirely within a non-secure memory
/// region the secure world is allowed to **write** to (NS SRAM only),
/// and does not overlap the shared mailbox.
#[inline]
pub(super) fn validate_ns_write_ptr(ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    if !(ptr >= NS_SRAM_BASE && end <= NS_SRAM_END) {
        return false;
    }
    // Reject any overlap with the shared mailbox region.
    if ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE {
        return false;
    }
    // HIGH-1: double-check against the SAU in hardware.
    if !tt_range_is_ns(ptr, len) {
        return false;
    }
    true
}

/// Validate that `ptr + len` falls entirely within a non-secure memory
/// region the secure world is allowed to **read** from. Allows both NS
/// SRAM and NS flash (the latter is read-only and can hold static
/// payloads like an unsigned tx). The shared mailbox is excluded.
#[inline]
pub(super) fn validate_ns_read_ptr(ptr: u32, len: usize) -> bool {
    if ptr == 0 {
        return false;
    }
    let end = match ptr.checked_add(len as u32) {
        Some(e) => e,
        None => return false,
    };
    let in_sram = ptr >= NS_SRAM_BASE && end <= NS_SRAM_END;
    let in_flash = ptr >= NS_FLASH_BASE && end <= NS_FLASH_END;
    if !(in_sram || in_flash) {
        return false;
    }
    if in_sram && ptr < SHARED_MAILBOX_END && end > SHARED_MAILBOX_BASE {
        return false;
    }
    // HIGH-1: double-check against the SAU in hardware.
    if !tt_range_is_ns(ptr, len) {
        return false;
    }
    true
}

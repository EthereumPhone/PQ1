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
//!
//! These helpers are called on every `cmd_*` entry; keeping them in a
//! single tiny file makes the memory-boundary invariants easy to audit.

use sphincs_tz_shared::{
    NS_FLASH_BASE, NS_FLASH_END, NS_SRAM_BASE, NS_SRAM_END, SHARED_MAILBOX_BASE, SHARED_MAILBOX_END,
};

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
    true
}

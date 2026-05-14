//! Fault-sweep target for the off-chain counter SCAN logic in
//! `secure/src/hw/flash.rs::offchain_count_read` + `parse_entry`. The page
//! storage lives in RAM here (not real flash), but the scan code is
//! bit-identical to production.
//!
//! **Attack we're testing.** A fault that makes `offchain_count_read`
//! return a value LOWER than the actual maximum in flash. Each successful
//! attack lets `cmd_sign_offchain` (and `cmd_sign_userop`'s combined cap
//! check) believe the counter is lower than it is → permits one extra
//! signature past the MAX_SLOT_USES = 65,536 cap. Over N successful
//! attacks: N extra signatures. This is the F-10 attack class extended to
//! the underlying counter machinery.
//!
//! Two entry-points:
//!   - `sca_flashctr_read_plain(page_ptr, slot_key_ptr) -> u64`
//!     Verbatim mirror of the production scan loop. Should always return
//!     the actual max.
//!   - `sca_flashctr_read_fi(page_ptr, slot_key_ptr) -> u64`
//!     Hardened variant: scans the page TWICE with `wait_random()` between,
//!     compares results, halts on glitch. Two coordinated faults required
//!     to bypass.
//!
//! Page layout (matches production):
//!   Each 16-byte quad-word:
//!     [ 0.. 8) slot_key (8 bytes)
//!     [ 8.. 9) type     (0x01 = OFFCHAIN_TYPE_COUNT, 0x02 = OFFCHAIN_TYPE_USEROP, 0xFF = blank)
//!     [ 9..16) count    (7-byte BE, supports up to 2^56)

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

const OFFCHAIN_CAPACITY: usize = 512;       // 8 KB / 16 B per QW
const OFFCHAIN_QW_SIZE: usize = 16;
const OFFCHAIN_TYPE_COUNT: u8 = 0x01;
const OFFCHAIN_TYPE_USEROP: u8 = 0x02;

#[inline(never)]
fn wait_random() {
    pqsigner_fi::wait_random_loop(|| 0x42);
}

// ---------------------------------------------------------------------------
// Verbatim mirror of `parse_entry` from secure/src/hw/flash.rs:983.
// Returns:
//   None — QW is truly blank (every byte 0xFF). End of journal.
//   Some((0, _, _))    — stale/undecodable QW. Skip and keep scanning.
//   Some((1|2, sk, c)) — valid entry.
// ---------------------------------------------------------------------------

#[inline(never)]
fn parse_entry(qw_addr: *const u8) -> Option<(u8, [u8; 8], u64)> {
    unsafe {
        let base = qw_addr;
        let type_byte = core::ptr::read_volatile(base.add(8));
        if type_byte == 0xFF {
            // All-blank check (mirrors find_next_blank_idx).
            let mut all_blank = true;
            for k in 0..OFFCHAIN_QW_SIZE {
                if core::ptr::read_volatile(base.add(k)) != 0xFF {
                    all_blank = false;
                    break;
                }
            }
            if all_blank {
                return None;
            }
            // Type byte is 0xFF but other bytes aren't → stale; keep scanning.
            return Some((0, [0u8; 8], 0));
        }
        if type_byte != OFFCHAIN_TYPE_COUNT && type_byte != OFFCHAIN_TYPE_USEROP {
            return Some((0, [0u8; 8], 0));
        }
        let mut slot_key = [0u8; 8];
        for k in 0..8 {
            slot_key[k] = core::ptr::read_volatile(base.add(k));
        }
        let mut count_be = [0u8; 8];
        // 7-byte BE count packed in bytes 9..16; high byte = 0
        for k in 0..7 {
            count_be[1 + k] = core::ptr::read_volatile(base.add(9 + k));
        }
        let count = u64::from_be_bytes(count_be);
        Some((type_byte, slot_key, count))
    }
}

// ---------------------------------------------------------------------------
// Plain mirror — verbatim from secure/src/hw/flash.rs:1256.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_flashctr_read_plain(page_ptr: *const u8, slot_key_ptr: *const u8) -> u64 {
    // SAFETY: harness maps 8 KB at page_ptr (full page) and 8 B at slot_key_ptr.
    let slot_key: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    let mut latest: u64 = 0;
    let mut found = false;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = unsafe { page_ptr.add(i * OFFCHAIN_QW_SIZE) };
        match parse_entry(addr) {
            None => break,
            Some((t, sk, count)) if t == OFFCHAIN_TYPE_COUNT && sk == slot_key => {
                if count > latest || !found {
                    latest = count;
                    found = true;
                }
            }
            _ => {}
        }
    }
    latest
}

// ---------------------------------------------------------------------------
// FI-hardened mirror — bit-equivalent to the production F-12 fix:
// forward + reverse scan with wait_random between, halt-on-mismatch.
// The reverse pass has asymmetric control flow (no early-break on blank;
// iterates from end-of-page back to 0), so a control-flow corruption
// at forward-scan entry doesn't symmetrically affect the reverse pass.
// ---------------------------------------------------------------------------

#[inline(never)]
fn scan_once(page_ptr: *const u8, slot_key: &[u8; 8]) -> u64 {
    let mut latest: u64 = 0;
    let mut found = false;
    for i in 0..OFFCHAIN_CAPACITY {
        let addr = unsafe { page_ptr.add(i * OFFCHAIN_QW_SIZE) };
        match parse_entry(addr) {
            None => break,
            Some((t, sk, count)) if t == OFFCHAIN_TYPE_COUNT && sk == *slot_key => {
                if count > latest || !found {
                    latest = count;
                    found = true;
                }
            }
            _ => {}
        }
    }
    latest
}

#[inline(never)]
fn scan_reverse(page_ptr: *const u8, slot_key: &[u8; 8]) -> u64 {
    let mut latest: u64 = 0;
    let mut i = OFFCHAIN_CAPACITY;
    while i > 0 {
        i -= 1;
        let addr = unsafe { page_ptr.add(i * OFFCHAIN_QW_SIZE) };
        if let Some((t, sk, count)) = parse_entry(addr) {
            if t == OFFCHAIN_TYPE_COUNT && sk == *slot_key && count > latest {
                latest = count;
            }
        }
    }
    latest
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_flashctr_read_fi(page_ptr: *const u8, slot_key_ptr: *const u8) -> u64 {
    // F-12 hardening: input-register redundancy on slot_key.
    let sk_a: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    wait_random();
    let sk_b: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    if sk_a != sk_b {
        return u64::MAX;
    }
    let r1 = scan_once(page_ptr, &sk_a);
    wait_random();
    let r2 = scan_reverse(page_ptr, &sk_b);
    if r1 != r2 {
        return u64::MAX;
    }
    r1
}

// ---------------------------------------------------------------------------
// WRITE PATH — mirror of offchain_count_bump (hw/flash.rs:1326). Tests
// whether a single fault can:
//   - Make bump return Ok WITHOUT actually writing the entry (silent write
//     failure → firmware emits a signature without counting it).
//   - Make bump skip the post-write verify-after-read check.
//
// Production has three layers of defense in bump:
//   1. write_entry's own program-and-verify (mirrored here as a memcpy-and-cmp)
//   2. read-after-write: post = read(); if post != new_count { return Err }
//   3. FI-hardened triple-check: check_true_into_sentinel(|| read == new_count)
//
// A single fault would need to bypass enough layers to (a) skip the actual
// write AND (b) make all three verify steps pass. The harness reports both:
//   - the function's return code (encoded in r0)
//   - whether the page actually got a new entry (the harness inspects the
//     page bytes after the call)
//
// Mirror page MUST be writable RAM (not the read-only ELF rodata where
// PAGE lives in read tests). Harness writes the populated entries to the
// scratch RAM region before each call, then reads back the same region
// to check the resulting state.
// ---------------------------------------------------------------------------

const ENTRY_OK: u32 = 0;
const ENTRY_ERR_MONOTONICITY: u32 = 1;
const ENTRY_ERR_NO_BLANK: u32 = 2;
const ENTRY_ERR_WRITE_VERIFY: u32 = 3;
const ENTRY_ERR_POST_CHECK: u32 = 4;
const ENTRY_ERR_FI_TRIPLE_CHECK: u32 = 5;

#[inline(never)]
fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}

/// Find the first all-0xFF (truly blank) QW in the page. Returns its index
/// in 0..OFFCHAIN_CAPACITY, or None if the page is full.
#[inline(never)]
fn find_next_blank_idx(page_ptr: *mut u8) -> Option<usize> {
    for i in 0..OFFCHAIN_CAPACITY {
        let qw_base = unsafe { page_ptr.add(i * OFFCHAIN_QW_SIZE) };
        let mut all_blank = true;
        for k in 0..OFFCHAIN_QW_SIZE {
            if unsafe { core::ptr::read_volatile(qw_base.add(k)) } != 0xFF {
                all_blank = false;
                break;
            }
        }
        if all_blank {
            return Some(i);
        }
    }
    None
}

/// Mirror of write_quadword_verified — program 16 bytes and verify they
/// read back identical. (Production uses STM32 flash controller's program
/// instruction; here it's just a memcpy + cmp on the RAM-backed page.)
#[inline(never)]
fn write_quadword_verified(dst: *mut u8, qw: &[u8; OFFCHAIN_QW_SIZE]) -> Result<(), ()> {
    for k in 0..OFFCHAIN_QW_SIZE {
        unsafe { core::ptr::write_volatile(dst.add(k), qw[k]) };
    }
    // Verify each byte read-back matches.
    for k in 0..OFFCHAIN_QW_SIZE {
        if unsafe { core::ptr::read_volatile(dst.add(k)) } != qw[k] {
            return Err(());
        }
    }
    Ok(())
}

/// Pack an entry. Mirrors entry_qw in hw/flash.rs:956.
#[inline(never)]
fn pack_entry(slot_key: &[u8; 8], type_byte: u8, count: u64) -> [u8; OFFCHAIN_QW_SIZE] {
    let mut qw = [0u8; OFFCHAIN_QW_SIZE];
    qw[..8].copy_from_slice(slot_key);
    qw[8] = type_byte;
    let count_be = count.to_be_bytes();
    qw[9..16].copy_from_slice(&count_be[1..8]); // 7-byte BE
    qw
}

/// Mirror of offchain_count_bump (hw/flash.rs:1326) — verbatim production logic,
/// but the page lives at page_ptr (RAM-backed). Returns the same status codes
/// the production code returns (Ok via 0; Err via 1..=5 mapping the rejection
/// reason).
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_flashctr_bump_plain(
    page_ptr: *mut u8,
    slot_key_ptr: *const u8,
    new_count_lo: u32,
    new_count_hi: u32,
) -> u32 {
    let slot_key: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    let new_count: u64 = (new_count_lo as u64) | ((new_count_hi as u64) << 32);

    // Step 1: pre-check monotonicity.
    let pre = scan_once(page_ptr as *const u8, &slot_key);
    if new_count <= pre {
        return ENTRY_ERR_MONOTONICITY;
    }

    // Step 2: pack entry.
    let qw = pack_entry(&slot_key, OFFCHAIN_TYPE_COUNT, new_count);

    // Step 3: find blank QW. (Production compacts on full; mirror just fails.)
    let blank = match find_next_blank_idx(page_ptr) {
        Some(i) => i,
        None => return ENTRY_ERR_NO_BLANK,
    };

    // Step 4: write the entry.
    let dst = unsafe { page_ptr.add(blank * OFFCHAIN_QW_SIZE) };
    if write_quadword_verified(dst, &qw).is_err() {
        return ENTRY_ERR_WRITE_VERIFY;
    }

    // Step 5: read-after-write check (post == new_count).
    let post = scan_once(page_ptr as *const u8, &slot_key);
    if post != new_count {
        return ENTRY_ERR_POST_CHECK;
    }

    // Step 6: FI-hardened triple-check via check_true_into_sentinel.
    let verdict = check_true_into_sentinel(|| {
        scan_once(page_ptr as *const u8, &slot_key) == new_count
    });
    if verdict != pqsigner_fi::OK_SENTINEL {
        return ENTRY_ERR_FI_TRIPLE_CHECK;
    }

    ENTRY_OK
}

/// FI-hardened bump mirror. Matches the production F-12 fix: read the
/// slot_key into two stack-local copies separated by wait_random, halt
/// on mismatch (catches stuck-at on the slot_key argument register), and
/// uses the forward+reverse hardened scan for both pre and post checks.
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_flashctr_bump_fi(
    page_ptr: *mut u8,
    slot_key_ptr: *const u8,
    new_count_lo: u32,
    new_count_hi: u32,
) -> u32 {
    // F-12: input-register redundancy — load slot_key twice with a
    // random gap, halt if they diverge. A glitch that clamps the
    // register to 0 only persists for one of the two loads.
    let sk_a: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    wait_random();
    let sk_b: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    if sk_a != sk_b {
        return ENTRY_ERR_FI_TRIPLE_CHECK;
    }
    let slot_key = sk_a;
    let new_count: u64 = (new_count_lo as u64) | ((new_count_hi as u64) << 32);

    // Pre-check: forward+reverse, halt-on-mismatch.
    let pre_fwd = scan_once(page_ptr as *const u8, &slot_key);
    wait_random();
    let pre_rev = scan_reverse(page_ptr as *const u8, &slot_key);
    if pre_fwd != pre_rev {
        return ENTRY_ERR_FI_TRIPLE_CHECK;
    }
    if new_count <= pre_fwd {
        return ENTRY_ERR_MONOTONICITY;
    }

    let qw = pack_entry(&slot_key, OFFCHAIN_TYPE_COUNT, new_count);
    let blank = match find_next_blank_idx(page_ptr) {
        Some(i) => i,
        None => return ENTRY_ERR_NO_BLANK,
    };
    let dst = unsafe { page_ptr.add(blank * OFFCHAIN_QW_SIZE) };
    if write_quadword_verified(dst, &qw).is_err() {
        return ENTRY_ERR_WRITE_VERIFY;
    }

    // Post-check: forward+reverse, halt-on-mismatch.
    let post_fwd = scan_once(page_ptr as *const u8, &slot_key);
    wait_random();
    let post_rev = scan_reverse(page_ptr as *const u8, &slot_key);
    if post_fwd != post_rev {
        return ENTRY_ERR_FI_TRIPLE_CHECK;
    }
    if post_fwd != new_count {
        return ENTRY_ERR_POST_CHECK;
    }

    let verdict = check_true_into_sentinel(|| {
        scan_once(page_ptr as *const u8, &slot_key) == new_count
    });
    if verdict != pqsigner_fi::OK_SENTINEL {
        return ENTRY_ERR_FI_TRIPLE_CHECK;
    }

    ENTRY_OK
}

#[used]
static _KEEP_PLAIN: extern "C" fn(*const u8, *const u8) -> u64 = sca_flashctr_read_plain;
#[used]
static _KEEP_FI: extern "C" fn(*const u8, *const u8) -> u64 = sca_flashctr_read_fi;
#[used]
static _KEEP_BUMP: extern "C" fn(*mut u8, *const u8, u32, u32) -> u32 = sca_flashctr_bump_plain;
#[used]
static _KEEP_BUMP_FI: extern "C" fn(*mut u8, *const u8, u32, u32) -> u32 = sca_flashctr_bump_fi;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_PLAIN);
    core::hint::black_box(&_KEEP_FI);
    core::hint::black_box(&_KEEP_BUMP);
    core::hint::black_box(&_KEEP_BUMP_FI);
    loop {
        cortex_m::asm::nop();
    }
}

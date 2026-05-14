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
// FI-hardened mirror — scan TWICE with wait_random between, halt-on-mismatch.
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
#[no_mangle]
pub extern "C" fn sca_flashctr_read_fi(page_ptr: *const u8, slot_key_ptr: *const u8) -> u64 {
    let slot_key: [u8; 8] = unsafe { *(slot_key_ptr as *const [u8; 8]) };
    let r1 = scan_once(page_ptr, &slot_key);
    wait_random();
    let r2 = scan_once(page_ptr, &slot_key);
    // Halt on mismatch — better than silently returning the wrong value.
    if r1 != r2 {
        // FAIL_SENTINEL pattern: caller compares against the expected
        // result; any halt-on-glitch value is "fail." We return u64::MAX
        // here because it's clearly not a legitimate counter value (well
        // past any realistic count and past MAX_SLOT_USES).
        return u64::MAX;
    }
    r1
}

#[used]
static _KEEP_PLAIN: extern "C" fn(*const u8, *const u8) -> u64 = sca_flashctr_read_plain;
#[used]
static _KEEP_FI: extern "C" fn(*const u8, *const u8) -> u64 = sca_flashctr_read_fi;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_PLAIN);
    core::hint::black_box(&_KEEP_FI);
    loop {
        cortex_m::asm::nop();
    }
}

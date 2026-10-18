//! NS pointer-validation boundary table (`ns-ptr-probe`, DVT row 3.8).
//!
//! Calls every pointer-taking gateway entry with each pointer from a
//! boundary table (secure SRAM/flash, the NSC veneers, both edges of the NS
//! SRAM window, wrap-around, peripherals, NS aliases of secure memory) while
//! the other arguments stay valid, and stores each returned status in
//! `NS_PTR_PROBE_RES`. Nothing is printed: the host reads the statics over
//! SWD (`tools/dvt/ns_ptr_probe.py`). Expected: every out-of-window pointer
//! returns `InvalidPointer` (4) and the core never faults.
//!
//! Needs a secure image with `e2e-test` (pre-unlocked) and `mock-se`. Signing
//! and firmware-update entries are probed only with invalid pointers or
//! garbage payloads, so no path reaches a signature or a flash erase.

#![allow(static_mut_refs)]

use core::sync::atomic::{AtomicU32, Ordering};
use sphincs_tz_shared::MAX_SIGN_RESPONSE_LEN;

unsafe extern "C" {
    fn nsc_is_unlocked() -> u32;
    fn nsc_get_wallet_address(out_ptr: u32, account_index: u32, show: u32) -> u32;
    fn nsc_get_init_code(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
    fn nsc_sign_offchain(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
    fn nsc_offchain_status(in_ptr: u32, out_ptr: u32, in_len: u32) -> u32;
    fn nsc_offchain_sync(in_ptr: u32, in_len: u32) -> u32;
    fn nsc_sign_userop(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_sign_userop_batch(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_fw_begin(manifest_ptr: u32, manifest_len: u32) -> u32;
    fn nsc_fw_chunk(chunk_ptr: u32, chunk_len: u32) -> u32;
    fn nsc_fw_status(out_ptr: u32) -> u32;
    fn nsc_get_pin_attempt_log(out_ptr: u32) -> u32;
}

pub const MAX_RES: usize = 512;
/// One word per call: `cmd << 24 | arg << 16 | case << 8 | status`.
#[used]
#[no_mangle]
pub static mut NS_PTR_PROBE_RES: [u32; MAX_RES] = [0; MAX_RES];
#[used]
#[no_mangle]
pub static NS_PTR_PROBE_N: AtomicU32 = AtomicU32::new(0);
/// 0 running, 1 done, 2 the gateway was not pre-unlocked.
#[used]
#[no_mangle]
pub static NS_PTR_PROBE_DONE: AtomicU32 = AtomicU32::new(0);
/// Addresses the host should read before and after (written pointer cases).
#[used]
#[no_mangle]
pub static mut NS_PTR_PROBE_CASES: [u32; 16] = [0; 16];

static mut IN_BUF: [u8; 8192] = [0xFF; 8192];
/// SIGN_OFFCHAIN input: 17-B header with payload_len = 32 and kind 0xFF (refused by the parser).
static mut IN_OFF: [u8; 49] = [0xFF; 49];
/// OFFCHAIN_SYNC input, 21 B of 0xFF (slot index out of range, refused by the parser).
static mut IN_SYNC: [u8; 21] = [0xFF; 21];
/// SIGN_USEROP input: 330-B header, data_len = 0, all other fields 0xFF.
static mut IN_UOP: [u8; 330] = [0xFF; 330];
static mut OUT_BUF: [u8; MAX_SIGN_RESPONSE_LEN] = [0; MAX_SIGN_RESPONSE_LEN];

fn rec(cmd: u32, arg: u32, case: u32, status: u32) {
    let n = NS_PTR_PROBE_N.load(Ordering::Relaxed) as usize;
    if n < MAX_RES {
        // SAFETY: single-threaded NS runner; the host reads below NS_PTR_PROBE_N.
        unsafe { NS_PTR_PROBE_RES[n] = cmd << 24 | arg << 16 | case << 8 | (status & 0xFF) };
        NS_PTR_PROBE_N.store(n as u32 + 1, Ordering::Release);
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    // SAFETY: the veneer is a plain query.
    if unsafe { nsc_is_unlocked() } != 1 {
        NS_PTR_PROBE_DONE.store(2, Ordering::Release);
        loop {
            cortex_m::asm::wfi();
        }
    }
    // A valid GET_INIT_CODE input (account 0, chain 1) so the control case
    // reaches the write; every other parser still sees 0xFF garbage after it.
    // SAFETY: single-threaded.
    unsafe { IN_BUF[..12].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) };
    let inb = unsafe { IN_BUF.as_ptr() } as u32;
    // SAFETY: single-threaded.
    unsafe {
        IN_OFF[14] = 0;
        IN_OFF[15] = 32;
        IN_UOP[328] = 0;
        IN_UOP[329] = 0;
    }
    let offb = unsafe { IN_OFF.as_ptr() } as u32;
    let syncb = unsafe { IN_SYNC.as_ptr() } as u32;
    let uopb = unsafe { IN_UOP.as_ptr() } as u32;
    let outb = unsafe { OUT_BUF.as_mut_ptr() } as u32;
    let veneer = nsc_is_unlocked as usize as u32 & !1;
    // Boundary pointers. Index = case number in the results.
    let cases: [u32; 15] = [
        0x0000_0000,     // 0 null
        0x2002_FFFC,     // 1 straddles the NS SRAM window start
        0x2003_FFFC,     // 2 straddles the NS SRAM window end
        0x2004_0000,     // 3 just past the window end
        0x2000_0000,     // 4 NS alias of secure SRAM1
        0x3000_0000,     // 5 secure SRAM1
        0x0C00_0000,     // 6 secure flash
        veneer,          // 7 NSC veneer region
        0x0800_0000,     // 8 NS alias of secure flash bank 1
        0xFFFF_FFF0,     // 9 wraps the address space
        0x4000_0000,     // 10 NS peripheral alias
        0x5000_0000,     // 11 secure peripheral alias
        0x0810_0000,     // 12 NS flash bank 2 (readable window)
        0x2003_F000,     // 13 inside the window, 4 KB below the NS stack top (unused)
        u32::MAX,        // 14 placeholder: the valid NS buffer (control)
    ];
    // SAFETY: single-threaded.
    unsafe {
        for (i, c) in cases.iter().enumerate() {
            NS_PTR_PROBE_CASES[i] = *c;
        }
    }
    let pick = |i: usize, valid: u32| if i == 14 { valid } else { cases[i] };

    // Garbage-but-well-sized inputs (all 0xFF, so every parser refuses them).
    // SAFETY: the veneers validate every pointer before use; this is the test.
    unsafe {
        for i in 0..cases.len() {
            let c = i as u32;
            // Write-only out pointers.
            rec(1, 0, c, nsc_get_wallet_address(pick(i, outb), 0, 0));
            rec(2, 0, c, nsc_get_pin_attempt_log(pick(i, outb)));
            rec(3, 0, c, nsc_fw_status(pick(i, outb)));
            // offchain_status: in (arg 0) then out (arg 1).
            rec(4, 0, c, nsc_offchain_status(pick(i, inb), outb, 13));
            rec(4, 1, c, nsc_offchain_status(inb, pick(i, outb), 13));
            // get_init_code: in 12 B (account u32 BE, chain u64 BE).
            rec(5, 0, c, nsc_get_init_code(pick(i, inb), outb, 12));
            rec(5, 1, c, nsc_get_init_code(inb, pick(i, outb), 12));
            // Off-chain sign and sync: every case, with inputs the parser refuses.
            rec(6, 0, c, nsc_sign_offchain(pick(i, offb), outb, 17 + 32));
            rec(6, 1, c, nsc_sign_offchain(offb, pick(i, outb), 17 + 32));
            rec(7, 0, c, nsc_offchain_sync(pick(i, syncb), 21));
            // UserOp signing and FW entries: invalid pointers only (case 14 skipped).
            if i != 14 {
                rec(8, 0, c, nsc_sign_userop(cases[i], outb, 330));
                rec(8, 1, c, nsc_sign_userop(uopb, cases[i], 330));
                rec(9, 0, c, nsc_sign_userop_batch(cases[i], outb, 330));
                rec(10, 0, c, nsc_fw_begin(cases[i], 8192));
                rec(11, 0, c, nsc_fw_chunk(cases[i], 1024));
            }
        }
        // Length abuse with valid pointers (case numbers 0x20+).
        rec(4, 2, 0x20, nsc_offchain_status(inb, outb, 0xFFFF_FFFF));
        rec(5, 2, 0x21, nsc_get_init_code(inb, outb, 0x8000_0000));
        rec(10, 2, 0x22, nsc_fw_begin(inb, 0xFFFF_FFFF));
        rec(6, 2, 0x23, nsc_sign_offchain(0x2003_FFE0, outb, 17 + 32)); // in runs past the window
        rec(8, 2, 0x24, nsc_sign_userop(uopb, outb, 0xFFFF_FFFF));
        rec(11, 2, 0x25, nsc_fw_chunk(0x3000_0000, 0)); // secure pointer, zero length
        rec(4, 2, 0x26, nsc_offchain_status(0x3000_0000, outb, 0)); // secure pointer, zero length
        rec(5, 2, 0x27, nsc_get_init_code(inb, 0x2003_FFF0, 12)); // 4,280-B write past the window end
    }
    NS_PTR_PROBE_DONE.store(1, Ordering::Release);
    loop {
        cortex_m::asm::wfi();
    }
}

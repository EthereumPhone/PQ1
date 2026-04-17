//! Key-speed bench runner.
//!
//! Measures wall-clock JARDÍN signing time on real STM32U585 hardware
//! at 160 MHz, using the DWT cycle counter enabled by the secure world.
//! Pairs with the `e2e-test` feature on the secure crate (auto-provisions
//! a fixed test mnemonic and pre-unlocks the gateway, so this runner
//! never needs to drive the PIN UI).
//!
//! Emits three measurements per run:
//!   * first-sign on a fresh chain  → Type 1 (C10) + slot keygen + Type 2
//!   * N subsequent signs on same chain → Type 2 only (slot cached)
//!   * first-sign on a second chain  → a second Type 1 data point
//!
//! Output lines are parseable by `make test-key-speed`, which asserts
//! on the final `PASS` marker.

#![allow(static_mut_refs)]

use crate::nsc_api;
use cortex_m_semihosting::{debug, hprintln};
use sphincs_tz_shared::{
    MAX_JARDIN_RESPONSE_LEN, NscStatus, SIGN_USEROP_HEADER_LEN,
};

// === Scratch buffers =======================================================

static mut SIG_BUF: [u8; MAX_JARDIN_RESPONSE_LEN] = [0u8; MAX_JARDIN_RESPONSE_LEN];
static mut PAYLOAD_BUF: [u8; SIGN_USEROP_HEADER_LEN + 64] =
    [0u8; SIGN_USEROP_HEADER_LEN + 64];

// === Timing ===============================================================

/// DWT cycle counter. Enabled by the secure world in `main.rs` right
/// before booting NS. Free-running 32-bit at CPU core frequency.
const DWT_CYCCNT: *const u32 = 0xE000_1004 as *const u32;

/// Secure-world sets SYSCLK to 160 MHz via PLL1 (see `hw::rcc::init`).
/// A 32-bit cycle counter wraps every ~26.8 s at this rate; single-op
/// deltas comfortably fit.
const CPU_HZ: u32 = 160_000_000;

#[inline(always)]
fn cycles_now() -> u32 {
    unsafe { core::ptr::read_volatile(DWT_CYCCNT) }
}

#[inline]
fn ms_from_cycles(c: u32) -> u32 {
    c / (CPU_HZ / 1000)
}

// === Payload builder =======================================================

/// EntryPoint v0.9 canonical address (Sepolia).
const ENTRY_POINT_V09: [u8; 20] = [
    0x43, 0x37, 0x09, 0x00, 0x9B, 0x83, 0x30, 0xFD, 0xa3, 0x23, 0x11, 0xDF, 0x1C, 0x2A, 0xFA, 0x40,
    0x2e, 0xD8, 0xD0, 0x09,
];

/// `keccak256("")` — empty paymaster and empty inner data hash.
const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

fn build_payload(buf: &mut [u8], chain_id: u64, nonce_seq: u64) -> usize {
    let sender: [u8; 20] = [0x42; 20];
    let to: [u8; 20] = [0xab; 20];
    let mut nonce = [0u8; 32];
    nonce[24..32].copy_from_slice(&nonce_seq.to_be_bytes());

    // accountGasLimits = (300_000 << 128) | 50_000
    let mut agl = [0u8; 32];
    agl[0..16].copy_from_slice(&300_000u128.to_be_bytes());
    agl[16..32].copy_from_slice(&50_000u128.to_be_bytes());

    let mut pre_gas = [0u8; 32];
    pre_gas[28..32].copy_from_slice(&100_000u32.to_be_bytes());

    // gasFees = (2 gwei << 128) | 10 gwei
    let mut gf = [0u8; 32];
    gf[0..16].copy_from_slice(&2_000_000_000u128.to_be_bytes());
    gf[16..32].copy_from_slice(&10_000_000_000u128.to_be_bytes());

    let mut value = [0u8; 32];
    value[16..32].copy_from_slice(&1_000_000_000_000_000_000u128.to_be_bytes()); // 1 ETH

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // slot_index_hint / flags
    off += 4;
    buf[off..off + 20].copy_from_slice(&sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&ENTRY_POINT_V09);
    off += 20;
    buf[off..off + 32].copy_from_slice(&nonce);
    off += 32;
    buf[off..off + 32].copy_from_slice(&agl);
    off += 32;
    buf[off..off + 32].copy_from_slice(&pre_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&gf);
    off += 32;
    buf[off..off + 32].copy_from_slice(&KECCAK_EMPTY);
    off += 32;
    buf[off..off + 20].copy_from_slice(&to);
    off += 20;
    buf[off..off + 32].copy_from_slice(&value);
    off += 32;
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes()); // data_len
    off += 2;
    debug_assert_eq!(off, SIGN_USEROP_HEADER_LEN);
    off
}

// === Single-sign timing primitive =========================================

struct SignTiming {
    cycles: u32,
    ms: u32,
    status: u32,
}

fn time_one_sign(chain_id: u64, nonce_seq: u64) -> SignTiming {
    unsafe {
        let len = build_payload(&mut PAYLOAD_BUF, chain_id, nonce_seq);
        let t0 = cycles_now();
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        let t1 = cycles_now();
        let cycles = t1.wrapping_sub(t0);
        SignTiming {
            cycles,
            ms: ms_from_cycles(cycles),
            status,
        }
    }
}

// === Entry ================================================================

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS][bench] === JARDÍN key-speed bench @ 160 MHz ===");

    // Secure `e2e-test` auto-provisions + pre-unlocks. Verify, don't drive
    // the PIN UI (there's no button input in this automated flow).
    if !nsc_api::is_unlocked() {
        hprintln!("[NS][bench] FAIL: gateway not pre-unlocked (needs e2e-test on secure)");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("[NS][bench] gateway pre-unlocked: OK");

    // ---- A. first-sign on chain 1: Type 1 + slot keygen + Type 2 ----
    let a = time_one_sign(1, 1);
    if a.status != NscStatus::Ok as u32 {
        hprintln!("[NS][bench] FAIL: first-sign on chain 1 = status {}", a.status);
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!(
        "[NS][bench] A) chain=1 first-sign   (type1 + slot-keygen + type2): {} cycles, {} ms",
        a.cycles, a.ms
    );

    // ---- B. N subsequent signs on chain 1: Type 2 only (slot cached) ----
    const N: u32 = 5;
    let mut total_b: u64 = 0;
    for i in 0..N {
        let b = time_one_sign(1, 2 + i as u64);
        if b.status != NscStatus::Ok as u32 {
            hprintln!(
                "[NS][bench] FAIL: type2 #{} on chain 1 = status {}",
                i + 1,
                b.status
            );
            debug::exit(debug::EXIT_FAILURE);
            loop {}
        }
        hprintln!(
            "[NS][bench] B{}) chain=1 type2-only (slot cached):              {} cycles, {} ms",
            i + 1,
            b.cycles,
            b.ms
        );
        total_b += b.cycles as u64;
    }
    let avg_b_cycles = (total_b / N as u64) as u32;
    let avg_b_ms = ms_from_cycles(avg_b_cycles);
    hprintln!(
        "[NS][bench] B-avg) type2-only over {} runs:                        {} cycles, {} ms",
        N, avg_b_cycles, avg_b_ms
    );

    // ---- C. first-sign on chain 2: second Type 1 + keygen + Type 2 ----
    let c = time_one_sign(2, 1);
    if c.status != NscStatus::Ok as u32 {
        hprintln!("[NS][bench] FAIL: first-sign on chain 2 = status {}", c.status);
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!(
        "[NS][bench] C) chain=2 first-sign   (type1 + slot-keygen + type2): {} cycles, {} ms",
        c.cycles, c.ms
    );

    // Derived estimate: A - B_avg ≈ cost of (Type 1 + slot keygen).
    // Not exact (Type 2 on first-sign reruns the slot keygen while
    // cached Type 2 does not), but a useful upper bound.
    let type1_plus_keygen_estimate = a.cycles.saturating_sub(avg_b_cycles);
    hprintln!(
        "[NS][bench] est) type1+keygen (A - B_avg):                         {} cycles, {} ms",
        type1_plus_keygen_estimate,
        ms_from_cycles(type1_plus_keygen_estimate)
    );

    hprintln!("[NS][bench] === PASS ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

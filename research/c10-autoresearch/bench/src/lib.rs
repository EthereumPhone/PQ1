//! C10 autoresearch kit bench (SRAM-only, B-U585I-IOT02A). FROZEN evaluator: do not edit during the loop.
//! Runs keygen, sign(m0, shuffle A), sign(m0, shuffle B), verify(m0), sign(m1, shuffle A), verify(m1)
//! with the fixed inputs of `inputs.rs`, times each on DWT_CYCCNT, and leaves the results at
//! 0x30000100 (OUT) and the two signatures in SIG0/SIG1 for the runner to read back over SWD.
#![no_std]
use sphincs_c10::{params::SIGNATURE_LEN, shuffle::ShuffleSeed, SigningKey};

include!("../../inputs.rs");

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
pub const OUT_WORDS: usize = 32;
const MAGIC: u32 = 0x4331_3042; // 'C10B'

#[no_mangle]
pub static mut SIG0: [u8; SIGNATURE_LEN] = [0; SIGNATURE_LEN];
#[no_mangle]
pub static mut SIG1: [u8; SIGNATURE_LEN] = [0; SIGNATURE_LEN];

extern "C" {
    fn bench_halt(code: u32) -> !;
}

#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: DWT_CYCCNT, enabled by startup.c; a plain read.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}
#[inline(always)]
fn out(i: usize, v: u32) {
    // SAFETY: OUT..OUT+32 words is reserved (0x30000100..0x300001FF, below the image).
    unsafe { core::ptr::write_volatile(OUT.add(i), v) }
}

#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    // SAFETY: C harness function, diverges.
    unsafe { bench_halt(0x00F0) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: as above.
    unsafe { bench_halt(0x00F1) }
}

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..OUT_WORDS {
        out(i, 0);
    }
    out(0, MAGIC);
    let t = cyc();
    // SAFETY: boot-time, single-threaded, no hash in flight.
    unsafe { pqsigner_hw::hash::init_clock() };
    out(2, cyc().wrapping_sub(t));
    out(1, 1);

    let t = cyc();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    out(3, cyc().wrapping_sub(t));
    out(1, 2);

    let t = cyc();
    let s0 = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    out(4, cyc().wrapping_sub(t));
    out(1, 3);
    let t = cyc();
    let s0b = sk.sign_with_shuffle_silent(&MSG0, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_B));
    out(5, cyc().wrapping_sub(t));
    out(1, 4);
    let vk = sk.verifying_key();
    let t = cyc();
    let ok0 = vk.verify(&MSG0, &s0);
    out(6, cyc().wrapping_sub(t));
    out(1, 5);
    let t = cyc();
    let s1 = sk.sign_with_shuffle_silent(&MSG1, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
    out(7, cyc().wrapping_sub(t));
    out(1, 6);
    let t = cyc();
    let ok1 = vk.verify(&MSG1, &s1);
    out(8, cyc().wrapping_sub(t));
    out(1, 7);

    let flags = (ok0 as u32) | ((ok1 as u32) << 1) | (((s0 == s0b) as u32) << 2);
    out(9, flags);
    let pk = sk.pk_root();
    for w in 0..4 {
        out(10 + w, u32::from_le_bytes([pk[4 * w], pk[4 * w + 1], pk[4 * w + 2], pk[4 * w + 3]]));
    }
    // SAFETY: single-threaded; the runner reads these after the core halts.
    unsafe {
        core::ptr::addr_of_mut!(SIG0).write_volatile(s0);
        core::ptr::addr_of_mut!(SIG1).write_volatile(s1);
    }
    out(1, 8);
}

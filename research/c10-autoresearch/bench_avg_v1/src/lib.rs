// MEASUREMENT VARIANT (#1155 round 5): average single-pass sign cost over NMSG
// messages, so WOTS+C / FORS+C grind luck (tens of thousands of tries,
// message-dependent) averages out of a v1 vs v2 comparison. Not a gate: each
// configuration's bytes are gated by its own golden run (experiment_flash.sh /
// experiment_v2.sh); here every signature must verify on-device.
#![no_std]
use sphincs_c10::{shuffle::ShuffleSeed, SigningKey};

include!("../../inputs.rs");

const OUT: *mut u32 = 0x3000_0100 as *mut u32;
const MAGIC: u32 = 0x4331_3041; // 'C10A'
const NMSG: u32 = 16;

// The runner reads these out (it refuses an image without them): the last
// message's signature, and the first's.
#[no_mangle]
pub static mut SIG0: [u8; sphincs_c10::params::SIGNATURE_LEN] = [0; sphincs_c10::params::SIGNATURE_LEN];
#[no_mangle]
pub static mut SIG1: [u8; sphincs_c10::params::SIGNATURE_LEN] = [0; sphincs_c10::params::SIGNATURE_LEN];

extern "C" {
    fn bench_halt(code: u32) -> !;
}
#[inline(always)]
fn cyc() -> u32 {
    // SAFETY: DWT_CYCCNT, enabled by the harness.
    unsafe { core::ptr::read_volatile(0xE000_1004 as *const u32) }
}
#[inline(always)]
fn out(i: usize, v: u32) {
    // SAFETY: the harness's result window (32 words at OUT).
    unsafe { core::ptr::write_volatile(OUT.add(i), v) }
}
#[no_mangle]
pub extern "C" fn pqsigner_hash_fault() -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F0) }
}
// Round 10 product-shaped measurement: the same stubs as `bench` (the secure world's
// `pqsigner_hash_tick` -> `film_tick_hash` per-call path; the time-paced frame draw is not modelled).
#[cfg(feature = "tick")]
mod tick {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    static FILM_LIVE: AtomicBool = AtomicBool::new(true);
    static FILM_HASHES: AtomicU32 = AtomicU32::new(0);
    #[inline(never)]
    fn film_tick_paced() {
        core::hint::black_box(());
    }
    /// Stub of the secure world's `pqsigner_hash_tick` -> `film_tick_hash` (ui/px/lcd.rs), drawing nothing.
    #[no_mangle]
    pub extern "C" fn pqsigner_hash_tick() {
        if !FILM_LIVE.load(Ordering::Relaxed) {
            return;
        }
        let n = FILM_HASHES.load(Ordering::Relaxed).wrapping_add(1);
        FILM_HASHES.store(n, Ordering::Relaxed);
        if n % 64 == 0 {
            film_tick_paced();
        }
    }
    /// Batched form: `k` digests at once; a frame check when the count crosses a multiple of 64.
    #[no_mangle]
    pub extern "C" fn pqsigner_hash_tick_n(k: u32) {
        if !FILM_LIVE.load(Ordering::Relaxed) {
            return;
        }
        let o = FILM_HASHES.load(Ordering::Relaxed);
        let n = o.wrapping_add(k);
        FILM_HASHES.store(n, Ordering::Relaxed);
        if n / 64 != o / 64 {
            film_tick_paced();
        }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: harness halt.
    unsafe { bench_halt(0x00F1) }
}

#[no_mangle]
pub extern "C" fn c10_bench_main() {
    for i in 0..32 {
        out(i, 0);
    }
    out(0, MAGIC);
    // SAFETY: first HASH use; the harness raised the clock.
    unsafe { pqsigner_hw::hash::init_clock() };
    out(1, 1);
    let t = cyc();
    let sk = SigningKey::keygen(SK_SEED, PK_SEED);
    out(3, cyc().wrapping_sub(t));
    let vk = sk.verifying_key();
    let (mut sum, mut vsum, mut ok) = (0u64, 0u64, 0u32);
    for i in 0..NMSG {
        let mut m = MSG0;
        m[0..4].copy_from_slice(&i.to_le_bytes());
        m[4] ^= 0xA5;
        let t = cyc();
        let s = sk.sign_with_shuffle_silent(&m, Some(&OPT_RAND), &ShuffleSeed(SHUFFLE_A));
        let dt = cyc().wrapping_sub(t);
        sum += u64::from(dt);
        out(16 + i as usize, dt);
        // SAFETY: single-threaded; read by the runner after the halt.
        unsafe {
            if i == 0 {
                core::ptr::addr_of_mut!(SIG1).write_volatile(s);
            }
            core::ptr::addr_of_mut!(SIG0).write_volatile(s);
        }
        let t = cyc();
        ok += u32::from(vk.verify(&m, &s));
        vsum += u64::from(cyc().wrapping_sub(t));
        out(1, 2 + i);
    }
    out(4, sum as u32);
    out(5, (sum >> 32) as u32);
    out(6, vsum as u32);
    out(7, ok);
    out(1, 100);
}

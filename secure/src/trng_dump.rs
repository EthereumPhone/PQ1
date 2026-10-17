//! TRNG output dump for SP 800-90B assessment (`trng-dump` feature, DVT row 4.8).
//!
//! Runs once at boot right after `hw::rng::init`, then never returns. Fills a
//! 64 KB secure-SRAM buffer through the production `rng::fill` path (the
//! same CR/HTCR/NSCR configuration, conditioning, error recovery and software
//! CRNGT every consumer gets), bumps `TRNG_DUMP_SEQ`, and spins until the host
//! writes that sequence number to `TRNG_DUMP_ACK`. The host reads the buffer
//! over SWD (`tools/dvt/trng_dump.py`); nothing is printed, so the image runs
//! without a debugger attached and needs no semihosting.
//!
//! Bench only: the buffer holds TRNG output in the clear. Never ship.

use core::sync::atomic::{AtomicU32, Ordering};

pub const DUMP_LEN: usize = 64 * 1024;

#[used]
#[no_mangle]
pub static mut TRNG_DUMP_BUF: [u8; DUMP_LEN] = [0; DUMP_LEN];
/// Number of buffers completed. The host waits for it to change.
#[used]
#[no_mangle]
pub static TRNG_DUMP_SEQ: AtomicU32 = AtomicU32::new(0);
/// Written by the host: the SEQ it has finished reading.
#[used]
#[no_mangle]
pub static TRNG_DUMP_ACK: AtomicU32 = AtomicU32::new(0);
/// `fill` calls that returned `Err` (the buffer is then refilled, not served).
#[used]
#[no_mangle]
pub static TRNG_DUMP_ERRS: AtomicU32 = AtomicU32::new(0);

pub fn run_and_halt() -> ! {
    loop {
        // SAFETY: single-threaded boot context; the host only reads the
        // buffer while SEQ != ACK, i.e. while this loop is parked below.
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(TRNG_DUMP_BUF) };
        while crate::rng::fill(buf).is_err() {
            TRNG_DUMP_ERRS.fetch_add(1, Ordering::Relaxed);
        }
        let seq = TRNG_DUMP_SEQ.load(Ordering::Relaxed).wrapping_add(1);
        TRNG_DUMP_SEQ.store(seq, Ordering::Release);
        while TRNG_DUMP_ACK.load(Ordering::Acquire) != seq {
            core::hint::spin_loop();
        }
    }
}

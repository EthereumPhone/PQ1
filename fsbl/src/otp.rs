//! OTP rollback-floor read for the FSBL.
//!
//! Mirror of `secure/src/hw/otp.rs::rollback_floor` — FSBL only needs
//! the read path, not the bump path (bumping is done by the secure
//! firmware's `CMD_FW_COMMIT` handler). Same tally encoding: count of
//! zero bits across 32 × 32-bit OTP words = current floor.

use core::ptr::read_volatile;

const OTP_BASE: usize = 0x0BFA_0000;
const ROLLBACK_WORDS: usize = 32;

pub fn rollback_floor() -> u32 {
    let mut count: u32 = 0;
    let base = OTP_BASE as *const u32;
    for i in 0..ROLLBACK_WORDS {
        // SAFETY: OTP is memory-mapped; indices bounded by ROLLBACK_WORDS.
        let w = unsafe { read_volatile(base.add(i)) };
        count += w.count_zeros();
    }
    count
}

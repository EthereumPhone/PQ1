//! STM32U585 OTP (one-time-programmable) access.
//!
//! STM32U585's user OTP area sits at `0x0BFA_0000` and is 512 × 64-bit
//! words (4 KB). Programming granularity is the flash controller's
//! standard quad-word (128 bits, 4 × 32-bit). Once a bit is flipped
//! from 1 to 0 it cannot be reset — not by erase, not by RDP
//! regression, nothing. This is the ideal home for the firmware-update
//! rollback floor: even an attacker who physically downgrades the chip
//! to RDP-0 and re-flashes the firmware cannot reset the counter.
//!
//! ## Rollback counter encoding
//!
//! We reserve the first 128 bytes of OTP (32 × 32-bit words,
//! 0x0BFA_0000..0x0BFA_0080) as a unary "tally" counter. Each bit
//! represents one irreversible increment:
//!
//! - Initially, every bit is 1 (erased OTP reads 0xFF...FF).
//! - Each firmware-update commit clears the *next* bit from 1 to 0.
//!   Encoding order: LSB-first within a 32-bit word, word 0 first.
//!   So the progression is bit 0 of word 0 → bit 1 of word 0 → ... →
//!   bit 31 of word 0 → bit 0 of word 1 → ...
//! - The rollback floor is the total count of zero bits.
//! - Maximum floor: 32 words × 32 bits = 1024 commits. At one update
//!   per month that's ~85 years — well past any reasonable device
//!   lifetime. A pathological-update rate (one per day) exhausts it
//!   in 2.8 years, so we surface a "OTP budget low" warning when the
//!   floor crosses 900.
//!
//! ## Programming quirks
//!
//! - OTP uses the standard FLASH controller (`SECCR` on the secure
//!   alias), same as bank 1. There's no separate OTP controller.
//! - Writes are quad-word aligned. To clear a single bit we read the
//!   current QW content, compute new bits (AND the clear mask in —
//!   never OR), and program the whole QW. NOR flash's "1 → 0 only"
//!   constraint means un-changed bits stay 1, and the new bits go to
//!   0. **We must never try to set a 0 bit back to 1** — the flash
//!   controller would latch PROGERR.
//! - Programming an OTP QW with data identical to its current content
//!   is a no-op. We use that in `verify_and_bump` to idempotently
//!   recover from a reset that happens mid-commit.
//!
//! ## Failure modes
//!
//! - **Brown-out during OTP write**: leaves the QW in an unknown state
//!   (some bits may have flipped, others not). The next boot re-reads
//!   the partial state and computes a floor that may be off by a few
//!   bits. This is safe: the recomputed floor is always consistent
//!   with the zero-bits-in-OTP invariant, and the worst case is a
//!   rollback floor that's been bumped by fewer bits than intended —
//!   which is not a security regression, only a missed-opportunity to
//!   reject an older version.
//! - **PROGERR on write** (WRPERR, PROGERR, SIZERR, etc.): Reported
//!   to the caller; the staged manifest is discarded and the active
//!   slot stays unchanged.

use core::ptr::{read_volatile, write_volatile};

// STM32U585 user OTP base address (same on secure and non-secure
// aliases; OTP has no watermark).
pub const OTP_BASE: u32 = 0x0BFA_0000;

// Flash controller registers — shared with `hw::flash`, duplicated
// here to keep `otp.rs` self-contained. Keeping a single source of
// truth in flash.rs would require exporting these privates, which
// would widen the unsafe surface of the flash module unnecessarily.
const FLASH: u32 = 0x5002_2000;
const FLASH_SECKEYR: *mut u32 = (FLASH + 0x0C) as *mut u32;
const FLASH_SECSR: *mut u32 = (FLASH + 0x24) as *mut u32;
const FLASH_SECCR: *mut u32 = (FLASH + 0x2C) as *mut u32;

const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

const PG: u32 = 1 << 0;
const LOCK: u32 = 1 << 31;
const BSY: u32 = 1 << 16;
const ERR_MASK: u32 = 0xFA;

/// Number of 32-bit words reserved for the rollback counter.
pub const ROLLBACK_WORDS: u32 = 32;
/// Total bits = 32 words × 32 bits = 1024. This is the maximum
/// firmware version the OTP can enforce as a rollback floor.
pub const MAX_FW_VERSION: u32 = ROLLBACK_WORDS * 32;

/// Error types returned by OTP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The requested floor would exceed `MAX_FW_VERSION` — OTP is
    /// exhausted. Devices that reach this state can no longer accept
    /// updates; the companion should surface a clear "OTP end of life"
    /// message.
    OutOfBudget,
    /// The requested floor is less than or equal to the current floor
    /// — nothing to do. This is a programmer error; `verify_and_bump`
    /// normalizes to `Ok(())` for idempotency (no bits to clear).
    BelowCurrent,
    /// The flash controller flagged a programming error during the QW
    /// write. The OTP may be partially written; caller should read
    /// back and recompute the floor.
    ProgramError,
}

/// Read the current rollback floor (count of zero bits in the OTP
/// tally region). Pure read, no programming.
pub fn rollback_floor() -> u32 {
    let mut count: u32 = 0;
    let base = OTP_BASE as *const u32;
    for i in 0..ROLLBACK_WORDS {
        // SAFETY: OTP is memory-mapped and readable from secure world.
        // The word count is bounded by ROLLBACK_WORDS, fitting inside
        // the 128-byte reserved region.
        let w: u32 = unsafe { read_volatile(base.offset(i as isize)) };
        count += w.count_zeros();
    }
    count
}

/// Bump the OTP floor to at least `target`. Idempotent when the
/// current floor is already `>= target` (returns Ok immediately).
///
/// If `target > MAX_FW_VERSION` returns `OtpError::OutOfBudget`.
pub unsafe fn bump_to(target: u32) -> Result<(), OtpError> {
    if target > MAX_FW_VERSION {
        return Err(OtpError::OutOfBudget);
    }

    let current = rollback_floor();
    if current >= target {
        return Ok(());
    }

    let to_clear = target - current;

    // Walk bits in the encoding order (LSB-first within each word,
    // word 0 first) and find the next `to_clear` still-set bits.
    // Collect them into per-word clear masks. Each QW holds 4 words,
    // so we can touch up to 4 words per programming op.
    //
    // For simplicity, process one 32-bit word at a time via an
    // identity QW write (3 unchanged words + 1 updated word). This
    // covers any bump size up to 32 per call; if the target crosses
    // a 32-bit boundary we iterate.
    let mut remaining = to_clear;
    let mut word_idx = current / 32;
    while remaining > 0 && word_idx < ROLLBACK_WORDS {
        let base = OTP_BASE as *const u32;
        let cur_word: u32 = unsafe { read_volatile(base.offset(word_idx as isize)) };

        // Find still-set bits (LSB-first).
        let mut new_word = cur_word;
        let mut bumps_this_word = 0;
        while remaining > 0 && new_word != 0 {
            let bit = new_word.trailing_zeros();
            // bit is the first set bit (trailing_zeros counts zeros,
            // so `bit` points to the LOWEST 1). Clear it.
            new_word &= !(1u32 << bit);
            remaining -= 1;
            bumps_this_word += 1;
        }

        if bumps_this_word > 0 {
            // Program the QW that contains word_idx. The other 3
            // words in the QW stay at their current values (we read
            // them back and re-write them identically — OTP accepts
            // that because no bit is flipped up).
            let qw_base = OTP_BASE + (word_idx & !0x03) * 4;
            let in_qw = (word_idx & 0x03) as usize;

            let mut qw_bytes = [0u8; 16];
            for i in 0..4u32 {
                let w: u32 =
                    unsafe { read_volatile(base.offset(((word_idx & !0x03) + i) as isize)) };
                qw_bytes[i as usize * 4..i as usize * 4 + 4]
                    .copy_from_slice(&w.to_le_bytes());
            }
            qw_bytes[in_qw * 4..in_qw * 4 + 4].copy_from_slice(&new_word.to_le_bytes());

            unsafe { program_otp_qw(qw_base, &qw_bytes)? };
        }

        word_idx += 1;
    }

    // Sanity: recompute floor and confirm it reached the target.
    let after = rollback_floor();
    if after < target {
        return Err(OtpError::ProgramError);
    }
    Ok(())
}

/// Low-level OTP quad-word program. `addr` must be 16-byte aligned and
/// within the OTP region. The 16 bytes at `addr` must have been
/// AND-compatible with `data` (each bit in `data` must be 0 or match
/// the current bit — never upgrade 0 → 1).
unsafe fn program_otp_qw(addr: u32, data: &[u8; 16]) -> Result<(), OtpError> {
    debug_assert!(addr >= OTP_BASE);
    debug_assert!(addr + 16 <= OTP_BASE + ROLLBACK_WORDS * 4);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| unsafe {
        // Wait for controller idle.
        while read_volatile(FLASH_SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
        // Clear stale error flags.
        let sr = read_volatile(FLASH_SECSR);
        if sr & ERR_MASK != 0 {
            write_volatile(FLASH_SECSR, sr & ERR_MASK);
        }
        // Unlock SECCR.
        write_volatile(FLASH_SECKEYR, KEY1);
        write_volatile(FLASH_SECKEYR, KEY2);

        write_volatile(FLASH_SECCR, PG);

        let dst = addr as *mut u32;
        for i in 0..4 {
            let word = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            write_volatile(dst.add(i), word);
        }

        while read_volatile(FLASH_SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
        write_volatile(FLASH_SECCR, 0);

        let sr = read_volatile(FLASH_SECSR);
        // Re-lock.
        let cr = read_volatile(FLASH_SECCR);
        write_volatile(FLASH_SECCR, cr | LOCK);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if sr & ERR_MASK != 0 {
            write_volatile(FLASH_SECSR, sr & ERR_MASK);
            Err(OtpError::ProgramError)
        } else {
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure-math test for the bump-planning helper: walk bits LSB-first
    // across words. Doesn't touch hardware.
    #[test]
    fn lsb_first_walk_is_contiguous() {
        // Simulate: current word = 0xFFFF_FFFF (32 set bits). Clear 3
        // bits LSB-first → should yield 0xFFFF_FFF8.
        let mut w: u32 = 0xFFFF_FFFF;
        for _ in 0..3 {
            let bit = w.trailing_zeros();
            w &= !(1u32 << bit);
        }
        assert_eq!(w, 0xFFFF_FFF8);
    }

    #[test]
    fn max_fw_version() {
        assert_eq!(MAX_FW_VERSION, 1024);
    }
}

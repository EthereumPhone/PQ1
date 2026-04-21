//! STM32U585 OTP (one-time-programmable) access.
//!
//! STM32U585's user OTP area sits at `0x0BFA_0000` and is 512 × 64-bit
//! words (4 KB). Programming granularity is the flash controller's
//! standard quad-word (128 bits, 4 × 32-bit). Once a bit is flipped
//! from 1 to 0 it cannot be reset — not by erase, not by RDP
//! regression, nothing. This is the ideal home for per-device secrets
//! that must survive firmware updates and factory-reset.
//!
//! ## Region map
//!
//! | Offset       | Size  | Purpose                                  |
//! |--------------|-------|------------------------------------------|
//! | 0..128       | 128 B | Firmware-update rollback tally (32 words)|
//! | 128..160     | 32 B  | Device master key (two quad-words)       |
//! | 160..512     | 352 B | Reserved for future use                  |
//!
//! ## Rollback counter encoding
//!
//! First 128 bytes of OTP (32 × 32-bit words, `0x0BFA_0000..0x0BFA_0080`)
//! as a unary "tally" counter. Each bit represents one irreversible
//! increment:
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
//! ## Device master key
//!
//! Bytes 128..160 of OTP (`0x0BFA_0080..0x0BFA_00A0`) hold a 32-byte
//! per-device master secret, filled with STM32 TRNG output on first
//! secure-world boot and never modified again. See `hw/secret_keys.rs`
//! for the HKDF wrappers that derive per-purpose subkeys from it
//! (OPTIGA PBS, SE050 SCP03, TROPIC01 pairing). The master key is
//! the root of trust for every on-device SE pairing; because it lives
//! in OTP it survives firmware updates, which is what keeps the
//! OPTIGA Shielded Connection alive through a reflash — see
//! `docs/optiga-brick-postmortem.md` for the history.
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
//!   reject an older version. For the master key, a brown-out mid-
//!   burn can leave a partially-programmed region that fails readback
//!   verification; `ensure_device_master` will refuse to proceed and
//!   the device bricks safely (OTP is one-way, so there is no "retry"
//!   path — ship-worthy boards must complete the first-boot burn).
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

/// Byte offset of the device master key within OTP (immediately after
/// the rollback tally).
pub const MASTER_KEY_OFFSET: u32 = ROLLBACK_WORDS * 4;
/// Size of the device master key in bytes.
pub const MASTER_KEY_SIZE: usize = 32;
/// Absolute address of the device master key.
const MASTER_KEY_ADDR: u32 = OTP_BASE + MASTER_KEY_OFFSET;
/// Upper bound for `program_otp_qw` bounds checks — one past the last
/// currently-used OTP byte.
const OTP_RESERVED_BYTES: u32 = MASTER_KEY_OFFSET + MASTER_KEY_SIZE as u32;

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
    /// The device master key region is still blank. Caller must run
    /// `burn_device_master` (or `ensure_device_master`) before expecting
    /// a valid master to read back.
    NotBurned,
    /// `burn_device_master` was called against a region that already
    /// contains non-blank bits. OTP is one-way; partial re-write would
    /// yield garbage.
    AlreadyBurned,
    /// Readback after a fresh burn did not match the bytes we wrote.
    /// Usually caused by a brown-out mid-program or a flash-controller
    /// error that didn't latch PROGERR. Device is effectively bricked —
    /// OTP cannot be re-written.
    ReadbackMismatch,
    /// Failed to obtain TRNG bytes from `crate::rng::fill`.
    RngFailed,
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
/// within the reserved OTP region (rollback tally + master key). The 16
/// bytes at `addr` must have been AND-compatible with `data` (each bit in
/// `data` must be 0 or match the current bit — never upgrade 0 → 1).
unsafe fn program_otp_qw(addr: u32, data: &[u8; 16]) -> Result<(), OtpError> {
    debug_assert!(addr >= OTP_BASE);
    debug_assert!(addr + 16 <= OTP_BASE + OTP_RESERVED_BYTES);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| unsafe {
        // Wait for controller idle.
        while read_volatile(FLASH_SECSR) & BSY != 0 {
            cortex_m::asm::nop();
        }
        // Clear stale error flags.
        let sr_pre = read_volatile(FLASH_SECSR);
        if sr_pre & ERR_MASK != 0 {
            write_volatile(FLASH_SECSR, sr_pre & ERR_MASK);
        }
        let cr_pre = read_volatile(FLASH_SECCR);
        // Unlock SECCR.
        write_volatile(FLASH_SECKEYR, KEY1);
        write_volatile(FLASH_SECKEYR, KEY2);
        let cr_after_unlock = read_volatile(FLASH_SECCR);

        write_volatile(FLASH_SECCR, PG);
        let cr_after_pg = read_volatile(FLASH_SECCR);

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
            secure_log!(
                "[OTP/prog] FAIL addr=0x{:08x} SR_pre=0x{:08x} CR_pre=0x{:08x} CR_after_unlock=0x{:08x} CR_after_pg=0x{:08x} SR_final=0x{:08x}",
                addr, sr_pre, cr_pre, cr_after_unlock, cr_after_pg, sr
            );
            write_volatile(FLASH_SECSR, sr & ERR_MASK);
            Err(OtpError::ProgramError)
        } else {
            secure_log!(
                "[OTP/prog] OK   addr=0x{:08x} SR_pre=0x{:08x} CR_pre=0x{:08x} CR_after_unlock=0x{:08x} CR_after_pg=0x{:08x} SR_final=0x{:08x}",
                addr, sr_pre, cr_pre, cr_after_unlock, cr_after_pg, sr
            );
            Ok(())
        }
    })
}

// ---------------------------------------------------------------------------
// Device master key
// ---------------------------------------------------------------------------
//
// The master key is the root input for every SE pairing secret this device
// uses — OPTIGA PBS, SE050 SCP03 ENC/MAC, TROPIC01 pairing. It is generated
// once from the STM32 TRNG on the first secure-world boot of a blank MCU
// and lives in OTP bytes 128..160 from that moment on. Callers in
// `hw/secret_keys.rs` run HKDF-style derivations over it with distinct
// domain labels to produce per-purpose subkeys.
//
// Under the `otp-hardcoded-master-key` Cargo feature the API is stubbed
// with a deliberately distinctive 32-byte ASCII pattern — it lets us
// exercise the derivation path on dev hardware without consuming OTP.
// The feature is OFF by default and guarded at `main.rs` against
// production builds.

/// 32-byte deliberately-distinctive test pattern used when the
/// `otp-hardcoded-master-key` Cargo feature is on. Plain ASCII so a
/// logic-analyzer snoop of the pairing secret (which is HKDF of this)
/// has no chance of being mistaken for real key material. The trailing
/// `!` fills the 32-byte slot exactly.
#[cfg(feature = "otp-hardcoded-master-key")]
const TEST_HARDCODED_MASTER_KEY: [u8; MASTER_KEY_SIZE] =
    *b"PQSIGNER-TEST-OTP-MASTER-DNS-v1!";

/// Returns true if any bit in the master-key region has been cleared
/// (i.e. the region has been burned). Blank OTP reads all-`0xFF` per
/// silicon; a successfully-burned key is statistically certain to have
/// many zero bits, so "any byte != 0xFF" is a sufficient sentinel.
///
/// Under `otp-hardcoded-master-key` always returns true — the test key
/// is considered "burned" so callers skip the first-boot provisioning
/// path.
pub fn is_device_master_burned() -> bool {
    #[cfg(feature = "otp-hardcoded-master-key")]
    {
        true
    }
    #[cfg(not(feature = "otp-hardcoded-master-key"))]
    {
        let base = MASTER_KEY_ADDR as *const u8;
        for i in 0..MASTER_KEY_SIZE {
            // SAFETY: OTP is memory-mapped and readable from secure world;
            // the loop is bounded by MASTER_KEY_SIZE = 32 bytes, all of
            // which fall inside the reserved master-key region.
            let b = unsafe { read_volatile(base.add(i)) };
            if b != 0xFF {
                return true;
            }
        }
        false
    }
}

/// Read the 32-byte device master key out of OTP.
///
/// Returns `OtpError::NotBurned` if the region is still blank — callers
/// should run `ensure_device_master` (the idempotent burn-if-needed
/// wrapper) rather than calling `read_device_master` directly.
///
/// Under `otp-hardcoded-master-key` returns the fixed test pattern.
pub fn read_device_master() -> Result<[u8; MASTER_KEY_SIZE], OtpError> {
    #[cfg(feature = "otp-hardcoded-master-key")]
    {
        Ok(TEST_HARDCODED_MASTER_KEY)
    }
    #[cfg(not(feature = "otp-hardcoded-master-key"))]
    {
        if !is_device_master_burned() {
            return Err(OtpError::NotBurned);
        }
        let base = MASTER_KEY_ADDR as *const u8;
        let mut out = [0u8; MASTER_KEY_SIZE];
        for i in 0..MASTER_KEY_SIZE {
            // SAFETY: same as is_device_master_burned — bounded read
            // inside the reserved master-key region.
            out[i] = unsafe { read_volatile(base.add(i)) };
        }
        Ok(out)
    }
}

/// Generate 32 TRNG bytes and program them into the master-key region.
///
/// Refuses to proceed (`AlreadyBurned`) if any bit in the region has
/// already been cleared — OTP is one-way, so partially rewriting the
/// region would produce garbage. The region must be pristine.
///
/// Readback-verifies the burned bytes match what was programmed; on
/// mismatch returns `ReadbackMismatch` (device effectively bricked —
/// see module docs). The key buffer is zeroized on every exit path.
///
/// Under `otp-hardcoded-master-key` this is a no-op that returns
/// `Ok(())` without touching flash — the test constant serves as the
/// "already burned" content.
///
/// # Safety
/// Invokes the STM32 flash programming sequence; other flash operations
/// must not be in flight on this core when this is called. The callers
/// `ensure_device_master` (and the first-boot wiring in `main.rs`)
/// uphold that contract by running single-threaded before SE init.
pub unsafe fn burn_device_master() -> Result<(), OtpError> {
    #[cfg(feature = "otp-hardcoded-master-key")]
    {
        Ok(())
    }
    #[cfg(not(feature = "otp-hardcoded-master-key"))]
    {
        use zeroize::Zeroize;

        if is_device_master_burned() {
            return Err(OtpError::AlreadyBurned);
        }

        let mut key = [0u8; MASTER_KEY_SIZE];
        if crate::rng::fill(&mut key).is_err() {
            key.zeroize();
            return Err(OtpError::RngFailed);
        }

        // Two quad-words: bytes 0..16 and 16..32.
        let mut qw0 = [0u8; 16];
        let mut qw1 = [0u8; 16];
        qw0.copy_from_slice(&key[..16]);
        qw1.copy_from_slice(&key[16..]);

        // SAFETY: addresses are within the reserved master-key region
        // and 16-byte aligned by construction (MASTER_KEY_ADDR is
        // 32-byte aligned; MASTER_KEY_ADDR + 16 inherits alignment).
        let r0 = unsafe { program_otp_qw(MASTER_KEY_ADDR, &qw0) };
        let r1 = unsafe { program_otp_qw(MASTER_KEY_ADDR + 16, &qw1) };
        qw0.zeroize();
        qw1.zeroize();

        if let Err(e) = r0 {
            key.zeroize();
            return Err(e);
        }
        if let Err(e) = r1 {
            key.zeroize();
            return Err(e);
        }

        // Readback verification — catches brown-out mid-program and any
        // flash-controller error that failed to latch PROGERR.
        let readback = match read_device_master() {
            Ok(b) => b,
            Err(e) => {
                key.zeroize();
                return Err(e);
            }
        };
        let ok = readback == key;
        key.zeroize();
        let mut readback_z = readback;
        readback_z.zeroize();

        if ok { Ok(()) } else { Err(OtpError::ReadbackMismatch) }
    }
}

/// Idempotent: if the master-key region is blank, run `burn_device_
/// master`; then read and return the key.
///
/// Safe to call on every boot — the first-boot-of-a-blank-MCU call
/// does the one-time burn, every subsequent call is a pure read.
/// Higher-level code (`secret_keys::*`) is expected to invoke this
/// rather than the split `burn`/`read` pair.
///
/// # Safety
/// May program OTP on the first call (when unburned). Same flash-
/// controller exclusivity contract as `burn_device_master`.
pub unsafe fn ensure_device_master() -> Result<[u8; MASTER_KEY_SIZE], OtpError> {
    if !is_device_master_burned() {
        // SAFETY: forwarded from our own `unsafe` contract.
        unsafe { burn_device_master()? };
    }
    read_device_master()
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

    #[test]
    fn master_key_layout() {
        assert_eq!(MASTER_KEY_OFFSET, 128);
        assert_eq!(MASTER_KEY_SIZE, 32);
        assert_eq!(MASTER_KEY_ADDR, OTP_BASE + 128);
        assert_eq!(OTP_RESERVED_BYTES, 160);
    }
}

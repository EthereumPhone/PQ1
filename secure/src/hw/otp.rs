//! STM32U585 OTP (one-time-programmable) access.
//!
//! STM32U585's user OTP area sits at `0x0BFA_0000` and is **512 bytes**:
//! 32 independent 128-bit ECC quad-words. Programming granularity is one
//! complete quad-word. An OTP quad-word may be programmed only once; it is
//! not a reusable bank of individually programmable fuse bits.
//!
//! ## Production status — legacy implementation, blocked from shipping
//!
//! The rollback functions below predate the hardware re-review and model the
//! first 128 bytes as a 1,024-bit unary tally. That model is invalid on
//! STM32U585: after the first program of a quad-word, a later bit-clear or
//! full-zero program raises `PROGERR`. The factory sentinel's proposed
//! rehearsal-then-production update has the same defect. The secure build
//! script and `nsc/mod.rs` reject every production/factory image; other
//! STM32U585 bench images require the explicit
//! `legacy-fw-rollback-unsafe` marker until this module is replaced by the
//! Draft-1.1 typed journal/ECC/OTP research candidate after exact-digest
//! approval and physical-gate closure.
//!
//! This warning does not approve the remaining one-shot secret provisioning
//! paths. Their exact factory map, interruption handling, and final protection
//! still require the corresponding production receipts.
//!
//! ## Region map
//!
//! | Offset       | Size  | Purpose                                  |
//! |--------------|-------|------------------------------------------|
//! | 0..128       | 128 B | Legacy rollback tally (**unsupported**)  |
//! | 128..160     | 32 B  | Device master key (two quad-words)       |
//! | 160..176     | 16 B  | Legacy factory sentinel (**unsupported**) |
//! | 176..512     | 336 B | Unallocated                              |
//!
//! ## Rollback counter encoding
//!
//! `rollback_floor` and `bump_to` implement the rejected unary design and are
//! retained only so pre-production images and tests remain diagnosable while
//! the replacement is developed. They are not a capacity claim. In the
//! reviewed architecture, ordinary releases do not consume OTP; a security-
//! epoch advance consumes complete, fresh quad-words according to the still-
//! open replicated record codec.
//!
//! ## Device master key
//!
//! Bytes 128..160 of OTP (`0x0BFA_0080..0x0BFA_00A0`) hold a 32-byte
//! per-device master secret, filled with STM32 TRNG output on first
//! secure-world boot and never modified again. See `hw/secret_keys.rs`
//! for the HKDF wrappers that derive per-purpose subkeys from it
//! (OPTIGA PBS, SE050 SCP03). The master key is
//! the root of trust for every on-device SE pairing; because it lives
//! in OTP it survives firmware updates, which is what keeps the
//! OPTIGA Shielded Connection alive through a reflash — see
//! `docs/secure-elements/optiga-brick-postmortem.md` for the history.
//!
//! ## Programming quirks
//!
//! - OTP uses the standard FLASH controller (`SECCR` on the secure
//!   alias), same as bank 1. There's no separate OTP controller.
//! - Writes are 16-byte aligned and program all 128 data bits plus hardware
//!   ECC as one operation.
//! - A target quad-word must be virgin. Reprogramming a partially programmed
//!   OTP quad-word—including an additional bit-clear or full-zero write—raises
//!   `PROGERR`; writing identical content is not an idempotent retry.
//!
//! ## Failure modes
//!
//! - **Brown-out during OTP write**: contents are not guaranteed and the
//!   quad-word is lost; it must not be retried or interpreted as a bit count.
//!   Exact-looking/ECC-corrected outcomes and cross-power-loss intent remain
//!   explicit open gates in the Draft-1.1 research candidate.
//! - **PROGERR on write** (WRPERR, PROGERR, SIZERR, etc.): Reported
//!   to the caller. No production path may infer that the target is reusable.

use crate::hw::mmio::{Reg32, RoReg32};

// STM32U585 user OTP base address (same on secure and non-secure
// aliases; OTP has no watermark).
pub const OTP_BASE: u32 = 0x0BFA_0000;

// Flash controller registers — shared with `hw::flash`, duplicated
// here to keep `otp.rs` self-contained. Keeping a single source of
// truth in flash.rs would require exporting these privates, which
// would widen the unsafe surface of the flash module unnecessarily.
const FLASH: u32 = 0x5002_2000;
const FLASH_SECKEYR_ADDR: u32 = FLASH + 0x0C;
const FLASH_SECSR_ADDR: u32 = FLASH + 0x24;
const FLASH_SECCR_ADDR: u32 = FLASH + 0x2C;

/// Flash-controller registers funnelled through typed MMIO handles.
struct FlashRegs {
    seckeyr: Reg32,
    secsr: Reg32,
    seccr: Reg32,
}

// SAFETY: each address is a real, 4-byte-aligned MMIO register in the
// flash controller's secure alias. The secure world is single-threaded
// and non-preemptive; `program_otp_qw` further fences its FLASH access
// inside `cortex_m::interrupt::free`. We duplicate these handles here
// (rather than reusing `hw::flash`'s) so the OTP driver is independent.
const FLASH_REG: FlashRegs = unsafe {
    FlashRegs {
        seckeyr: Reg32::new(FLASH_SECKEYR_ADDR),
        secsr: Reg32::new(FLASH_SECSR_ADDR),
        seccr: Reg32::new(FLASH_SECCR_ADDR),
    }
};

/// Read-only handle pointing at OTP word 0. The OTP region is memory-
/// mapped and read with normal load instructions; we use `RoReg32::read_at`
/// for contiguous-bank reads of the rollback tally.
///
// SAFETY: OTP_BASE is the 4-byte-aligned start of the OTP region, readable
// from the secure world. Reads are pure loads with no side effects.
const OTP_W0: RoReg32 = unsafe { RoReg32::new(OTP_BASE) };

const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;

const PG: u32 = 1 << 0;
const LOCK: u32 = 1 << 31;
const BSY: u32 = 1 << 16;
const ERR_MASK: u32 = 0xFA;

/// Number of 32-bit words reserved for the rollback counter.
pub const ROLLBACK_WORDS: u32 = 32;
/// Legacy unary model's logical bit count. This is **not** usable STM32U585
/// update capacity; the production fence forbids this codec from shipping.
pub const MAX_FW_VERSION: u32 = ROLLBACK_WORDS * 32;

/// Byte offset of the device master key within OTP (immediately after
/// the rollback tally).
pub const MASTER_KEY_OFFSET: u32 = ROLLBACK_WORDS * 4;
/// Size of the device master key in bytes.
pub const MASTER_KEY_SIZE: usize = 32;
/// Absolute address of the device master key.
const MASTER_KEY_ADDR: u32 = OTP_BASE + MASTER_KEY_OFFSET;
// Master-region geometry + the pure Virgin/Partial/Complete rule live in
// `crate::otp_state` so they are host-testable without MMIO. Re-exported here
// because `hw::otp` is the public face of the OTP surface.
pub use crate::otp_state::{MasterKeyState, classify_master_words};
use crate::otp_state::{MASTER_KEY_QWS, MASTER_KEY_WORDS, QW_BYTES, WORDS_PER_QW};

/// Byte offset of the factory-ceremony sentinel within OTP. Lives
/// directly after the device master key (offset 160..176, one
/// 128-bit quad-word). This is a quarantined legacy receipt: the host may
/// report it read-only, but no value authorizes an irreversible operation.
///
/// Encoding: 32-bit word at byte offset 0 of the QW.
///
///   bit 0: factory ceremony ran at least once
///   bit 1: rehearsal mode completed
///   bit 2: legacy production-completion bit (quarantined; no RDP2 authority)
///   bits 3..31: reserved (must remain 1)
///
/// The table below documents the legacy intended encoding, not supported
/// transition semantics. Only one virgin-to-programmed transition is valid for
/// this QW. In particular, rehearsal followed by production would require a
/// forbidden second QW program and must not be used as a factory workflow.
/// The legacy host fixture interprets:
///
/// | Raw value     | Meaning                                | RDP2 authority? |
/// |---------------|----------------------------------------|-----------------|
/// | `0xFFFFFFFF`  | never ran                              | NO        |
/// | `0xFFFFFFFE`  | ran but didn't complete (interrupted)  | NO        |
/// | `0xFFFFFFFC`  | rehearsal only                         | NO        |
/// | `0xFFFFFFFA`  | legacy production bits                 | NO        |
/// | `0xFFFFFFF8`  | legacy combined bits                   | NO        |
///
/// No value in this table is production authority while the ship fence is
/// active. The replacement factory receipt must use a one-shot or otherwise
/// hardware-valid encoding.
pub const FACTORY_SENTINEL_OFFSET: u32 = MASTER_KEY_OFFSET + MASTER_KEY_SIZE as u32;
/// Absolute address of the factory sentinel's 32-bit value.
pub const FACTORY_SENTINEL_ADDR: u32 = OTP_BASE + FACTORY_SENTINEL_OFFSET;
/// Size of the factory sentinel QW (16 B reserved; only the first 4
/// are meaningful today).
pub const FACTORY_SENTINEL_SIZE: u32 = 16;

/// Bit masks for the factory sentinel.
pub const FACTORY_SENTINEL_BIT_RAN: u32 = 1 << 0;
pub const FACTORY_SENTINEL_BIT_REHEARSAL: u32 = 1 << 1;
pub const FACTORY_SENTINEL_BIT_PRODUCTION: u32 = 1 << 2;

/// Upper bound for `program_otp_qw` bounds checks — one past the last
/// currently-used OTP byte.
const OTP_RESERVED_BYTES: u32 =
    FACTORY_SENTINEL_OFFSET + FACTORY_SENTINEL_SIZE;

/// Read-only handle at the master-key region word 0.
///
// SAFETY: 4-byte aligned (OTP_BASE is 4 KB aligned, MASTER_KEY_OFFSET is
// 128). Readable from secure world; reads are pure loads.
const MASTER_KEY_W0: RoReg32 = unsafe { RoReg32::new(MASTER_KEY_ADDR) };

/// Error types returned by OTP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// The rejected legacy tally's logical limit was exceeded. This is not a
    /// valid estimate of physical OTP capacity.
    OutOfBudget,
    /// The requested floor is less than or equal to the current floor
    /// — nothing to do under the legacy model. It is not permission to
    /// reprogram a physical QW idempotently.
    BelowCurrent,
    /// The flash controller flagged a programming error during the QW
    /// write. The OTP may be partially written; a production design must mark
    /// the QW consumed/ambiguous and must not retry or recompute a bit tally.
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
    /// The master-key region is programmed in ONE quad-word but not the other
    /// — a burn was interrupted between its two quad-word programs (D4).
    /// `read_device_master` refuses this state: handing back
    /// `[QW0 ‖ 0xFF×16]` would root every derived credential in a 128-bit
    /// master. `burn_device_master` completes the still-virgin quad-word.
    MasterKeyPartial,
    /// Two independent classifications of the master region disagreed, i.e.
    /// the region does not read stably (glitch, or an ECC-poisoned quad-word
    /// from an interrupted program). Fail closed: never act on an unstable
    /// read when the consequence is an irreversible write or a key
    /// derivation.
    MasterKeyUnstable,
    /// The page-127 journal says the first-boot rotation COMPLETED, but the
    /// persisted salt could not be recovered — so the salted-final OPTIGA PBS
    /// that E140 was paired with cannot be reconstructed.
    ///
    /// There is deliberately no fallback. The unsalted pre-rotation secret is
    /// a different value; handing it to the PRL handshake fails against a
    /// rotated chip, and writing it back would overwrite the pairing. Fail
    /// closed and surface the damage instead.
    FinalPbsSaltMissing,
}

/// Read the current rollback floor (count of zero bits in the OTP
/// tally region). Pure read, no programming.
///
/// F15 hardening: the floor feeds the FW-update `verify_rollback` verdict; a
/// single faulted word-read that under-counts zero bits would LOWER the floor
/// and admit a validly-signed *downgrade*. Sentinel-hardening `verify_rollback`
/// alone cannot catch this (both evaluations consume the same faulted floor),
/// so the read itself is voted: take `max(a, b)` of two independent passes.
/// `max` is the conservative vote for a monotonic floor on the ADMISSION path —
/// a single under-count is overridden by the correct pass (defeating the
/// downgrade), an over-count only rejects more (fail-closed). Two clean reads
/// agree, so the common path is unchanged.
///
/// **This vote is ONLY correct for the verify/admission path.** `bump_to` does
/// NOT use it: for an irreversible OTP write the `max(a,b)` over-bias is wrong
/// (a glitched-high read would skip a needed bump; a glitched-low read would
/// overshoot and brick), so `bump_to` reads `rollback_floor_once` twice and
/// fails closed on disagreement — see its body.
pub fn rollback_floor() -> u32 {
    let a = rollback_floor_once();
    let b = rollback_floor_once();
    a.max(b)
}

fn rollback_floor_once() -> u32 {
    let mut count: u32 = 0;
    for i in 0..ROLLBACK_WORDS {
        // SAFETY: `i < ROLLBACK_WORDS = 32`, so `OTP_W0 + i words` stays
        // inside the 128-byte rollback-tally region — the same contiguous
        // OTP bank `OTP_W0` was constructed for.
        let w: u32 = unsafe { OTP_W0.read_at(i as usize) };
        count += w.count_zeros();
    }
    count
}

/// Rejected legacy helper that tries to bump a unary floor to `target`.
///
/// Only the `current >= target` early return is a software no-op. Any path
/// that launches a QW write is not idempotent and is not a valid STM32U585
/// production operation after that QW's first program. Shipping builds are
/// compile-blocked while this diagnostic implementation remains.
///
/// If `target > MAX_FW_VERSION` returns `OtpError::OutOfBudget`.
pub unsafe fn bump_to(target: u32) -> Result<(), OtpError> {
    if target > MAX_FW_VERSION {
        return Err(OtpError::OutOfBudget);
    }

    // F15: `bump_to` needs the TRUE current floor — both for this idempotency
    // skip AND for the bit-walk start below. It must NOT reuse the verify-path
    // `rollback_floor()` (which votes `max(a,b)` so a glitched-LOW read can't
    // admit a downgrade): that conservative-HIGH vote is exactly WRONG here.
    //   * A glitched-HIGH `current` would falsely satisfy `current >= target`
    //     and SKIP a needed bump — and this early return runs BEFORE the
    //     post-write readback, so nothing would catch it (the same FI-asymmetry
    //     F15 closes elsewhere).
    //   * A glitched-LOW `current` would over-size `to_clear` and OVERSHOOT the
    //     floor past `target`, risking a brick (verify_rollback then rejects the
    //     just-installed version).
    // An irreversible OTP write must therefore FAIL CLOSED on a read glitch, not
    // act on a voted estimate: read twice (raw) and require agreement; on
    // disagreement abort (the COMMIT caller retries on a clean read).
    let c1 = rollback_floor_once();
    crate::fi::wait_random();
    let c2 = rollback_floor_once();
    if c1 != c2 {
        return Err(OtpError::ProgramError);
    }
    let current = c1;
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
        // SAFETY: `word_idx < ROLLBACK_WORDS = 32` — inside the tally bank.
        let cur_word: u32 = unsafe { OTP_W0.read_at(word_idx as usize) };

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
            // Legacy-invalid operation: program the QW that contains
            // word_idx while copying the other words unchanged. STM32U585
            // OTP does NOT accept this as an identity rewrite once the QW has
            // been programmed; it raises PROGERR. Retained only so the old
            // path remains diagnosable behind the nonshipping compile fence.
            let qw_base = OTP_BASE + (word_idx & !0x03) * 4;
            let in_qw = (word_idx & 0x03) as usize;

            let mut qw_bytes = [0u8; 16];
            for i in 0..4u32 {
                let wi = (word_idx & !0x03) + i;
                // SAFETY: `wi < ROLLBACK_WORDS = 32` (word_idx itself is
                // bounded by the loop guard above, and we mask its low
                // bits before adding `i ∈ 0..4`). All four reads remain
                // inside the tally bank `OTP_W0` was constructed for.
                let w: u32 = unsafe { OTP_W0.read_at(wi as usize) };
                qw_bytes[i as usize * 4..i as usize * 4 + 4]
                    .copy_from_slice(&w.to_le_bytes());
            }
            qw_bytes[in_qw * 4..in_qw * 4 + 4].copy_from_slice(&new_word.to_le_bytes());

            // SAFETY: `program_otp_qw` is `unsafe` to keep one-way OTP
            // commits visible at every call site — see fn docs.
            unsafe { program_otp_qw(qw_base, &qw_bytes)? };
        }

        word_idx += 1;
    }

    // Sanity: recompute floor and confirm it reached the target. The
    // double-read + `fi::check_true` gate raises the cost of a glitch
    // that silently skipped the inner `program_otp_qw` calls: the
    // readback would then return `< target`, the open-coded `if` is
    // glitchable, but the hamming-distant sentinel in `fi::check_true`
    // requires multiple cooperating faults to bypass.
    // F15: the readback uses RAW single reads (`rollback_floor_once`), NOT the
    // verify-path `rollback_floor()` max(a,b). "Did the floor REACH target?"
    // wants the conservative direction — two INDEPENDENT raw reads that must
    // BOTH be `>= target`, so a single glitched-HIGH read cannot false-pass the
    // "bump succeeded" check. (max(a,b) would over-report and weaken it.)
    let after1 = rollback_floor_once();
    crate::fi::wait_random();
    let after2 = rollback_floor_once();
    if crate::fi::check_true_into_sentinel(|| after1 >= target && after2 >= target) != crate::fi::OK_SENTINEL {
        return Err(OtpError::ProgramError);
    }
    Ok(())
}

/// Low-level OTP quad-word program. `addr` must be 16-byte aligned, within the
/// reserved OTP region, and point to a proven-virgin quad-word. AND-compatible
/// data is insufficient: STM32U585 OTP rejects every second program of a
/// partially programmed QW, even when only clearing more bits or writing zero.
///
/// # Safety
/// Commits one complete quad-word to OTP. There is no recovery or second
/// supported program operation (not even after RDP regression).
/// Every call site MUST have a `// SAFETY:` comment naming the irreversible
/// effect. Callers must also ensure no other flash op is in flight on this
/// core; the secure world is single-threaded, but DMA / pre-fetch must be
/// quiesced. We additionally fence with `cortex_m::interrupt::free`.
unsafe fn program_otp_qw(addr: u32, data: &[u8; 16]) -> Result<(), OtpError> {
    debug_assert!(addr >= OTP_BASE);
    debug_assert!(addr + 16 <= OTP_BASE + OTP_RESERVED_BYTES);
    debug_assert_eq!(addr & 0xF, 0);

    cortex_m::interrupt::free(|_| {
        // Wait for controller idle.
        while FLASH_REG.secsr.read() & BSY != 0 {
            cortex_m::asm::nop();
        }
        // Clear stale error flags.
        let sr_pre = FLASH_REG.secsr.read();
        if sr_pre & ERR_MASK != 0 {
            FLASH_REG.secsr.write(sr_pre & ERR_MASK);
        }
        let cr_pre = FLASH_REG.seccr.read();
        // Unlock SECCR.
        FLASH_REG.seckeyr.write(KEY1);
        FLASH_REG.seckeyr.write(KEY2);
        let cr_after_unlock = FLASH_REG.seccr.read();

        FLASH_REG.seccr.write(PG);
        let cr_after_pg = FLASH_REG.seccr.read();

        // Construct a single `Reg32` aimed at the QW base; step the four
        // word commits via `write_at`. The per-word `unsafe` markers below
        // preserve the OTP recipe's call-site-visibility property: every
        // irreversible bit flip is named.
        // SAFETY: `addr` is 16-byte aligned and inside the OTP reserved
        // region (asserted above); offsets `0..=3` stay inside the QW.
        let qw = unsafe { Reg32::new(addr) };
        for i in 0..4 {
            let word = u32::from_le_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ]);
            // SAFETY: offset `i ∈ 0..4` stays inside the 4-word QW the
            // handle above was constructed for. This write irreversibly
            // commits bits to silicon — the OTP one-way property.
            unsafe { qw.write_at(i, word) };
        }

        while FLASH_REG.secsr.read() & BSY != 0 {
            cortex_m::asm::nop();
        }
        FLASH_REG.seccr.write(0);

        let sr = FLASH_REG.secsr.read();
        // Re-lock.
        FLASH_REG.seccr.set_bits(LOCK);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        if sr & ERR_MASK != 0 {
            secure_log!(
                "[OTP/prog] FAIL addr=0x{:08x} SR_pre=0x{:08x} CR_pre=0x{:08x} CR_after_unlock=0x{:08x} CR_after_pg=0x{:08x} SR_final=0x{:08x}",
                addr, sr_pre, cr_pre, cr_after_unlock, cr_after_pg, sr
            );
            FLASH_REG.secsr.write(sr & ERR_MASK);
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
// uses — OPTIGA PBS, SE050 SCP03 ENC/MAC. It is generated
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
        // D4: `Complete` ONLY. The pre-2026-07-17 test was "any word !=
        // 0xFFFF_FFFF ⇒ burned", which reports an interrupted two-quad-word
        // burn as burned; `read_device_master` then handed out
        // `[QW0 ‖ 0xFF×16]` and every SE transport credential rooted in a
        // 128-bit master, silently and irreversibly. An unstable read yields
        // `Err` ⇒ `false` here, which is fail-closed at every call site:
        // `read_device_master` → `NotBurned`, `first_boot`'s precondition →
        // `OtpMasterNotBurned` (RMA screen), and `ensure_device_master` →
        // re-enters `burn_device_master`, which re-classifies and refuses.
        matches!(master_key_state(), Ok(MasterKeyState::Complete))
    }
}

/// Snapshot the eight master-region words with volatile reads.
///
/// This is the only MMIO in the classification path; the *rule* it feeds
/// (`crate::otp_state::classify_master_words`) is pure and host-tested.
#[cfg(not(feature = "otp-hardcoded-master-key"))]
fn read_master_words() -> [u32; MASTER_KEY_WORDS] {
    let mut words = [0u32; MASTER_KEY_WORDS];
    for (i, slot) in words.iter_mut().enumerate() {
        // SAFETY: `i < MASTER_KEY_WORDS = 8` — inside the master-key bank
        // `MASTER_KEY_W0` was constructed for.
        *slot = unsafe { MASTER_KEY_W0.read_at(i) };
    }
    words
}

/// Is quad-word `qw` (0 or 1) of the master region programmed?
#[cfg(not(feature = "otp-hardcoded-master-key"))]
fn master_qw_programmed(qw: usize) -> bool {
    debug_assert!(qw < MASTER_KEY_QWS);
    crate::otp_state::qw_programmed(&read_master_words(), qw)
}

#[cfg(not(feature = "otp-hardcoded-master-key"))]
fn master_key_state_once() -> MasterKeyState {
    classify_master_words(&read_master_words())
}

/// Classify the master-key region per quad-word, fail-closed on an unstable
/// read.
///
/// Read twice with an FI delay between passes and require agreement. This
/// mirrors `bump_to`'s discipline and for the same reason: the verdict gates
/// an irreversible OTP write *and* a key derivation, so a glitched
/// classification must abort rather than be voted. Note the deliberate
/// asymmetry with `rollback_floor`, which votes `max(a, b)` — that
/// conservative-HIGH bias is correct for a monotonic admission check and
/// wrong here, where a glitched-`Complete` would skip a needed completion and
/// a glitched-`Virgin` would re-drive a programmed quad-word.
#[cfg(not(feature = "otp-hardcoded-master-key"))]
pub fn master_key_state() -> Result<MasterKeyState, OtpError> {
    let a = master_key_state_once();
    crate::fi::wait_random();
    let b = master_key_state_once();
    if a != b {
        return Err(OtpError::MasterKeyUnstable);
    }
    Ok(a)
}

/// Under `otp-hardcoded-master-key` the fixed test constant stands in for a
/// completed burn; no OTP word is ever read or programmed.
#[cfg(feature = "otp-hardcoded-master-key")]
pub fn master_key_state() -> Result<MasterKeyState, OtpError> {
    Ok(MasterKeyState::Complete)
}

/// Read the 32-byte device master key out of OTP.
///
/// Returns `NotBurned` if the region is still blank, `MasterKeyPartial` if an
/// interrupted burn left exactly one of its two quad-words programmed, and
/// `MasterKeyUnstable` if two classifications disagree. **Only a `Complete`
/// region yields bytes** — this is the barrier that makes D4 unreachable: a
/// caller can never obtain `[QW0 ‖ 0xFF×16]` and root a credential in a
/// 128-bit master.
///
/// Under `otp-hardcoded-master-key` returns the fixed test pattern.
pub fn read_device_master() -> Result<[u8; MASTER_KEY_SIZE], OtpError> {
    #[cfg(feature = "otp-hardcoded-master-key")]
    {
        Ok(TEST_HARDCODED_MASTER_KEY)
    }
    #[cfg(not(feature = "otp-hardcoded-master-key"))]
    {
        // D4: refuse anything that is not a completed burn. This is the
        // barrier that makes the whole defect unreachable — no caller can
        // obtain `[QW0 ‖ 0xFF×16]`, so no credential can ever root in a
        // half-blank master. `Partial` and `MasterKeyUnstable` are distinct
        // from `NotBurned` so the fault screen says which one it is.
        match master_key_state()? {
            MasterKeyState::Virgin => return Err(OtpError::NotBurned),
            MasterKeyState::Partial => return Err(OtpError::MasterKeyPartial),
            MasterKeyState::Complete => {}
        }
        let mut out = [0u8; MASTER_KEY_SIZE];
        for i in 0..MASTER_KEY_WORDS {
            // SAFETY: `i < MASTER_KEY_WORDS = 8` — inside the master-key
            // bank `MASTER_KEY_W0` was constructed for. Reading as 32-bit
            // words and reassembling little-endian preserves the original
            // byte order of the per-byte volatile reads.
            let w = unsafe { MASTER_KEY_W0.read_at(i) };
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
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
/// **D4 (fixed 2026-07-17): `Partial` is completed, not refused.** The master
/// spans two quad-words and takes two separate programs, so a reset between
/// them is reachable. Only `Complete` is `AlreadyBurned`; from `Partial` this
/// programs the still-virgin quad-word (its one legal program) and keeps the
/// committed quad-word's bytes as part of the master. That is safe because
/// `read_device_master` refuses any non-`Complete` region, so no caller can
/// ever have derived a credential from the partial value.
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

        // D4: classify per QUAD-WORD, and fail closed on an unstable read.
        // `Partial` is a legitimately reachable state (a reset between the two
        // programs below) and is COMPLETABLE — the virgin quad-word can still
        // take its one legal program. It is not `AlreadyBurned`.
        let state = master_key_state()?;
        if state == MasterKeyState::Complete {
            return Err(OtpError::AlreadyBurned);
        }

        let mut key = [0u8; MASTER_KEY_SIZE];
        // The device-master key is irreversibly burned to OTP — there
        // is no second chance to regenerate it if the source RNG was
        // biased / broken at burn time. Use `rng_strong::fill` so any
        // unbroken TRNG (STM32 / OPTIGA / SE050) contributes entropy
        // via XOR-fold. There is deliberately no platform-only fallback: if
        // both authenticated SE entropy channels are not already available,
        // this irreversible burn fails. The factory transport master is a
        // bootstrap root for those same channels, so the production factory
        // ceremony must resolve that ordering explicitly; this routine must
        // never hide it by silently burning platform-only entropy.
        if crate::rng_strong::fill(&mut key).is_err() {
            key.zeroize();
            return Err(OtpError::RngFailed);
        }

        // `key` is the INTENDED final master. A programmed quad-word is
        // immutable, so on the `Partial` path its committed bytes stay part of
        // the master and only the virgin quad-word takes fresh entropy: read
        // each programmed quad-word back over its slot in `key`. On the
        // `Virgin` path nothing is overwritten and `key` is wholly fresh.
        // Either way `key` is what the readback below must equal.
        let words = read_master_words();
        let mut virgin = [false; MASTER_KEY_QWS];
        for (qw, slot) in virgin.iter_mut().enumerate() {
            if crate::otp_state::qw_programmed(&words, qw) {
                for w in 0..WORDS_PER_QW {
                    let i = qw * WORDS_PER_QW + w;
                    key[i * 4..i * 4 + 4].copy_from_slice(&words[i].to_le_bytes());
                }
            } else {
                *slot = true;
            }
        }

        // Program ONLY the virgin quad-words, and abort on the first error
        // rather than compounding it. (Pre-2026-07-17 this ran both programs
        // unconditionally and inspected neither result until afterwards, so a
        // failed QW0 was still followed by a QW1 program — turning a
        // recoverable `Partial` into a `Complete`-looking region with an
        // ambiguous QW0. A quad-word whose program errored is consumed and
        // must not be re-driven; see the module header.)
        for (qw, _) in virgin.iter().enumerate().filter(|(_, v)| **v) {
            let mut buf = [0u8; QW_BYTES];
            buf.copy_from_slice(&key[qw * QW_BYTES..(qw + 1) * QW_BYTES]);
            // SAFETY: addresses are within the reserved master-key region and
            // 16-byte aligned by construction (MASTER_KEY_ADDR is 32-byte
            // aligned; +16 inherits alignment). `qw < MASTER_KEY_QWS = 2`.
            let r = unsafe { program_otp_qw(MASTER_KEY_ADDR + (qw * QW_BYTES) as u32, &buf) };
            buf.zeroize();
            if let Err(e) = r {
                key.zeroize();
                return Err(e);
            }
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

/// If the master-key region is not a completed burn, run `burn_device_master`;
/// then read and return the key. After a successful verified burn, later calls
/// are pure reads.
///
/// **D4 (fixed 2026-07-17).** This IS now crash-retry-safe across the burn's
/// two quad-word programs. The three states compose:
///
/// - `Virgin`  → `burn_device_master` programs both quad-words → `Complete` → read.
/// - `Partial` → `burn_device_master` completes the virgin quad-word → `Complete` → read.
/// - `Complete`→ skip the burn → read.
///
/// and every failure path lands on `read_device_master`, which refuses anything
/// that is not `Complete`. Previously `is_device_master_burned` was true for a
/// `Partial` region, so this skipped the burn and returned `[QW0 ‖ 0xFF×16]` —
/// silently rooting every SE transport credential in a 128-bit master.
///
/// Safe to call on every boot only after factory evidence establishes that the
/// first burn completed and read back correctly. The production ceremony for
/// that evidence remains open.
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

// ---------------------------------------------------------------------------
// Factory ceremony sentinel — used by the production factory firmware
// to record one-way "ceremony ran" state for the host-side fixture to
// read before boxing a unit. (Historically this gated a fixture-side
// RDP2 bump; per work-todo #36 devices ship at RDP-0 and the FSBL
// self-locks to RDP-2 on the first field boot — no host RDP2
// authority exists.) See `secure/src/factory_provisioning.rs` for the
// state machine that writes this.
// ---------------------------------------------------------------------------

/// Read the factory sentinel's 32-bit value. `0xFFFFFFFF` on a fresh
/// (never-factory-run) chip; bits 0-2 are cleared by completion
/// events per the docstring on `FACTORY_SENTINEL_OFFSET`.
pub fn factory_sentinel_read() -> u32 {
    // SAFETY: FACTORY_SENTINEL_ADDR is 4-byte aligned (OTP_BASE is
    // 4 KB aligned, FACTORY_SENTINEL_OFFSET = 160 is 4-aligned) and
    // sits inside the OTP region (160..176). Readable from secure
    // world; pure load.
    unsafe { core::ptr::read_volatile(FACTORY_SENTINEL_ADDR as *const u32) }
}

/// Record the rejected legacy factory-sentinel value. This helper is retained
/// for pre-production diagnosis only. Calling it more than once for the QW is
/// unsupported on STM32U585 and will normally raise `PROGERR`; the early
/// equality return is a software no-op, not a hardware retry primitive.
///
/// `bits_to_clear` is `OR`'d into the cleared-bits set. Pass any
/// combination of `FACTORY_SENTINEL_BIT_*` constants. The production
/// ceremony passes `BIT_RAN | BIT_PRODUCTION`; the rehearsal
/// ceremony passes `BIT_RAN | BIT_REHEARSAL`.
///
/// # Safety
///
/// Commits one complete quad-word to OTP. A chip whose sentinel QW was written
/// by rehearsal cannot later update that same QW for production. The shipping
/// compile fence must remain until a hardware-valid factory receipt replaces
/// this helper.
///
/// Caller MUST coordinate exclusive access to the flash controller
/// (no other op in flight). The secure world is single-threaded; we
/// fence interrupts inside `program_otp_qw` to guard against any
/// pending IRQ shifting the controller state.
pub unsafe fn factory_sentinel_record(bits_to_clear: u32) -> Result<(), OtpError> {
    // Legacy target computation. This is valid only for the QW's first program;
    // a later AND-compatible write is still rejected by STM32U585 OTP.
    let current = factory_sentinel_read();
    let target = current & !bits_to_clear;
    if target == current {
        // Software no-op only; no hardware program command is issued.
        return Ok(());
    }

    // Pack the 32-bit target into a 128-bit QW with the upper 96
    // bits at 0xFF (untouched — they stay at their current OTP
    // values, which are also 0xFF on a fresh chip).
    let mut qw_bytes = [0xFFu8; 16];
    qw_bytes[0..4].copy_from_slice(&target.to_le_bytes());

    // SAFETY: FACTORY_SENTINEL_ADDR is 16-byte aligned (OTP_BASE is
    // 4 KB aligned, FACTORY_SENTINEL_OFFSET = 160 is 16-aligned) and
    // inside `OTP_RESERVED_BYTES = 176`. Caller's docstring covers
    // the irreversibility contract.
    unsafe { program_otp_qw(FACTORY_SENTINEL_ADDR, &qw_bytes) }
}

// Host tests for this module's layout live in
// `secure/src/hw_crypto_under_test/pure_tests.rs`, NOT here.
//
// #723: a `#[cfg(test)] mod tests` at this spot could never run. `mod hw;` is
// `#[cfg(not(test))]` in main.rs, so the whole `hw` tree is absent from every
// host test build — no feature flag reaches it. Four tests sat here reporting
// neither pass nor fail.
//
// Three were constant pins and are now asserted, with the absolute addresses
// and the three other copies of this geometry, by `positive_otp_*` and
// `negative_otp_geometry_agrees_across_all_four_copies` over there.
//
// The fourth, `lsb_first_walk_is_contiguous`, is deliberately NOT carried
// over. It reimplemented `bump_to`'s three-line clear loop locally and
// asserted on its own copy: it called nothing in this module, would have
// passed had this file been deleted, and was in substance a test of
// `u32::trailing_zeros`. `bump_to` is the rejected legacy unary tally, has no
// Rust call sites, and `cmd_fw_commit.rs` documents the writer's removal and
// refuses — extracting a helper out of fenced legacy code to serve a test
// would be churn on a path nobody may call.

//! Fault-injection-hardened state types for security-critical booleans.
//!
//! Pattern from Trezor's `FihInt` / `secbool` (referenced by RFC-9814
//! erratum work and the Masaryk-U STM32U5 voltage-glitch thesis):
//! a security-critical boolean is too brittle as a plain `bool` —
//! a single bit-flip in SRAM, a stuck-at fault on the load register,
//! or a compiler-elided branch can flip its value end-to-end.
//!
//! `FihBool` defends three classes of fault simultaneously:
//!
//!   1. **Storage glitch** — the value is held as a pair
//!      `(val, complement)` with the invariant `val ^ complement ==
//!      0xFFFFFFFF`. A single bit-flip in either word breaks the
//!      invariant; the reader detects it and fail-closes to `false`.
//!
//!   2. **Single bit-flip from FALSE to TRUE** — the chosen magic
//!      constants `SEC_TRUE = 0x1AAA_AAAA` and `SEC_FALSE =
//!      0x1555_5555` differ in 28 of 32 bit positions. No single
//!      bit-flip can turn one into the other.
//!
//!   3. **Stuck-at on the load register** — readers go through
//!      `core::ptr::read_volatile`, defeating compiler-CSE and forcing
//!      the load to materialise. The companion `is_true_fi()` reads
//!      the pair *twice* with a `wait_random()` between, and requires
//!      both passes to agree.
//!
//! What `FihBool` does **not** defend on its own:
//!
//!   - **Caller branch-skip** — `if !x.is_true_fi() { reject }` can be
//!     bypassed by skipping the `cbz`/branch. Callers at security
//!     gates should compose `FihBool` with the existing
//!     `fi::check_true_into_sentinel` pattern (returns a Hamming-
//!     distant sentinel; the caller compares the *value* rather than
//!     branching on the bool). See the `check_sentinel` helper below.

use core::ptr::{read_volatile, write_volatile};

/// True pattern. Hamming weight 15. Differs from `SEC_FALSE` by 28
/// bit positions — no single bit-flip can turn TRUE → FALSE.
const SEC_TRUE: u32 = 0x1AAA_AAAA;

/// False pattern. Hamming weight 15. Initial state of every
/// `FihBool` is FALSE.
const SEC_FALSE: u32 = 0x1555_5555;

/// FI-hardened boolean. Stored as a pair `(val, complement)`; the
/// reader checks both `val ^ complement == 0xFFFFFFFF` (storage
/// invariant) and `val ∈ {SEC_TRUE, SEC_FALSE}` (pattern invariant).
/// Anything else means a fault landed, and the reader fail-closes to
/// `false`.
#[repr(C)]
pub struct FihBool {
    val: u32,
    complement: u32,
}

impl FihBool {
    /// Const-construct a FALSE value, suitable for static-init.
    pub const fn new_false() -> Self {
        Self {
            val: SEC_FALSE,
            complement: !SEC_FALSE,
        }
    }

    /// Set to TRUE via volatile writes. Volatile prevents the compiler
    /// from reordering or eliding these writes around the surrounding
    /// flow (e.g. across a `zeroize` call that semantically follows).
    pub fn set_true(&mut self) {
        // SAFETY: `self` is a unique mutable borrow; the volatile
        // writes target two adjacent `u32` fields we own.
        unsafe {
            write_volatile(&mut self.val, SEC_TRUE);
            write_volatile(&mut self.complement, !SEC_TRUE);
        }
    }

    /// Set to FALSE via volatile writes.
    pub fn set_false(&mut self) {
        // SAFETY: same as `set_true`.
        unsafe {
            write_volatile(&mut self.val, SEC_FALSE);
            write_volatile(&mut self.complement, !SEC_FALSE);
        }
    }

    /// Read with tamper detection. Returns `true` iff *both* words
    /// read intact (storage invariant) AND `val == SEC_TRUE` (pattern
    /// invariant). Anything else means a fault landed; fail-closed to
    /// `false`.
    pub fn is_true(&self) -> bool {
        // SAFETY: `self` is a valid borrow; the volatile reads target
        // the two `u32` fields we own. Volatile is load-bearing — a
        // plain field access lets LLVM treat the pair as fungible
        // (e.g. CSE the load with a nearby write), defeating the
        // detection.
        unsafe {
            let v = read_volatile(&self.val);
            let c = read_volatile(&self.complement);
            if v ^ c != 0xFFFF_FFFF {
                return false;
            }
            v == SEC_TRUE
        }
    }

    /// Is this **exactly** the valid FALSE codeword pair?
    ///
    /// THE FAILURE DIRECTION IS THE POINT (#802). `is_true` fail-closes to
    /// `false`, which is right for every gate that asks "may I proceed?" —
    /// false means refuse. It is INVERTED for a consumer that asks "is there
    /// anything to wipe?", where `false` means "nothing to do" and the
    /// secrets stay resident. Under that reading a single bit flip in either
    /// word, or one skipped store in `set_true`, suppresses the idle wipe for
    /// the rest of the session: `master_secret`, `slot_master_entropy` and
    /// `SLOT_CACHE` stay in SRAM until a power cycle, and nothing reports it.
    /// All 64 single-bit mutations of a valid TRUE pair decode as `false`.
    ///
    /// So the wipe side asks the opposite question. Only the EXACT valid
    /// FALSE pair means "already locked, nothing to do". Armed, corrupted and
    /// torn all fall through to the wipe, which costs one redundant zeroize
    /// and a PIN re-prompt — the fail-SAFE direction. `zeroize_sensitive`
    /// rewrites the exact pair, so a corrupted word produces exactly one wipe
    /// and then settles.
    ///
    /// Deliberately NO `wait_random`: this is read once per SysTick, and for
    /// a fail-to-wipe reading a transient glitch buys an attacker at most one
    /// millisecond. The per-tick re-evaluation IS the defence — suppressing
    /// the wipe for a whole idle window means glitching every tick of it.
    /// Hardening it with a TRNG-jittered double read is what cost 25.7% of
    /// the CPU (#802); it bought nothing here.
    #[must_use]
    pub fn is_exactly_false(&self) -> bool {
        // SAFETY: `self` is a valid borrow; volatile reads of the two `u32`
        // fields we own. Volatile for the same reason as `is_true` — a plain
        // read lets LLVM fold the pair and defeat the detection.
        unsafe {
            let v = read_volatile(&self.val);
            let c = read_volatile(&self.complement);
            v == SEC_FALSE && c == !SEC_FALSE
        }
    }

    /// Same as `is_true` but reads the pair *twice* with a
    /// `wait_random()` between, requires both passes to agree.
    /// Defends a single-fault that lands inside one read's
    /// invariant-check. Use at high-value gates (every gateway
    /// command's "is the device unlocked" check).
    pub fn is_true_fi(&self) -> bool {
        let r1 = self.is_true();
        crate::fi::wait_random();
        let r2 = self.is_true();
        r1 && r2
    }

    /// Compose with `fi::check_true_into_sentinel`: returns
    /// `OK_SENTINEL` (Hamming-distant from `FAIL_SENTINEL`) iff the
    /// FihBool reads cleanly as `true`. The caller compares the
    /// returned *value* against `OK_SENTINEL` rather than branching
    /// on a bool — this defeats single-instruction-skip on the
    /// caller's `if`.
    ///
    /// Use at every gated command:
    ///
    /// ```ignore
    /// let v = peek_state(|s| s.pin_verified.check_sentinel());
    /// if v != crate::fi::OK_SENTINEL {
    ///     return NscStatus::NotInitialized as u32;
    /// }
    /// ```
    pub fn check_sentinel(&self) -> u32 {
        crate::fi::check_true_into_sentinel(|| self.is_true_fi())
    }
}

#[cfg(test)]
mod exactly_false_tests {
    use super::*;

    /// #802. The property the idle wipe depends on: ONLY the exact intact
    /// FALSE pair means "nothing to wipe". Every corruption must fall
    /// through to the wipe, which is the fail-SAFE direction.
    #[test]
    fn only_the_exact_false_codeword_reads_as_locked() {
        let locked = FihBool::new_false();
        assert!(locked.is_exactly_false(), "a clean FALSE must read as locked");

        let mut unlocked = FihBool::new_false();
        unlocked.set_true();
        assert!(!unlocked.is_exactly_false(), "TRUE must not read as locked");
    }

    /// The contrast that motivates the whole change: `is_true` fail-closes to
    /// `false`, so under corruption it says "not unlocked" — which the wipe
    /// consumer reads as "nothing to do". `is_exactly_false` says "not
    /// cleanly locked" for the same input, so the wipe fires.
    #[test]
    fn every_single_bit_corruption_of_true_wipes_rather_than_being_ignored() {
        for bit in 0..32 {
            for which in 0..2 {
                let mut b = FihBool::new_false();
                b.set_true();
                // SAFETY: test-only poke at our own fields, mirroring a
                // single-bit fault landing on one of the two words.
                unsafe {
                    if which == 0 {
                        let v = read_volatile(&b.val) ^ (1u32 << bit);
                        write_volatile(&mut b.val, v);
                    } else {
                        let c = read_volatile(&b.complement) ^ (1u32 << bit);
                        write_volatile(&mut b.complement, c);
                    }
                }
                // The old reading: corruption looks like "locked, nothing to
                // wipe" — secrets stay resident for the rest of the session.
                assert!(
                    !b.is_true(),
                    "bit {bit}/{which}: is_true must fail closed (this is the \
                     reading that made corruption SUPPRESS the idle wipe)"
                );
                // The new reading: corruption is not the exact locked
                // codeword, so the caller wipes.
                assert!(
                    !b.is_exactly_false(),
                    "bit {bit}/{which}: corrupted state must NOT read as \
                     cleanly locked — it must fall through to the wipe"
                );
            }
        }
    }

    /// A skipped store in `set_true` must also wipe, not be ignored.
    #[test]
    fn a_torn_arm_is_not_cleanly_locked() {
        for skip_complement in [false, true] {
            let mut b = FihBool::new_false();
            // SAFETY: test-only; emulates one of the two volatile stores in
            // `set_true` being skipped by a fault.
            unsafe {
                if skip_complement {
                    write_volatile(&mut b.val, SEC_TRUE);
                } else {
                    write_volatile(&mut b.complement, !SEC_TRUE);
                }
            }
            assert!(!b.is_true(), "a torn pair must not read as unlocked");
            assert!(
                !b.is_exactly_false(),
                "a torn pair must not read as cleanly locked either — \
                 skip_complement={skip_complement}"
            );
        }
    }
}

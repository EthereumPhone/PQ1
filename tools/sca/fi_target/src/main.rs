//! Rainbow fault-injection / side-channel target ELF for `tools/sca/`.
//!
//! Holds the bits of code the harnesses in `tools/sca/*.py` load and sweep:
//!
//!  * `sca_fi_check_true` / `sca_fi_wait_random` — thin C-symbol wrappers over
//!    the FI-guard primitives in `secure/src/fi.rs`, which is **`#[path]`-included
//!    verbatim** (so the test always runs against the exact production source; if
//!    `fi.rs` grows a new dependency this build breaks loudly). Its one hardware
//!    call, `crate::rng::byte()` inside `wait_random()`, is satisfied by the `rng`
//!    stub below (a small fixed loop count keeps sweeps fast; the loop's invariant
//!    checks, which are what we probe, are unchanged).
//!  * `sca_c10_verify_release` — a *structural reproduction* (NOT a `#[path]`
//!    include — `crypto.rs` drags in too much) of
//!    `secure/src/crypto.rs::c10_sign_verified_with_progress`: the
//!    verify-before-release glue `wait_random → verify → if !check_true(|| v) {
//!    Err } → Ok(sig)`. `sign` and `verify` are stubbed (`sca_c10_sign_stub` /
//!    `sca_c10_verify_stub`) — the SPHINCS+ math has its own targets; this one
//!    probes the *gate*. **KEEP IN SYNC** with `crypto.rs` if that function's
//!    control flow changes — see the comment on `sca_c10_verify_release`.
//!
//! Build:  cargo build --release --target thumbv8m.main-none-eabi
//!         (or: make -C tools/sca build)
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

/// Stub for the TRNG call `fi::wait_random()` makes on non-test builds.
/// A small constant keeps the random-delay loop short so fault sweeps are quick;
/// the per-iteration `i + j == wait` invariant — what the sweep actually probes
/// — is identical regardless of the value.
pub mod rng {
    #[inline(never)]
    pub fn byte() -> u8 {
        5
    }
}

// The production FI-countermeasure source, included verbatim.
#[path = "../../../../secure/src/fi.rs"]
mod fi;

/// The boolean source `check_true` re-evaluates. `#[inline(never)]` + a
/// `black_box` so LLVM can't (a) inline it into `check_true`, (b) common-
/// subexpression-eliminate the two `cond()` calls into one, or (c) prove the
/// `&& v1 && v2` in the final check away. That is what makes the sweep probe
/// `check_true`'s *actual* double-check / sentinel / re-check shape — the shape
/// it has in production when the closure is `|| sphincs_c10::verify(...)` (a
/// real, un-CSE-able `bl`). Returns `want != 0`.
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_fi_cond(want: u32) -> bool {
    core::hint::black_box(want) != 0
}

/// `fi::check_true(|| sca_fi_cond(want))` as a C symbol — returns 1 if the
/// double-checked, sentinel-gated verdict is true, else 0. The fault-sweep win
/// condition: with `want == 0`, **no** single instruction-skip makes this
/// return a non-zero value.
#[no_mangle]
pub extern "C" fn sca_fi_check_true(want: u32) -> u32 {
    fi::check_true(|| sca_fi_cond(want)) as u32
}

/// `fi::wait_random()` on its own — sweep skips over its `i + j == wait`
/// invariant loop. A glitch that skews `i`/`j` or short-circuits the loop must
/// land in `halt_on_glitch` (an endless `wfe` loop under emulation → the run
/// exhausts its instruction budget, which the harness reads as "caught").
#[no_mangle]
pub extern "C" fn sca_fi_wait_random() {
    fi::wait_random();
}

// ---------------------------------------------------------------------------
// C10 verify-before-release glue (mirror of secure/src/crypto.rs).
// ---------------------------------------------------------------------------

/// SPHINCS+C10 signature length — `sphincs_c10::params::SIGNATURE_LEN`.
const C10_SIG_LEN: usize = 4008;

/// Stand-in for `sk.sign_with_progress(...)` — the harness probes the *gate*,
/// not the SPHINCS+ math, so this just returns a fixed buffer (kept opaque so
/// the call survives, mirroring the real, un-elidable `bl sign`).
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_c10_sign_stub() -> *const u8 {
    static SIG: [u8; C10_SIG_LEN] = [0xABu8; C10_SIG_LEN];
    core::hint::black_box(SIG.as_ptr())
}

/// Stand-in for `sphincs_c10::verify(pk_seed, pk_root, msg_hash, &sig)` — the
/// harness drives the verdict: `want_pass == 0` ⇒ "the signature did NOT
/// verify" (the interesting case: the gate must then refuse to release it).
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_c10_verify_stub(want_pass: u32) -> bool {
    core::hint::black_box(want_pass) != 0
}

/// Structural mirror of `secure/src/crypto.rs::c10_sign_verified_with_progress`.
///
/// **KEEP IN SYNC** — if that function's control flow changes (the order of
/// `sign` / `wait_random` / `verify`, the `if !check_true(|| v)` shape, the
/// `Err`/`Ok` arms), update this body to match. Returns `1` if it would release
/// the signature (`Ok(sig)`), `0` if it refused (`Err(())`). The harness calls
/// it with `want_pass = 0` (verify "fails") and a non-`0` return is a bypass:
/// a glitch released an unverified signature.
///
/// Note: this passes `check_true(|| core::hint::black_box(v))` exactly as
/// `crypto.rs` now does (the F-1 fix) — the `black_box` stops LLVM from CSEing
/// the two `cond()` evaluations into one load of `v` and collapsing the
/// `&& v1 && v2` re-check, so `check_true`'s full four-decision-point shape
/// survives at this call site. Before the fix `crypto.rs` passed the bare
/// `|| v`, and this sweep found 5 single-skip bypasses (see README §Findings).
#[no_mangle]
pub extern "C" fn sca_c10_verify_release(want_pass: u32) -> u32 {
    let sig = sca_c10_sign_stub(); // sk.sign_with_progress(msg_hash, None, progress);
    fi::wait_random(); // crate::fi::wait_random();
    let v = sca_c10_verify_stub(want_pass); // sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig);
    if !fi::check_true(|| core::hint::black_box(v)) {
        return 0; // return Err(());
    }
    core::hint::black_box(sig); // Ok(sig)
    1
}

// ---------------------------------------------------------------------------
// PIN pre-commit gate (mirror of nsc::gated_unlock + hw::flash::pin_attempts_bump).
// ---------------------------------------------------------------------------

/// Fake page-124 attempt counter (in `.bss` → zero on every `e.load()`, so each
/// harness iteration starts fresh). `#[no_mangle]` so the harness can read it by
/// symbol name after a run (the gate returns only `status`; the counter is read
/// out-of-band so the read isn't itself in the fault window).
#[no_mangle]
pub static mut SCA_PIN_COUNTER: u32 = 0;
const SCA_PIN_MAX: u32 = 10; // sphincs_tz_shared::MAX_ATTEMPTS
const SCA_PIN_CAPACITY: u32 = 512; // page-124 quad-word slots

/// Mirror of `hw::flash::pin_attempts_read`. `#[inline(never)]` + a volatile load
/// so the compiler can't CSE two reads (a real flash readback is volatile too) —
/// which is the property `pin_attempts_bump`'s `check_true(|| read() == pre+1)`
/// re-check relies on.
#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_pin_attempts_read() -> u32 {
    // SAFETY: single-threaded test harness; volatile to model a flash read.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SCA_PIN_COUNTER)) }
}

/// Mirror of the `write_quadword_verified(...)` that programs one more attempt
/// marker. Returns `false` on a (modelled) write fault — a *fault* in this
/// writeback is exactly what the gate's readback check is meant to catch.
#[inline(never)]
fn sca_pin_attempts_program_one() -> bool {
    // SAFETY: as above.
    unsafe {
        let p = core::ptr::addr_of_mut!(SCA_PIN_COUNTER);
        core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
    }
    true
}

/// Mirror of `hw::flash::pin_attempts_bump`. Returns `0` = `Err(())`, else
/// `post + 1` (so `0` is unambiguously the error case). **KEEP IN SYNC.**
#[no_mangle]
pub extern "C" fn sca_pin_attempts_bump() -> u32 {
    let pre = sca_pin_attempts_read();
    if pre >= SCA_PIN_CAPACITY {
        return 0; // Err(())
    }
    if !sca_pin_attempts_program_one() {
        return 0; // write_quadword_verified(...)? bailed
    }
    fi::wait_random();
    let post = sca_pin_attempts_read();
    if post != pre + 1 {
        return 0; // Err(())
    }
    if !fi::check_true(|| sca_pin_attempts_read() == pre + 1) {
        return 0; // Err(())
    }
    post + 1 // Ok(post)
}

/// Mirror of `nsc::gated_unlock`'s `stm32u585` branch. `se_unlock_ok != 0` ⇒ the
/// SE says the PIN is correct. Returns `status`: `2` = unlocked (master returned),
/// `1` = refused (PinLocked / InternalError / wrong PIN). The harness calls with
/// `se_unlock_ok = 0` (wrong PIN) and afterwards reads `SCA_PIN_COUNTER` directly
/// (so the measurement doesn't itself sit in the fault window). An un-faulted run
/// gives `status == 1` and `SCA_PIN_COUNTER == 1`. A bypass is `status == 2`
/// (spurious unlock — the wallet treats a wrong PIN as correct) or
/// `SCA_PIN_COUNTER == 0` (the wrong attempt was NOT charged → a free guess).
/// **KEEP IN SYNC.**
#[no_mangle]
pub extern "C" fn sca_pin_gated_unlock(se_unlock_ok: u32) -> u32 {
    let pre_count = sca_pin_attempts_read();
    if pre_count >= SCA_PIN_MAX {
        return 1; // Err(PinLocked)
    }
    if sca_pin_attempts_bump() == 0 {
        return 1; // Err(InternalError)
    }
    if core::hint::black_box(se_unlock_ok) != 0 {
        // se.unlock(pin) -> Ok(master): erase the counter (fresh start)
        // SAFETY: single-threaded test harness.
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SCA_PIN_COUNTER), 0) };
        return 2; // Ok(master)
    }
    1 // Err(wrong pin) — the bump stays committed
}

// Keep the exported entry points alive: `#[no_mangle]` gives them stable symbol
// names but does NOT make them garbage-collection roots, and cortex-m-rt's
// linker script runs `--gc-sections`. A `#[used]` static that points at each fn
// forces the linker to retain its `.text` section (and therefore its `.symtab`
// entry, which is what rainbow's `e.functions[...]` reads).
#[used]
static _KEEP_CHECK_TRUE: extern "C" fn(u32) -> u32 = sca_fi_check_true;
#[used]
static _KEEP_WAIT_RANDOM: extern "C" fn() = sca_fi_wait_random;
#[used]
static _KEEP_COND: extern "C" fn(u32) -> bool = sca_fi_cond;
#[used]
static _KEEP_C10_RELEASE: extern "C" fn(u32) -> u32 = sca_c10_verify_release;
#[used]
static _KEEP_C10_SIGN: extern "C" fn() -> *const u8 = sca_c10_sign_stub;
#[used]
static _KEEP_C10_VERIFY: extern "C" fn(u32) -> bool = sca_c10_verify_stub;
#[used]
static _KEEP_PIN_UNLOCK: extern "C" fn(u32) -> u32 = sca_pin_gated_unlock;
#[used]
static _KEEP_PIN_BUMP: extern "C" fn() -> u32 = sca_pin_attempts_bump;
#[used]
static _KEEP_PIN_READ: extern "C" fn() -> u32 = sca_pin_attempts_read;

#[entry]
fn main() -> ! {
    // The harness never runs `main`; it jumps straight to the no-mangle fns.
    // Touch the keep-statics too, belt-and-braces against aggressive DCE.
    core::hint::black_box(&_KEEP_CHECK_TRUE);
    core::hint::black_box(&_KEEP_WAIT_RANDOM);
    core::hint::black_box(&_KEEP_COND);
    core::hint::black_box(&_KEEP_C10_RELEASE);
    core::hint::black_box(&_KEEP_C10_SIGN);
    core::hint::black_box(&_KEEP_C10_VERIFY);
    core::hint::black_box(&_KEEP_PIN_UNLOCK);
    core::hint::black_box(&_KEEP_PIN_BUMP);
    core::hint::black_box(&_KEEP_PIN_READ);
    loop {
        cortex_m::asm::nop();
    }
}

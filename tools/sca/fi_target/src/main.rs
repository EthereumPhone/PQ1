//! Rainbow fault-injection target: re-exports the FI-guard primitives from
//! `secure/src/fi.rs` under stable, no-mangle C symbols so a rainbow harness
//! (`tools/sca/fault_sweep_fi.py`) can load this ELF and sweep instruction-skip
//! faults over them.
//!
//! `fi.rs` is **included** (not copied) via `#[path]` so the test always runs
//! against the exact production source, byte for byte. Its one hardware
//! dependency — the `crate::rng::byte()` call inside `wait_random()` on
//! non-test builds — is satisfied by the `rng` stub below (a small fixed loop
//! count keeps emulation fast; the loop's *invariant checks*, which are what
//! we're testing, are unchanged). If `fi.rs` ever grows a new external
//! dependency, this build breaks loudly — which is the point: the test target
//! stays in lockstep with the thing it tests.
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

#[entry]
fn main() -> ! {
    // The harness never runs `main`; it jumps straight to the no-mangle fns.
    // Touch the keep-statics too, belt-and-braces against aggressive DCE.
    core::hint::black_box(&_KEEP_CHECK_TRUE);
    core::hint::black_box(&_KEEP_WAIT_RANDOM);
    core::hint::black_box(&_KEEP_COND);
    loop {
        cortex_m::asm::nop();
    }
}

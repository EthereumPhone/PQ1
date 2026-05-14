//! Fault-sweep target for the Type 1 / Type 2 dispatch logic in
//! `cmd_sign_userop.rs:160-236`. The companion provides a 32-bit `flags`
//! field and a 22-bit `slot_index`; the firmware derives two booleans
//! (`include_init_code`, `register_slot`) and runs three sanity checks
//! before deciding which signature types to emit.
//!
//! Decision categorization (the `sca_dispatch_decide` return value):
//!   0  = TYPE_2_ONLY     — plain Type-2 UserOp sign
//!   1  = TYPE_1_PLUS_2   — REGISTER_SLOT set; emit Type 1 (slot rotation)
//!                         AND Type 2 (the requested UserOp)
//!   2  = DEPLOY          — INCLUDE_INIT_CODE set; first-deploy bundle
//!                         (slot 0 pre-registration in initCode + Type 2)
//!   99 = REJECTED        — input violated a sanity check; firmware bails
//!
//! Production sanity-check rejection cases:
//!   - INCLUDE_INIT_CODE AND REGISTER_SLOT (mutually exclusive)
//!   - INCLUDE_INIT_CODE AND slot_index != 0 (init can only seed slot 0)
//!   - REGISTER_SLOT AND slot_index == 0 (slot 0 is factory-pre-registered)
//!
//! **Critical bypass class** to detect: a fault on (flags=0, slot_index=N)
//! that flips `register_slot` from false to true makes the firmware emit a
//! Type 1 the companion did NOT request — silently installing an
//! attacker-controlled slot key. On-chain `validateUserOp` re-validates the
//! bootstrap C10 sig, so a faulted Type 1 would have to also be paired with
//! valid bootstrap-key signing — which the unfaulted firmware would do
//! correctly. Blast radius: bounded by on-chain re-validation but still
//! worth confirming the firmware-side dispatch is robust.

#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

// Mirror the constants from `pqsigner_proto`.
const FLAG_INCLUDE_INIT_CODE: u32 = 0x8000_0000;
const FLAG_REGISTER_SLOT: u32 = 0x4000_0000;
const SLOT_INDEX_MASK: u32 = 0x003F_FFFF; // bits 21..0

const TYPE_2_ONLY: u32 = 0;
const TYPE_1_PLUS_2: u32 = 1;
const DEPLOY: u32 = 2;
const REJECTED: u32 = 99;

#[inline(never)]
fn wait_random() {
    pqsigner_fi::wait_random_loop(|| 0x42);
}

#[inline(never)]
fn check_true_into_sentinel<F: FnMut() -> bool>(cond: F) -> u32 {
    pqsigner_fi::check_true_into_sentinel(cond, wait_random)
}

// ---------------------------------------------------------------------------
// Plain (production) mirror.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_dispatch_decide_plain(flags: u32, slot_index: u32) -> u32 {
    let include_init_code = (flags & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & FLAG_REGISTER_SLOT) != 0;
    let slot_idx = slot_index & SLOT_INDEX_MASK;

    // Sanity checks — verbatim from production.
    if include_init_code && register_slot {
        return REJECTED;
    }
    if include_init_code && slot_idx != 0 {
        return REJECTED;
    }
    if register_slot && slot_idx == 0 {
        return REJECTED;
    }

    if include_init_code {
        DEPLOY
    } else if register_slot {
        TYPE_1_PLUS_2
    } else {
        TYPE_2_ONLY
    }
}

// ---------------------------------------------------------------------------
// FI-hardened mirror — verify-twice + sentinel for each sanity check AND for
// the boolean derivations of include_init_code / register_slot. The double-
// pass pattern that closed F-8 (NsPtr) but had the F-10 input-fault limit:
// here the inputs are u32 register args, not flash, so a stuck-at on the
// input register has nowhere to be cross-checked against. We accept that
// residual (same as F-10) and protect the gate predicate at minimum.
// ---------------------------------------------------------------------------

#[inline(never)]
#[no_mangle]
pub extern "C" fn sca_dispatch_decide_fi(flags: u32, slot_index: u32) -> u32 {
    let include_init_code = (flags & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & FLAG_REGISTER_SLOT) != 0;
    let slot_idx = slot_index & SLOT_INDEX_MASK;

    // Check 1: !(include_init_code && register_slot)
    let c1a = check_true_into_sentinel(|| !(include_init_code && register_slot));
    if c1a != pqsigner_fi::OK_SENTINEL { return REJECTED; }
    wait_random();
    let c1b = check_true_into_sentinel(|| !(include_init_code && register_slot));
    if c1b != pqsigner_fi::OK_SENTINEL { return REJECTED; }

    // Check 2: !(include_init_code && slot_idx != 0)
    let c2a = check_true_into_sentinel(|| !(include_init_code && slot_idx != 0));
    if c2a != pqsigner_fi::OK_SENTINEL { return REJECTED; }
    wait_random();
    let c2b = check_true_into_sentinel(|| !(include_init_code && slot_idx != 0));
    if c2b != pqsigner_fi::OK_SENTINEL { return REJECTED; }

    // Check 3: !(register_slot && slot_idx == 0)
    let c3a = check_true_into_sentinel(|| !(register_slot && slot_idx == 0));
    if c3a != pqsigner_fi::OK_SENTINEL { return REJECTED; }
    wait_random();
    let c3b = check_true_into_sentinel(|| !(register_slot && slot_idx == 0));
    if c3b != pqsigner_fi::OK_SENTINEL { return REJECTED; }

    if include_init_code {
        DEPLOY
    } else if register_slot {
        TYPE_1_PLUS_2
    } else {
        TYPE_2_ONLY
    }
}

#[used]
static _KEEP_PLAIN: extern "C" fn(u32, u32) -> u32 = sca_dispatch_decide_plain;
#[used]
static _KEEP_FI: extern "C" fn(u32, u32) -> u32 = sca_dispatch_decide_fi;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP_PLAIN);
    core::hint::black_box(&_KEEP_FI);
    loop {
        cortex_m::asm::nop();
    }
}

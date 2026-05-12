//! Fault-sweep target ELF for `tools/sca/fault_sweep_c10v.py`: a thin
//! `#[no_mangle]` wrapper over the **real** `sphincs_c10::verify` (software
//! SHA-256 path — what the bench/host tooling runs). The companion harness
//! loads a known *invalid* C10 signature vector (a structurally-valid signature
//! for the *wrong message* — so verification reaches and fails the final
//! `computed_root == pk_root` check) and sweeps single faults over the tail of
//! `verify`'s execution, watching for a fault that flips the reject into an
//! accept (a forged signature verifying = the worst possible FI outcome).
//!
//! Build:  cargo build --release --target thumbv8m.main-none-eabi
//!         (or: make -C tools/sca build-c10v)
#![no_std]
#![no_main]

use cortex_m_rt::entry;
use panic_halt as _;

/// `sphincs_c10::verify(pk_seed[16], pk_root[16], msg_hash[32], sig[4008]) as u32`.
/// The four args land in r0–r3 (ARM AAPCS); the harness maps the four buffers in
/// emulator RAM and passes their addresses.
#[no_mangle]
pub extern "C" fn sca_c10_verify_real(
    pk_seed: *const u8,
    pk_root: *const u8,
    msg_hash: *const u8,
    sig: *const u8,
) -> u32 {
    // SAFETY: the harness passes valid, mapped buffers of exactly these sizes.
    let pk_seed: &[u8; 16] = unsafe { &*(pk_seed as *const [u8; 16]) };
    let pk_root: &[u8; 16] = unsafe { &*(pk_root as *const [u8; 16]) };
    let msg_hash: &[u8; 32] = unsafe { &*(msg_hash as *const [u8; 32]) };
    let sig: &[u8; sphincs_c10::params::SIGNATURE_LEN] =
        unsafe { &*(sig as *const [u8; sphincs_c10::params::SIGNATURE_LEN]) };
    u32::from(sphincs_c10::verify(pk_seed, pk_root, msg_hash, sig))
}

#[used]
static _KEEP: extern "C" fn(*const u8, *const u8, *const u8, *const u8) -> u32 = sca_c10_verify_real;

#[entry]
fn main() -> ! {
    core::hint::black_box(&_KEEP);
    loop {
        cortex_m::asm::nop();
    }
}

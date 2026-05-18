//! Fault-sweep target ELF for `tools/sca/fault_sweep_groth16.py`: a thin
//! `#[no_mangle]` wrapper over the real Groth16 verifier from
//! `secure/src/zk/groth16.rs`. The harness loads an INVALID input (a
//! structurally-valid proof + VK paired with WRONG public signals, so the
//! pairing equation `e(π.A, π.B) · e(-α, β) · e(-vk_x, γ) · e(-π.C, δ) == 1`
//! is violated and `groth16_verify` returns `false`) and sweeps single faults
//! over the tail of `verify`'s execution, watching for a fault that flips the
//! reject into an accept — a forged ZK proof verifying, which would let an
//! attacker fake the clear-sign step (Aave / CowSwap / etc.) and trick the
//! user into thinking the device confirmed something it didn't.
//!
//! The `groth16_verify` function (the verifier core) is duplicated here
//! verbatim from `secure/src/zk/groth16.rs` because that file `use
//! super::poseidon::*` imports more crate-internal modules than this
//! detached target can supply. Drift risk acknowledged — the function is
//! 25 lines and a future commit that changes its behaviour would also
//! need to land this mirror. The deserialise helpers
//! (`Groth16Proof::from_bytes`, `VerificationKey::from_bytes`) are mirrored
//! likewise.
//!
//! Build: `cargo build --release --target thumbv8m.main-none-eabi`
//!        (or: `make -C tools/sca build-groth16`)

#![no_std]
#![no_main]

use bls12_381::{miller_loop_4, G1Affine, G1Projective, G2Affine, Gt, Scalar};
use cortex_m_rt::entry;
use panic_halt as _;

/// A Groth16 proof — copied verbatim from `secure/src/zk/groth16.rs`.
pub struct Groth16Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// Verification key (2 public signals) — copied verbatim.
pub struct VerificationKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    pub ic: [G1Affine; 3],
}

pub const VK_LEN: usize = 96 + 192 + 192 + 192 + 3 * 96;

impl Groth16Proof {
    pub fn from_bytes(bytes: &[u8; 384]) -> Option<Self> {
        let a_bytes: &[u8; 96] = bytes[0..96].try_into().ok()?;
        let b_bytes: &[u8; 192] = bytes[96..288].try_into().ok()?;
        let c_bytes: &[u8; 96] = bytes[288..384].try_into().ok()?;
        let a = Option::from(G1Affine::from_uncompressed(a_bytes))?;
        let b = Option::from(G2Affine::from_uncompressed(b_bytes))?;
        let c = Option::from(G1Affine::from_uncompressed(c_bytes))?;
        Some(Groth16Proof { a, b, c })
    }
}

impl VerificationKey {
    pub fn from_bytes(bytes: &[u8; VK_LEN]) -> Option<Self> {
        let alpha_g1 = Option::from(G1Affine::from_uncompressed(bytes[0..96].try_into().ok()?))?;
        let beta_g2 = Option::from(G2Affine::from_uncompressed(bytes[96..288].try_into().ok()?))?;
        let gamma_g2 = Option::from(G2Affine::from_uncompressed(bytes[288..480].try_into().ok()?))?;
        let delta_g2 = Option::from(G2Affine::from_uncompressed(bytes[480..672].try_into().ok()?))?;
        let ic0 = Option::from(G1Affine::from_uncompressed(bytes[672..768].try_into().ok()?))?;
        let ic1 = Option::from(G1Affine::from_uncompressed(bytes[768..864].try_into().ok()?))?;
        let ic2 = Option::from(G1Affine::from_uncompressed(bytes[864..960].try_into().ok()?))?;
        Some(VerificationKey {
            alpha_g1, beta_g2, gamma_g2, delta_g2,
            ic: [ic0, ic1, ic2],
        })
    }
}

/// Mirror of `secure/src/zk/groth16.rs::groth16_verify`.
/// **DRIFT WATCH** — if this diverges from the production code, fault
/// findings here may not transfer. The 25-line body is small enough
/// that drift should be obvious in review.
#[inline(never)]
fn groth16_verify(
    proof: &Groth16Proof,
    vk: &VerificationKey,
    pub0: Scalar,
    pub1: Scalar,
) -> bool {
    let vk_x: G1Affine = {
        let ic0 = G1Projective::from(vk.ic[0]);
        let ic1 = G1Projective::from(vk.ic[1]);
        let ic2 = G1Projective::from(vk.ic[2]);
        G1Affine::from(ic0 + ic1 * pub0 + ic2 * pub1)
    };

    let neg_alpha = -vk.alpha_g1;
    let neg_vk_x = -vk_x;
    let neg_c = -proof.c;

    let result = miller_loop_4([
        (&proof.a, &proof.b),
        (&neg_alpha, &vk.beta_g2),
        (&neg_vk_x, &vk.gamma_g2),
        (&neg_c, &vk.delta_g2),
    ])
    .final_exponentiation();

    result == Gt::identity()
}

/// Entry-point exported to the harness.
///
/// Wire format of the 1376-byte input buffer at `input_ptr`:
///
/// ```text
///   offset  size  field
///      0    960   VK bytes (alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ IC[0..3])
///    960    384   Proof bytes (π.A ‖ π.B ‖ π.C)
///   1344     32   pub0 (Scalar, little-endian)
///   1376     32   pub1 (Scalar, little-endian)
/// ```
///
/// Returns:
///   1  iff `groth16_verify` returned true (proof verified)
///   0  iff it returned false (proof rejected — the expected path under the
///        wrong-pub-signals vector the harness uses)
///   2  iff input deserialisation failed (malformed VK / proof / scalar)
///
/// The harness expects the unfaulted run to return 0 (the loaded vector is
/// designed to reject); a fault that produces 1 is the FORGE_RELEASE outcome.
#[no_mangle]
pub extern "C" fn sca_groth16_verify_real(input_ptr: *const u8) -> u32 {
    // SAFETY: harness maps a 1408-byte input buffer at `input_ptr` populated
    // with the (VK ‖ proof ‖ pub0 ‖ pub1) layout above.
    let buf = unsafe { core::slice::from_raw_parts(input_ptr, 1408) };

    let vk_bytes: &[u8; VK_LEN] = match buf[0..VK_LEN].try_into() {
        Ok(b) => b,
        Err(_) => return 2,
    };
    let proof_bytes: &[u8; 384] = match buf[VK_LEN..VK_LEN + 384].try_into() {
        Ok(b) => b,
        Err(_) => return 2,
    };
    let pub0_bytes: &[u8; 32] = match buf[VK_LEN + 384..VK_LEN + 416].try_into() {
        Ok(b) => b,
        Err(_) => return 2,
    };
    let pub1_bytes: &[u8; 32] = match buf[VK_LEN + 416..VK_LEN + 448].try_into() {
        Ok(b) => b,
        Err(_) => return 2,
    };

    let vk = match VerificationKey::from_bytes(vk_bytes) {
        Some(v) => v,
        None => return 2,
    };
    let proof = match Groth16Proof::from_bytes(proof_bytes) {
        Some(p) => p,
        None => return 2,
    };
    let pub0 = match Option::from(Scalar::from_bytes(pub0_bytes)) {
        Some(s) => s,
        None => return 2,
    };
    let pub1 = match Option::from(Scalar::from_bytes(pub1_bytes)) {
        Some(s) => s,
        None => return 2,
    };

    groth16_verify(&proof, &vk, pub0, pub1) as u32
}

#[entry]
fn main() -> ! {
    // Touch the keep-static so the linker retains the no_mangle export.
    core::hint::black_box(&_KEEP_GROTH16_VERIFY);
    loop {
        cortex_m::asm::nop();
    }
}

#[used]
static _KEEP_GROTH16_VERIFY: extern "C" fn(*const u8) -> u32 = sca_groth16_verify_real;

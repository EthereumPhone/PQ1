//! ZK clear signing verification module.
//!
//! Implements on-device Groth16 proof verification for the ZKlarity clear
//! signing circuit. The circuit proves that a human-readable string is a
//! faithful ABI interpretation of raw Aave v3 calldata.
//!
//! Architecture:
//!   1. Receive (calldata, readable_string, proof) from NS world
//!   2. Compute H_tx  = Poseidon(calldata)  — bind the transaction
//!   3. Compute H_str = Poseidon(readable)  — bind the display string
//!   4. Verify Groth16 proof against (H_tx, H_str) and embedded VK
//!   5. If valid: display readable_string on trusted UI

pub mod groth16;
pub mod poseidon;
mod poseidon_constants;
#[cfg(feature = "debug-log")]
pub mod test_vectors;
pub mod vk_bundle;

pub use groth16::{Groth16Proof, VerificationKey, verify_clear_signing_proof};
pub use poseidon::poseidon_bytes;
pub use vk_bundle::{verify_vk_bundle, VerifiedVk};

/// Maximum calldata size (must match ZKlarity circuit MAX_CALLDATA = 164)
pub const MAX_CALLDATA: usize = 164;

/// Human-readable string length (must match ZKlarity circuit STRING_LEN = 64)
pub const STRING_LEN: usize = 64;

/// Groth16 proof size: π.A (96) + π.B (192) + π.C (96) = 384 bytes
pub const PROOF_LEN: usize = 384;

//! Optimized Keccak-256 for ARM Cortex-M3/M4/M33.
//!
//! On ARM Thumb targets, uses hand-tuned ARMv7-M assembly from
//! Adomnicai (2023) with bit-interleaving + lazy rotations + pipelined
//! memory accesses (~9,400 cycles per f1600 vs ~18,000+ for LLVM-generated
//! Rust). On other targets, re-exports `sha3::Keccak256` for compatibility.
//!
//! API is a drop-in replacement for `sha3::{Digest, Keccak256}`.
//!
//! # References
//! - <https://eprint.iacr.org/2023/773>
//! - <https://github.com/aadomn/keccak_armv7m> (CC0)

#![no_std]

// On non-ARM targets (host tests, CI), fall back to the sha3 crate.
// The cfg is set by build.rs only for thumbv7m/v7em/v8m targets.
#[cfg(not(keccak_asm))]
pub use sha3::{Digest, Keccak256};

#[cfg(keccak_asm)]
mod asm_impl;

#[cfg(keccak_asm)]
pub use asm_impl::{Digest, Keccak256};

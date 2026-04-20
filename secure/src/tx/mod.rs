//! Ethereum transaction parsing for the secure world.
//!
//! Today only EIP-1559 (typed transaction envelope `0x02 ‖ rlp(...)`) is
//! supported. The unsigned tx envelope is passed across the gateway by NS,
//! copied into a secure stack buffer, parsed here, displayed for user
//! confirmation, and only then hashed + signed.

// display depends on crate::ui (hardware), so it's gated out in host
// test builds. eip1559, eip712 core, hash, and rlp are pure logic.
// eip712 itself is compiled in test mode but its `cowswap_display`
// submodule is gated at the submodule level (see eip712/mod.rs).
#[cfg(not(test))]
pub mod display;
pub mod eip1559;
pub mod eip712;
pub mod hash;
pub mod rlp;

// No flat re-exports of `eip1559::*` — call sites import through the
// `eip1559::` sub-path so accidentally-dead items surface as warnings.

//! Ethereum transaction parsing for the secure world.
//!
//! Today only EIP-1559 (typed transaction envelope `0x02 ‖ rlp(...)`) is
//! supported. The unsigned tx envelope is passed across the gateway by NS,
//! copied into a secure stack buffer, parsed here, displayed for user
//! confirmation, and only then hashed + signed.

// display and eip712 depend on crate::ui (hardware), so they're gated
// out in host test builds. eip1559, hash, and rlp are pure logic.
#[cfg(not(test))]
pub mod display;
pub mod eip1559;
#[cfg(not(test))]
pub mod eip712;
pub mod hash;
pub mod rlp;

// No flat re-exports of `eip1559::*` — call sites import through the
// `eip1559::` sub-path so accidentally-dead items surface as warnings.

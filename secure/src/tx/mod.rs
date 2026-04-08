//! Ethereum transaction parsing for the secure world.
//!
//! Today only EIP-1559 (typed transaction envelope `0x02 ‖ rlp(...)`) is
//! supported. The unsigned tx envelope is passed across the gateway by NS,
//! copied into a secure stack buffer, parsed here, displayed for user
//! confirmation, and only then hashed + signed.

pub mod display;
pub mod eip1559;
pub mod eip712;
pub mod hash;
pub mod rlp;

pub use eip1559::{Eip1559Tx, TxError, U256};

//! Strict ABI decoder for the standard ERC20 method calldata.
//!
//! This decodes only the three classic ERC20 surface methods. Anything
//! else (including non-standard "ERC20-like" tokens with extra
//! arguments, or any contract method that happens to share a selector
//! prefix) returns `None` and the secure world falls back to BLIND
//! SIGNING display.
//!
//! ## Selectors (first 4 bytes of the calldata)
//!
//! - `0xa9059cbb`  `transfer(address,uint256)`
//! - `0x23b872dd`  `transferFrom(address,address,uint256)`
//! - `0x095ea7b3`  `approve(address,uint256)`
//!
//! ## Strictness
//!
//! The decoder rejects any of:
//!
//! - Calldata length not exactly `4 + 32 * N` for the chosen method
//! - Address words whose top 12 bytes are non-zero (left-pad violation)
//!
//! All amounts are returned as the wallet's existing big-endian
//! [`U256`] type so the renderer can format them with the matching
//! token decimals from the metadata DB.

use crate::tx::eip1559::U256;

pub const SELECTOR_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
pub const SELECTOR_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
pub const SELECTOR_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

#[derive(Debug, Clone, Copy)]
pub enum Erc20Call {
    Transfer { to: [u8; 20], amount: U256 },
    TransferFrom { from: [u8; 20], to: [u8; 20], amount: U256 },
    Approve { spender: [u8; 20], amount: U256 },
}

/// Try to decode `data` as one of the three strict ERC20 method calls.
/// Returns `None` if `data` is too short, has the wrong length for the
/// selector, or violates address-word zero-padding.
pub fn parse_erc20_calldata(data: &[u8]) -> Option<Erc20Call> {
    if data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = data[0..4].try_into().ok()?;
    let body = &data[4..];

    match selector {
        SELECTOR_TRANSFER => {
            if body.len() != 64 {
                return None;
            }
            let to = decode_address_word(&body[0..32])?;
            let amount = decode_u256_word(&body[32..64]);
            Some(Erc20Call::Transfer { to, amount })
        }
        SELECTOR_TRANSFER_FROM => {
            if body.len() != 96 {
                return None;
            }
            let from = decode_address_word(&body[0..32])?;
            let to = decode_address_word(&body[32..64])?;
            let amount = decode_u256_word(&body[64..96]);
            Some(Erc20Call::TransferFrom { from, to, amount })
        }
        SELECTOR_APPROVE => {
            if body.len() != 64 {
                return None;
            }
            let spender = decode_address_word(&body[0..32])?;
            let amount = decode_u256_word(&body[32..64]);
            Some(Erc20Call::Approve { spender, amount })
        }
        _ => None,
    }
}

/// Decode a 32-byte ABI word as an Ethereum address. The address is
/// right-justified in the word; the top 12 bytes MUST be zero.
pub(crate) fn decode_address_word(word: &[u8]) -> Option<[u8; 20]> {
    if word.len() != 32 {
        return None;
    }
    if word[0..12].iter().any(|&b| b != 0) {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&word[12..32]);
    Some(out)
}

/// Decode a 32-byte big-endian ABI word as a U256.
pub(crate) fn decode_u256_word(word: &[u8]) -> U256 {
    let mut out = [0u8; 32];
    out.copy_from_slice(word);
    U256(out)
}

/// Heuristic threshold above which an `approve` amount is rendered as
/// the literal word `unlimited` instead of a 1.157e77-style number.
/// Anything above 2^200 is treated as "unlimited" — covers
/// `type(uint256).max`, `2^255`, and the various near-max values that
/// approval flows use.
pub fn is_unlimited_amount(amount: &U256) -> bool {
    // U256 is big-endian: amount.0[0] holds bits 248..255 (most significant
    // byte), amount.0[31] holds bits 0..7. Bit 200 is the LSB of byte 6,
    // so any nonzero byte in `amount.0[0..7]` means amount >= 2^200.
    amount.0[0..7].iter().any(|&b| b != 0)
}

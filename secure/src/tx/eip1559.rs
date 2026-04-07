//! EIP-1559 typed transaction envelope parser.
//!
//! Format (EIP-2718 typed envelope, EIP-1559 type 0x02):
//!
//! ```text
//! 0x02 ‖ rlp([
//!     chain_id,
//!     nonce,
//!     max_priority_fee_per_gas,
//!     max_fee_per_gas,
//!     gas_limit,
//!     to,            // 20 bytes or empty (contract creation)
//!     value,
//!     data,
//!     access_list,   // RLP list of [address, [storage_keys...]]
//!     // signature appended after signing — omitted in unsigned form
//! ])
//! ```
//!
//! Strict parser: rejects malformed RLP, leading zeros, oversized integers,
//! and any envelope > MAX_TX_LEN.

use super::rlp::{self, Item, ListIter, RlpError};

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    NotEip1559,
    EmptyEnvelope,
    Rlp(RlpError),
    BadToLength,
    TrailingBytes,
    EnvelopeTooLong,
}

impl From<RlpError> for TxError {
    fn from(e: RlpError) -> Self {
        TxError::Rlp(e)
    }
}

/// Big-endian 256-bit unsigned integer.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Format as a decimal integer divided by 10^decimals into `out`,
    /// with **fixed-width** fractional digits — `frac_digits` always
    /// emitted, no trailing-zero trimming. Used for ERC20 token amounts
    /// where `1.500000 USDC` is harder to spoof visually than
    /// `1.5 USDC`.
    ///
    /// Returns the number of bytes written.
    pub fn format_decimal_fixed(&self, decimals: u32, frac_digits: u32, out: &mut [u8]) -> usize {
        let mut digits = [0u8; 80];
        let mut n_digits = 0usize;
        let mut v = self.0;
        let zero = [0u8; 32];
        if v == zero {
            digits[0] = b'0';
            n_digits = 1;
        } else {
            while v != zero {
                let r = div10_inplace(&mut v);
                digits[n_digits] = b'0' + r;
                n_digits += 1;
            }
        }

        let total_decimals = decimals as usize;
        let frac = frac_digits as usize;

        let mut written = 0usize;
        let int_digits = if n_digits > total_decimals {
            n_digits - total_decimals
        } else {
            0
        };

        if int_digits == 0 {
            if written < out.len() {
                out[written] = b'0';
                written += 1;
            }
        } else {
            for i in (0..int_digits).rev() {
                if written < out.len() {
                    out[written] = digits[total_decimals + i];
                    written += 1;
                }
            }
        }

        if frac > 0 && total_decimals > 0 {
            if written < out.len() {
                out[written] = b'.';
                written += 1;
            }
            for i in (0..frac).rev() {
                let actual_idx = total_decimals.saturating_sub(1 + i);
                let d = if actual_idx < n_digits { digits[actual_idx] } else { b'0' };
                if written < out.len() {
                    out[written] = d;
                    written += 1;
                }
            }
            // NOTE: deliberately no trailing-zero trimming.
        }

        written
    }

    /// Format as a decimal integer divided by 10^decimals into `out`.
    /// Returns the number of bytes written. Truncates trailing zeros in
    /// the fractional part — used for ETH/gwei display where `1 ETH`
    /// is more readable than `1.000000 ETH`. For ERC20 token amounts
    /// use [`Self::format_decimal_fixed`] instead (anti-spoof).
    pub fn format_decimal(&self, decimals: u32, frac_digits: u32, out: &mut [u8]) -> usize {
        // Convert U256 → decimal string by repeated division by 10. Up to 78
        // digits. We compute integer part and `frac_digits` fractional digits.
        let mut digits = [0u8; 80];
        let mut n_digits = 0usize;

        let mut v = self.0;
        let zero = [0u8; 32];

        if v == zero {
            digits[0] = b'0';
            n_digits = 1;
        } else {
            while v != zero {
                let r = div10_inplace(&mut v);
                digits[n_digits] = b'0' + r;
                n_digits += 1;
            }
        }

        // digits[0..n_digits] holds least-significant digit first.
        let total_decimals = decimals as usize;
        let frac = frac_digits as usize;

        // Build into out: <integer>.<fraction>
        let mut written = 0usize;
        let int_digits = if n_digits > total_decimals {
            n_digits - total_decimals
        } else {
            0
        };

        if int_digits == 0 {
            if written < out.len() {
                out[written] = b'0';
                written += 1;
            }
        } else {
            for i in (0..int_digits).rev() {
                if written < out.len() {
                    out[written] = digits[total_decimals + i];
                    written += 1;
                }
            }
        }

        if frac > 0 && total_decimals > 0 {
            if written < out.len() {
                out[written] = b'.';
                written += 1;
            }
            for i in (0..frac).rev() {
                let digit_idx = i + (if total_decimals > frac { total_decimals - frac } else { 0 });
                let _ = digit_idx;
                // Use total_decimals - 1 - i down to total_decimals - frac
                let actual_idx = total_decimals.saturating_sub(1 + i);
                let d = if actual_idx < n_digits { digits[actual_idx] } else { b'0' };
                if written < out.len() {
                    out[written] = d;
                    written += 1;
                }
            }
            // Trim trailing zeros after decimal point.
            while written > 0 && out[written - 1] == b'0' {
                written -= 1;
            }
            if written > 0 && out[written - 1] == b'.' {
                written -= 1;
            }
        }

        written
    }
}

/// Divide a 32-byte big-endian U256 by 10 in place; returns remainder.
fn div10_inplace(v: &mut [u8; 32]) -> u8 {
    let mut rem: u16 = 0;
    for byte in v.iter_mut() {
        let acc = (rem << 8) | (*byte as u16);
        *byte = (acc / 10) as u8;
        rem = acc % 10;
    }
    rem as u8
}

#[derive(Default, Debug)]
pub struct Eip1559Tx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: U256,
    pub data_len: usize,
    pub access_list_count: usize,
    /// keccak256 of the unsigned envelope. Set by `parse()`.
    pub signing_hash: [u8; 32],
}

/// Output of `parse()`. Borrows from the input envelope so the calldata
/// slice cannot outlive the buffer it points into — the borrow checker
/// enforces what was previously a convention. The owned `tx` field still
/// holds the legacy `data_len` for renderers that don't need the bytes.
pub struct ParsedTx<'a> {
    pub tx: Eip1559Tx,
    /// Raw calldata bytes (`tx.data` from the EIP-1559 envelope). Empty
    /// for plain value transfers and contract creations.
    pub data: &'a [u8],
    /// The complete unsigned envelope (leading 0x02 byte + RLP body).
    /// Useful if a caller needs to re-hash or re-serialize.
    pub envelope: &'a [u8],
}

/// Parse a complete unsigned EIP-1559 envelope: leading 0x02 byte followed
/// by RLP-encoded list of nine fields. Computes the keccak256 signing hash.
pub fn parse<'a>(envelope: &'a [u8]) -> Result<ParsedTx<'a>, TxError> {
    if envelope.len() > sphincs_tz_shared::MAX_TX_LEN {
        return Err(TxError::EnvelopeTooLong);
    }
    let first = *envelope.first().ok_or(TxError::EmptyEnvelope)?;
    if first != 0x02 {
        return Err(TxError::NotEip1559);
    }

    let payload = &envelope[1..];
    let (item, used) = rlp::decode_item(payload)?;
    if used != payload.len() {
        return Err(TxError::TrailingBytes);
    }
    let list_payload = match item {
        Item::List(l) => l,
        Item::Bytes(_) => return Err(TxError::Rlp(RlpError::UnexpectedType)),
    };

    let mut iter = ListIter::new(list_payload);

    let chain_id = rlp::bytes_to_u64(iter.expect_bytes()?)?;
    let nonce = rlp::bytes_to_u64(iter.expect_bytes()?)?;
    let max_priority = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let max_fee = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let gas_limit = rlp::bytes_to_u64(iter.expect_bytes()?)?;

    let to_bytes = iter.expect_bytes()?;
    let to = match to_bytes.len() {
        0 => None,
        20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(to_bytes);
            Some(arr)
        }
        _ => return Err(TxError::BadToLength),
    };

    let value = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let data = iter.expect_bytes()?;
    let access_list_payload = iter.expect_list()?;

    // Count entries in the access list. Each entry is itself a list of
    // [address, [storage_keys...]]. We don't decode them; just count.
    let mut access_iter = ListIter::new(access_list_payload);
    let mut access_list_count = 0usize;
    while let Some(_item) = access_iter.next_item()? {
        access_list_count += 1;
    }

    // The unsigned form must have no further fields.
    if iter.next_item()?.is_some() {
        return Err(TxError::TrailingBytes);
    }

    let signing_hash = super::hash::keccak256(envelope);

    Ok(ParsedTx {
        tx: Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data_len: data.len(),
            access_list_count,
            signing_hash,
        },
        data,
        envelope,
    })
}


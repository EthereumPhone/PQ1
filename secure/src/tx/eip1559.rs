//! EIP-1559 typed transaction envelope parser and the shared `U256`
//! big-endian integer used throughout the display / sign pipeline.
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
//!     access_list,   // RLP list of [address(20), [storage_key(32)...]]
//!     // signature appended after signing — omitted in unsigned form
//! ])
//! ```
//!
//! Strict parser: rejects malformed RLP, leading zeros, oversized
//! integers, malformed access lists, EIP-155 chain_id == 0, gas below
//! the 21 000 intrinsic floor, max_priority > max_fee, and any envelope
//! outside `1 < len ≤ MAX_TX_LEN`.

use super::rlp::{self, Item, ListIter, RlpError};

/// EIP-1559 intrinsic gas floor for a signed tx. Nothing below this can
/// execute on an EVM chain, so accepting it would mean the user
/// confirmed a tx that can never land.
pub const MIN_INTRINSIC_GAS: u64 = 21_000;

#[derive(Debug, PartialEq, Eq)]
pub enum TxError {
    NotEip1559,
    EmptyEnvelope,
    Rlp(RlpError),
    BadToLength,
    TrailingBytes,
    EnvelopeTooLong,
    /// `chain_id` was zero — forbidden by EIP-155.
    BadChainId,
    /// `gas_limit` was below the 21 000-gas intrinsic floor.
    GasLimitTooLow,
    /// `max_priority_fee_per_gas > max_fee_per_gas`, forbidden by EIP-1559.
    PriorityExceedsFee,
    /// Access list entry was not `[address(20), [key(32)...]]`.
    BadAccessList,
}

impl From<RlpError> for TxError {
    fn from(e: RlpError) -> Self {
        TxError::Rlp(e)
    }
}

// ---------------------------------------------------------------------------
// U256
// ---------------------------------------------------------------------------

/// Big-endian 256-bit unsigned integer.
///
/// Stored most-significant-byte first: `self.0[0]` is bits 248..255,
/// `self.0[31]` is bits 0..7. All public accessors preserve that.
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Return true iff `self >= other`.
    pub fn ge(&self, other: &U256) -> bool {
        // Big-endian bytewise compare.
        for i in 0..32 {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Greater => return true,
                core::cmp::Ordering::Less => return false,
                core::cmp::Ordering::Equal => {}
            }
        }
        true
    }

    /// Saturating `self * other_u64 -> U256` for fee-budget display
    /// (`max_fee * gas_limit`). Returns `(product, overflow)`; the
    /// product saturates at `U256::MAX` on overflow.
    pub fn saturating_mul_u64(&self, rhs: u64) -> (U256, bool) {
        let mut out = [0u8; 32];
        let mut carry: u128 = 0;
        // LS-first multiply
        for i in (0..32).rev() {
            let prod = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = prod as u8;
            carry = prod >> 8;
        }
        let overflow = carry != 0;
        if overflow {
            (U256([0xffu8; 32]), true)
        } else {
            (U256(out), false)
        }
    }

    /// Format `self / 10^decimals` as a human-readable decimal. Writes
    /// at most `out.len()` bytes. Returns the number of bytes on
    /// success or `None` if the full output would not fit — the
    /// function is **overflow-safe**: on overflow, it writes nothing
    /// and the caller renders a truncation banner rather than a
    /// silently-shortened number.
    ///
    /// `frac_digits` fractional digits are always emitted when
    /// `trim_trailing_zeros = false`; when true, trailing '0' bytes and
    /// the decimal point are removed if the fraction collapses to
    /// zeros.
    ///
    /// Examples (decimals=18, ETH):
    ///
    ///   - value = 0,                    frac=6, trim=false → "0.000000"
    ///   - value = 0,                    frac=6, trim=true  → "0"
    ///   - value = 1_500_000_000_000_000_000, frac=6, trim=false → "1.500000"
    ///   - value = 1,                    frac=18, trim=false → "0.000000000000000001"
    ///   - value = U256::MAX,            frac=0                → 78-digit integer
    pub fn format_decimal(
        &self,
        decimals: u32,
        frac_digits: u32,
        trim_trailing_zeros: bool,
        out: &mut [u8],
    ) -> Option<usize> {
        // --- 1. Digit extraction. Max 78 decimal digits for 2^256-1. -------
        let mut digits = [0u8; 80];
        let mut n_digits = 0usize;
        let mut v = self.0;
        if self.is_zero() {
            digits[0] = 0;
            n_digits = 1;
        } else {
            while !is_zero(&v) {
                let r = div10_inplace(&mut v);
                digits[n_digits] = r;
                n_digits += 1;
            }
        }
        // `digits[i]` holds the i-th least-significant decimal digit
        // as a raw 0..=9 value; we ASCII-encode on write.

        let total_decimals = decimals as usize;
        let frac = frac_digits as usize;

        // --- 2. Decide how many fractional digits to actually emit ---------
        //
        // When frac_digits > total_decimals, the extra positions are
        // structural zeros (e.g. format_decimal(decimals=0, frac=3)
        // of value 5 → "5.000"). We emit exactly `frac` digits so the
        // visual width is stable.
        //
        // When trim_trailing_zeros, we recompute `frac_emit` from the
        // last non-zero fractional digit backwards.
        let mut frac_emit = frac;
        if trim_trailing_zeros && frac_emit > 0 {
            while frac_emit > 0 {
                // Digit index inside `digits` for the i-th fractional
                // position counted from the decimal point (1..=frac):
                let pos = frac_emit; // positions 1..=frac
                let digit_idx = total_decimals.saturating_sub(pos);
                let d = if total_decimals >= pos && digit_idx < n_digits {
                    digits[digit_idx]
                } else {
                    0
                };
                if d != 0 {
                    break;
                }
                frac_emit -= 1;
            }
        }

        // --- 3. Compute integer-part width --------------------------------
        let int_digits = if n_digits > total_decimals {
            n_digits - total_decimals
        } else {
            0
        };
        let int_emit = core::cmp::max(int_digits, 1); // always at least "0"

        // --- 4. Required output width -------------------------------------
        let mut need = int_emit;
        let emit_point = frac_emit > 0;
        if emit_point {
            need += 1 + frac_emit;
        }
        if need > out.len() {
            return None;
        }

        // --- 5. Write -----------------------------------------------------
        let mut w = 0usize;
        if int_digits == 0 {
            out[w] = b'0';
            w += 1;
        } else {
            for i in (0..int_digits).rev() {
                let d = digits[total_decimals + i];
                out[w] = b'0' + d;
                w += 1;
            }
        }
        if emit_point {
            out[w] = b'.';
            w += 1;
            // Emit fractional positions 1..=frac_emit (most-significant first).
            for pos in 1..=frac_emit {
                let digit_idx = total_decimals.saturating_sub(pos);
                let d = if total_decimals >= pos && digit_idx < n_digits {
                    digits[digit_idx]
                } else {
                    0
                };
                out[w] = b'0' + d;
                w += 1;
            }
        }
        debug_assert_eq!(w, need);
        Some(w)
    }

    /// Fixed-width anti-spoof variant: always emits exactly
    /// `frac_digits` fractional positions (no trailing-zero trim), so
    /// `1 USDC` can't visually collide with `1.000000 USDC`. Used for
    /// ERC-20 token amounts where the decimals come from an
    /// attacker-supplied (but Merkle-verified) DB row.
    pub fn format_decimal_fixed(
        &self,
        decimals: u32,
        frac_digits: u32,
        out: &mut [u8],
    ) -> Option<usize> {
        self.format_decimal(decimals, frac_digits, false, out)
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

fn is_zero(v: &[u8; 32]) -> bool {
    v.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// Eip1559Tx + strict envelope parser
// ---------------------------------------------------------------------------

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

/// Output of [`parse`]. Borrows from the input envelope so the calldata
/// slice cannot outlive the buffer it points into — the borrow checker
/// enforces what was previously a convention.
#[derive(Debug)]
pub struct ParsedTx<'a> {
    pub tx: Eip1559Tx,
    /// Raw calldata bytes (`tx.data` from the EIP-1559 envelope). Empty
    /// for plain value transfers and contract creations.
    pub data: &'a [u8],
    /// The complete unsigned envelope (leading 0x02 byte + RLP body).
    /// Useful if a caller needs to re-hash or re-serialize.
    pub envelope: &'a [u8],
}

/// Parse a complete unsigned EIP-1559 envelope: leading 0x02 byte
/// followed by an RLP-encoded list of nine fields. Enforces every
/// structural invariant the EVM requires, so a successful return
/// guarantees the transaction can be displayed to the user as-is
/// without further validation.
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
    if chain_id == 0 {
        return Err(TxError::BadChainId);
    }
    let nonce = rlp::bytes_to_u64(iter.expect_bytes()?)?;
    let max_priority = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let max_fee = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    if max_priority.ge(&max_fee) && max_priority != max_fee {
        return Err(TxError::PriorityExceedsFee);
    }
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

    // Contract-creation txs need not hit the 21 000 floor (CREATE has
    // its own intrinsic cost of 53 000, but enforcing both would reject
    // simulations); plain txs must.
    if to.is_some() && gas_limit < MIN_INTRINSIC_GAS {
        return Err(TxError::GasLimitTooLow);
    }

    let value = U256(rlp::bytes_to_u256(iter.expect_bytes()?)?);
    let data = iter.expect_bytes()?;
    let access_list_payload = iter.expect_list()?;

    // Validate each access list entry structurally: `[address(20),
    // [storage_key(32)...]]`. The EVM reverts on malformed entries, so
    // letting them through here lets NS signal "valid" on a tx that
    // can never land.
    let access_list_count = validate_access_list(access_list_payload)?;

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

/// Walk the access list payload, enforcing that every entry is a pair
/// `[address(20), [storage_key(32)...]]`. Returns the number of
/// entries.
fn validate_access_list(payload: &[u8]) -> Result<usize, TxError> {
    let mut iter = ListIter::new(payload);
    let mut count = 0usize;
    while let Some(item) = iter.next_item()? {
        let tuple = match item {
            Item::List(l) => l,
            Item::Bytes(_) => return Err(TxError::BadAccessList),
        };
        let mut inner = ListIter::new(tuple);
        // Field 1: 20-byte address.
        let addr = match inner.next_item()? {
            Some(Item::Bytes(b)) => b,
            _ => return Err(TxError::BadAccessList),
        };
        if addr.len() != 20 {
            return Err(TxError::BadAccessList);
        }
        // Field 2: list of 32-byte storage keys.
        let keys = match inner.next_item()? {
            Some(Item::List(l)) => l,
            _ => return Err(TxError::BadAccessList),
        };
        let mut key_iter = ListIter::new(keys);
        while let Some(k) = key_iter.next_item()? {
            match k {
                Item::Bytes(b) if b.len() == 32 => {}
                _ => return Err(TxError::BadAccessList),
            }
        }
        // No extra fields in the tuple.
        if inner.next_item()?.is_some() {
            return Err(TxError::BadAccessList);
        }
        count += 1;
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Tests (host-only).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn u256_from_u64(x: u64) -> U256 {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&x.to_be_bytes());
        U256(buf)
    }

    fn u256_from_bigint_pow10(exp: u32) -> U256 {
        // Returns 10^exp as a U256. exp must be <= 77.
        let mut v = [0u8; 32];
        v[31] = 1;
        let mut u = U256(v);
        for _ in 0..exp {
            let (p, over) = u.saturating_mul_u64(10);
            assert!(!over);
            u = p;
        }
        u
    }

    fn format_to_string(v: &U256, decimals: u32, frac: u32, trim: bool) -> Option<std::string::String> {
        let mut out = [0u8; 96];
        let n = v.format_decimal(decimals, frac, trim, &mut out)?;
        Some(std::string::String::from_utf8(out[..n].to_vec()).unwrap())
    }

    #[test]
    fn format_zero_no_frac() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 0, 0, false).as_deref(), Some("0"));
    }

    #[test]
    fn format_zero_with_frac_fixed() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("0.000000"));
    }

    #[test]
    fn format_zero_with_frac_trim() {
        let v = U256::zero();
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("0"));
    }

    #[test]
    fn format_one_wei_as_eth() {
        let v = u256_from_u64(1);
        // 1 wei with 18 decimals + 18 frac = "0.000000000000000001"
        assert_eq!(
            format_to_string(&v, 18, 18, false).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_one_wei_as_eth_trimmed() {
        let v = u256_from_u64(1);
        // trim=true keeps exactly the non-zero fractional tail
        assert_eq!(
            format_to_string(&v, 18, 18, true).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_one_eth_fixed6() {
        // 10^18 wei = 1 ETH
        let v = u256_from_bigint_pow10(18);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("1.000000"));
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("1"));
    }

    #[test]
    fn format_1_5_eth() {
        // 1.5 * 10^18 wei
        let v = u256_from_bigint_pow10(18);
        let half = u256_from_bigint_pow10(17);
        let mut sum = [0u16; 32];
        for i in 0..32 {
            sum[i] = v.0[i] as u16 + half.0[i] as u16 + (half.0[i] as u16 / 2); // quick hack
        }
        // Easier: just compute 1_500_000_000_000_000_000 = 0x14D1_120D_7B16_0000
        let raw: u128 = 1_500_000_000_000_000_000u128;
        let mut buf = [0u8; 32];
        buf[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(buf);
        assert_eq!(format_to_string(&v, 18, 6, false).as_deref(), Some("1.500000"));
        assert_eq!(format_to_string(&v, 18, 6, true).as_deref(), Some("1.5"));
    }

    #[test]
    fn format_overflow_returns_none() {
        // 10^18 = "1.000000" needs 8 bytes.
        let v = u256_from_bigint_pow10(18);
        let mut out = [0u8; 4];
        assert_eq!(v.format_decimal(18, 6, false, &mut out), None);
    }

    #[test]
    fn format_u256_max_integer() {
        let v = U256([0xffu8; 32]);
        let mut out = [0u8; 96];
        let n = v.format_decimal(0, 0, false, &mut out).unwrap();
        let s = core::str::from_utf8(&out[..n]).unwrap();
        // 2^256 - 1 = 78-digit number:
        // 115792089237316195423570985008687907853269984665640564039457584007913129639935
        assert_eq!(n, 78);
        assert!(s.starts_with("115792089237"));
    }

    #[test]
    fn format_decimals_greater_than_digits() {
        // 1 wei, 18 decimals, 18 frac → "0.000000000000000001"
        let v = u256_from_u64(1);
        assert_eq!(
            format_to_string(&v, 18, 18, false).as_deref(),
            Some("0.000000000000000001"),
        );
    }

    #[test]
    fn format_huge_integer_returns_none_on_tight_buffer() {
        // Regression guard: the old formatter silently truncated the
        // MOST significant digits of values whose decimal form didn't
        // fit in the scratch buffer, so a whale trying to send
        // 1_234_567_890_123.123456 ETH would see the display claim a
        // 10× smaller amount. The new formatter refuses to fit and
        // returns None so the display layer can raise an overflow
        // banner instead.
        let mut buf = [0u8; 32];
        let raw: u128 = 1_234_567_890_123_000_000_000_000_000_000u128;
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(bytes);
        // Rendered as ETH (18 decimals, 6 frac, trim=true) the result
        // is "1234567890123.000000" trimmed to "1234567890123" (13
        // chars). Fits in 16 but trips the 12-byte scratch that the
        // pre-fix helpers used:
        assert_eq!(v.format_decimal(18, 6, true, &mut buf[..12]), None);
        // And renders correctly in a wide-enough buffer:
        let n = v.format_decimal(18, 6, true, &mut buf).unwrap();
        assert_eq!(
            core::str::from_utf8(&buf[..n]).unwrap(),
            "1234567890123",
        );
    }

    #[test]
    fn format_whale_transfer_preserves_fractional_tail() {
        // 12_345_678_901.234567 ETH as wei.
        let raw: u128 = 12_345_678_901_234_567_000_000_000_000u128;
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&raw.to_be_bytes());
        let v = U256(bytes);
        let s = format_to_string(&v, 18, 6, false).unwrap();
        assert_eq!(s, "12345678901.234567");
    }

    #[test]
    fn format_frac_greater_than_decimals() {
        // 1 unit with 2 decimals, 6 frac digits → "0.010000"?
        // Actually value = 1, decimals = 2 means 1 / 100 = 0.01. With
        // 6 frac digits that's "0.010000".
        let v = u256_from_u64(1);
        assert_eq!(format_to_string(&v, 2, 6, false).as_deref(), Some("0.010000"));
        // Integer 5 unit with 0 decimals, 3 frac → "5.000"
        let v = u256_from_u64(5);
        assert_eq!(format_to_string(&v, 0, 3, false).as_deref(), Some("5.000"));
    }

    #[test]
    fn saturating_mul_basic() {
        let v = u256_from_u64(1_000_000);
        let (p, over) = v.saturating_mul_u64(2_000);
        assert!(!over);
        let mut out = [0u8; 96];
        let n = p.format_decimal(0, 0, false, &mut out).unwrap();
        assert_eq!(&out[..n], b"2000000000");
    }

    #[test]
    fn saturating_mul_overflow_saturates() {
        let v = U256([0xffu8; 32]);
        let (p, over) = v.saturating_mul_u64(2);
        assert!(over);
        assert_eq!(p, U256([0xffu8; 32]));
    }

    #[test]
    fn ge_compare() {
        let a = u256_from_u64(10);
        let b = u256_from_u64(5);
        assert!(a.ge(&b));
        assert!(!b.ge(&a));
        assert!(a.ge(&a));
    }

    // --- parser tests -----------------------------------------------------

    fn rlp_encode_bytes(bytes: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        if bytes.len() == 1 && bytes[0] <= 0x7f {
            out.push(bytes[0]);
        } else if bytes.len() <= 55 {
            out.push(0x80 + bytes.len() as u8);
            out.extend_from_slice(bytes);
        } else {
            // Long form
            let len_bytes = (bytes.len() as u64).to_be_bytes();
            let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
            let len_enc = &len_bytes[first_nonzero..];
            out.push(0xb7 + len_enc.len() as u8);
            out.extend_from_slice(len_enc);
            out.extend_from_slice(bytes);
        }
        out
    }

    fn rlp_encode_list(items: &[std::vec::Vec<u8>]) -> std::vec::Vec<u8> {
        let mut body = std::vec::Vec::new();
        for it in items {
            body.extend_from_slice(it);
        }
        let mut out = std::vec::Vec::new();
        if body.len() <= 55 {
            out.push(0xc0 + body.len() as u8);
        } else {
            let len_bytes = (body.len() as u64).to_be_bytes();
            let first_nonzero = len_bytes.iter().position(|&b| b != 0).unwrap();
            let len_enc = &len_bytes[first_nonzero..];
            out.push(0xf7 + len_enc.len() as u8);
            out.extend_from_slice(len_enc);
        }
        out.extend_from_slice(&body);
        out
    }

    fn be_trim(bytes: &[u8]) -> std::vec::Vec<u8> {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        bytes[first..].to_vec()
    }

    fn build_envelope(
        chain_id: u64,
        nonce: u64,
        max_prio_gwei: u64,
        max_fee_gwei: u64,
        gas_limit: u64,
        to: Option<[u8; 20]>,
        value_wei: u64,
        data: &[u8],
    ) -> std::vec::Vec<u8> {
        let items = std::vec![
            rlp_encode_bytes(&be_trim(&chain_id.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&nonce.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&max_prio_gwei.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&max_fee_gwei.to_be_bytes())),
            rlp_encode_bytes(&be_trim(&gas_limit.to_be_bytes())),
            match to {
                Some(a) => rlp_encode_bytes(&a),
                None => rlp_encode_bytes(&[]),
            },
            rlp_encode_bytes(&be_trim(&value_wei.to_be_bytes())),
            rlp_encode_bytes(data),
            rlp_encode_list(&[]),
        ];
        let list = rlp_encode_list(&items);
        let mut env = std::vec![0x02u8];
        env.extend_from_slice(&list);
        env
    }

    #[test]
    fn parse_minimal_tx() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 1, 2, 21_000, Some(to), 0, &[]);
        let parsed = parse(&env).unwrap();
        assert_eq!(parsed.tx.chain_id, 1);
        assert_eq!(parsed.tx.gas_limit, 21_000);
        assert_eq!(parsed.tx.to, Some(to));
    }

    #[test]
    fn reject_chain_zero() {
        let to = [0x11u8; 20];
        let env = build_envelope(0, 0, 1, 2, 21_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::BadChainId);
    }

    #[test]
    fn reject_gas_too_low() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 1, 2, 20_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::GasLimitTooLow);
    }

    #[test]
    fn reject_priority_greater_than_fee() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 10, 5, 21_000, Some(to), 0, &[]);
        assert_eq!(parse(&env).unwrap_err(), TxError::PriorityExceedsFee);
    }

    #[test]
    fn allow_priority_equal_to_fee() {
        let to = [0x11u8; 20];
        let env = build_envelope(1, 0, 5, 5, 21_000, Some(to), 0, &[]);
        let parsed = parse(&env).unwrap();
        assert_eq!(parsed.tx.max_fee_per_gas.0[31], 5);
        assert_eq!(parsed.tx.max_priority_fee_per_gas.0[31], 5);
    }

    #[test]
    fn reject_wrong_envelope_type() {
        let mut env = build_envelope(1, 0, 1, 2, 21_000, Some([0u8; 20]), 0, &[]);
        env[0] = 0x01;
        assert_eq!(parse(&env).unwrap_err(), TxError::NotEip1559);
    }

    #[test]
    fn reject_trailing_bytes() {
        let mut env = build_envelope(1, 0, 1, 2, 21_000, Some([0u8; 20]), 0, &[]);
        env.push(0x00);
        assert_eq!(parse(&env).unwrap_err(), TxError::TrailingBytes);
    }
}

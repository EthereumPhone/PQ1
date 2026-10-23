//! Pure field-decode for the packed Uniswap Permit2 permit carried by
//! `CMD_SIGN_OFFCHAIN` kind 6 (`OFFCHAIN_KIND_PERMIT2`).
//!
//! The host-compilable, Kani-friendly core of the Permit2 clear-sign path,
//! the twin of [`crate::cowswap_order`]: the fixed-offset extraction of the
//! packed permit into [`Permit2Core`], plus the policy refusals that do not
//! need hashing. The keccak struct hash / digest and the ERC-20 leg decode
//! stay in `secure/src/tx/eip712/permit2/`.
//!
//! ## Packed layout
//!
//! ```text
//!   allowance (variant 0 PermitSingle, 1 PermitBatch), head 62 B:
//!     [ 0]       variant
//!     [ 1.. 9)   chain_id      u64 BE
//!     [ 9..29)   spender       address
//!     [29..61)   sigDeadline   uint256 BE
//!     [61]       count         (variant 0: 1, variant 1: 1..=6)
//!     count x { token(20) amount uint160 BE (20) expiration uint48 BE (6) nonce uint48 BE (6) }
//!   transfer (variant 2 PermitTransferFrom, 3 PermitBatchTransferFrom), head 94 B:
//!     [ 0]       variant
//!     [ 1.. 9)   chain_id      u64 BE
//!     [ 9..29)   spender       address
//!     [29..61)   nonce         uint256 BE
//!     [61..93)   deadline      uint256 BE
//!     [93]       count         (variant 2: 1, variant 3: 1..=6)
//!     count x { token(20) amount uint256 BE (32) }
//! ```
//!
//! Every value is packed at its Solidity width and widened here into its
//! EIP-712 word (zero-padded on the left), so a dirty high bit in a
//! `uint160` / `uint48` / `address` word cannot reach the digest: there is no
//! byte on the wire for it to live in.
//!
//! ## Refusals
//!
//! Beyond framing (variant, count, exact length), [`decode_core`] refuses a
//! zero spender, a zero token and a token that appears twice. A duplicate is
//! not invalid to Permit2, but it changes the meaning of what is shown:
//! AllowanceTransfer applies the entries in order (the last one wins) and
//! SignatureTransfer pulls each entry (they add up). Showing two rows for one
//! token would invite the user to read either one as the effect, so the
//! device refuses instead.

use pqsigner_proto::{
    PERMIT2_ALLOWANCE_HEAD_LEN, PERMIT2_ENTRY_LEN, PERMIT2_MAX_TOKENS, PERMIT2_TRANSFER_HEAD_LEN,
    PERMIT2_VARIANT_BATCH, PERMIT2_VARIANT_BATCH_TRANSFER, PERMIT2_VARIANT_SINGLE,
    PERMIT2_VARIANT_TRANSFER,
};

/// Why a packed permit was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permit2DecodeError {
    /// Empty input, or a variant byte above 3.
    BadVariant,
    /// `count` outside the variant's range (single: 1, batch: 1..=6).
    BadCount,
    /// The input is not exactly `head + count * 52` bytes.
    BadLength,
    /// The spender is the zero address.
    ZeroSpender,
    /// A token is the zero address.
    ZeroToken,
    /// The same token appears in two entries.
    DuplicateToken,
}

impl Permit2DecodeError {
    /// Short status-line text for the trusted display.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadVariant => "permit2 variant",
            Self::BadCount => "permit2 count",
            Self::BadLength => "permit2 length",
            Self::ZeroSpender => "permit2 zero adr",
            Self::ZeroToken => "permit2 zero tok",
            Self::DuplicateToken => "permit2 dup tok",
        }
    }
}

/// One token entry, widened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit2Entry {
    pub token: [u8; 20],
    /// The amount as its EIP-712 word: a `uint160` (allowance) or `uint256`
    /// (transfer) big-endian, zero-padded to 32 bytes.
    pub amount: [u8; 32],
    /// Allowance `expiration` (`uint48`); 0 for transfer variants.
    pub expiration: u64,
    /// Allowance `nonce` (`uint48`); 0 for transfer variants.
    pub nonce: u64,
}

const ZERO_ENTRY: Permit2Entry = Permit2Entry {
    token: [0; 20],
    amount: [0; 32],
    expiration: 0,
    nonce: 0,
};

/// A decoded permit. Borrows nothing; entries past `count` are zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permit2Core {
    pub variant: u8,
    pub chain_id: u64,
    pub spender: [u8; 20],
    /// `sigDeadline` (allowance) or `deadline` (transfer), `uint256` BE.
    pub deadline: [u8; 32],
    /// SignatureTransfer `nonce` (`uint256` BE); zero for allowance variants.
    pub nonce: [u8; 32],
    pub count: u8,
    pub entries: [Permit2Entry; PERMIT2_MAX_TOKENS],
}

impl Permit2Core {
    /// AllowanceTransfer (`PermitSingle` / `PermitBatch`): reusable allowances.
    pub const fn is_allowance(&self) -> bool {
        is_allowance(self.variant)
    }

    /// The `count` live entries.
    pub fn live(&self) -> &[Permit2Entry] {
        &self.entries[..usize::from(self.count)]
    }
}

const fn is_allowance(variant: u8) -> bool {
    variant == PERMIT2_VARIANT_SINGLE || variant == PERMIT2_VARIANT_BATCH
}

const fn is_batch(variant: u8) -> bool {
    variant == PERMIT2_VARIANT_BATCH || variant == PERMIT2_VARIANT_BATCH_TRANSFER
}

/// Head length (including the `count` byte) for a variant, or `None` for an
/// unknown variant.
pub const fn head_len(variant: u8) -> Option<usize> {
    if is_allowance(variant) {
        Some(PERMIT2_ALLOWANCE_HEAD_LEN)
    } else if variant == PERMIT2_VARIANT_TRANSFER || variant == PERMIT2_VARIANT_BATCH_TRANSFER {
        Some(PERMIT2_TRANSFER_HEAD_LEN)
    } else {
        None
    }
}

/// Whether `count` is allowed for `variant`: exactly 1 for the single
/// variants, `1..=PERMIT2_MAX_TOKENS` for the batches.
pub const fn count_ok(variant: u8, count: u8) -> bool {
    if is_batch(variant) {
        count >= 1 && (count as usize) <= PERMIT2_MAX_TOKENS
    } else {
        count == 1
    }
}

/// The exact core length announced by the first `head_len` bytes, or the
/// framing error. Used by the frame parser to find where the bundle
/// sections begin.
pub fn core_len(buf: &[u8]) -> Result<usize, Permit2DecodeError> {
    let variant = *buf.first().ok_or(Permit2DecodeError::BadVariant)?;
    let head = head_len(variant).ok_or(Permit2DecodeError::BadVariant)?;
    let count = *buf.get(head - 1).ok_or(Permit2DecodeError::BadLength)?;
    if !count_ok(variant, count) {
        return Err(Permit2DecodeError::BadCount);
    }
    Ok(head + usize::from(count) * PERMIT2_ENTRY_LEN)
}

fn widen<const N: usize>(src: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - N..].copy_from_slice(&src[..N]);
    w
}

fn be_u48(src: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    b[2..].copy_from_slice(&src[..6]);
    u64::from_be_bytes(b)
}

/// Decode an exact packed permit (see the module docs for the layout).
pub fn decode_core(core: &[u8]) -> Result<Permit2Core, Permit2DecodeError> {
    let len = core_len(core)?;
    if core.len() != len {
        return Err(Permit2DecodeError::BadLength);
    }
    let variant = core[0];
    let allowance = is_allowance(variant);

    let mut chain = [0u8; 8];
    chain.copy_from_slice(&core[1..9]);
    let chain_id = u64::from_be_bytes(chain);
    let mut spender = [0u8; 20];
    spender.copy_from_slice(&core[9..29]);

    let mut deadline = [0u8; 32];
    let mut nonce = [0u8; 32];
    let head = if allowance {
        deadline.copy_from_slice(&core[29..61]);
        PERMIT2_ALLOWANCE_HEAD_LEN
    } else {
        nonce.copy_from_slice(&core[29..61]);
        deadline.copy_from_slice(&core[61..93]);
        PERMIT2_TRANSFER_HEAD_LEN
    };
    let count = core[head - 1];

    if spender == [0u8; 20] {
        return Err(Permit2DecodeError::ZeroSpender);
    }

    let mut entries = [ZERO_ENTRY; PERMIT2_MAX_TOKENS];
    let mut i = 0;
    while i < usize::from(count) {
        let e = &core[head + i * PERMIT2_ENTRY_LEN..head + (i + 1) * PERMIT2_ENTRY_LEN];
        let mut token = [0u8; 20];
        token.copy_from_slice(&e[..20]);
        if token == [0u8; 20] {
            return Err(Permit2DecodeError::ZeroToken);
        }
        entries[i] = if allowance {
            Permit2Entry {
                token,
                amount: widen::<20>(&e[20..40]),
                expiration: be_u48(&e[40..46]),
                nonce: be_u48(&e[46..52]),
            }
        } else {
            Permit2Entry {
                token,
                amount: widen::<32>(&e[20..52]),
                expiration: 0,
                nonce: 0,
            }
        };
        let mut j = 0;
        while j < i {
            if entries[j].token == token {
                return Err(Permit2DecodeError::DuplicateToken);
            }
            j += 1;
        }
        i += 1;
    }

    Ok(Permit2Core {
        variant,
        chain_id,
        spender,
        deadline,
        nonce,
        count,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn allowance(variant: u8, tokens: &[[u8; 20]]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(variant);
        v.extend_from_slice(&8453u64.to_be_bytes());
        v.extend_from_slice(&[0x5a; 20]);
        v.extend_from_slice(&[0x11; 32]);
        v.push(tokens.len() as u8);
        for t in tokens {
            v.extend_from_slice(t);
            v.extend_from_slice(&[0xff; 20]);
            v.extend_from_slice(&[0, 0, 0, 0, 1, 2]);
            v.extend_from_slice(&[0, 0, 0, 0, 0, 7]);
        }
        v
    }

    fn transfer(variant: u8, tokens: &[[u8; 20]]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(variant);
        v.extend_from_slice(&1u64.to_be_bytes());
        v.extend_from_slice(&[0x5a; 20]);
        v.extend_from_slice(&[0x22; 32]);
        v.extend_from_slice(&[0x33; 32]);
        v.push(tokens.len() as u8);
        for t in tokens {
            v.extend_from_slice(t);
            v.extend_from_slice(&[0xee; 32]);
        }
        v
    }

    #[test]
    fn single_allowance_decodes_and_widens() {
        let c = decode_core(&allowance(PERMIT2_VARIANT_SINGLE, &[[0xaa; 20]])).unwrap();
        assert_eq!(c.chain_id, 8453);
        assert_eq!(c.spender, [0x5a; 20]);
        assert_eq!(c.deadline, [0x11; 32]);
        assert_eq!(c.nonce, [0; 32]);
        assert_eq!(c.count, 1);
        let e = c.entries[0];
        assert_eq!(e.amount[..12], [0; 12]);
        assert_eq!(e.amount[12..], [0xff; 20]);
        assert_eq!((e.expiration, e.nonce), (0x0102, 7));
        assert_eq!(c.entries[1], ZERO_ENTRY);
    }

    #[test]
    fn transfer_decodes_nonce_and_deadline() {
        let c = decode_core(&transfer(PERMIT2_VARIANT_BATCH_TRANSFER, &[[0xaa; 20], [0xbb; 20]]))
            .unwrap();
        assert_eq!(c.nonce, [0x22; 32]);
        assert_eq!(c.deadline, [0x33; 32]);
        assert_eq!(c.live().len(), 2);
        assert_eq!(c.entries[1].amount, [0xee; 32]);
        assert_eq!((c.entries[1].expiration, c.entries[1].nonce), (0, 0));
    }

    #[test]
    fn refusals() {
        use Permit2DecodeError::*;
        assert_eq!(decode_core(&[]), Err(BadVariant));
        let mut v = allowance(PERMIT2_VARIANT_SINGLE, &[[0xaa; 20]]);
        v[0] = 4;
        assert_eq!(decode_core(&v), Err(BadVariant));
        // a single variant with two entries
        let mut v = allowance(PERMIT2_VARIANT_SINGLE, &[[0xaa; 20], [0xbb; 20]]);
        assert_eq!(decode_core(&v), Err(BadCount));
        v[0] = PERMIT2_VARIANT_BATCH;
        assert!(decode_core(&v).is_ok());
        // empty and over-full batches
        assert_eq!(decode_core(&allowance(PERMIT2_VARIANT_BATCH, &[])), Err(BadCount));
        let seven: Vec<[u8; 20]> = (1..=7u8).map(|i| [i; 20]).collect();
        assert_eq!(decode_core(&transfer(PERMIT2_VARIANT_BATCH_TRANSFER, &seven)), Err(BadCount));
        assert!(decode_core(&transfer(PERMIT2_VARIANT_BATCH_TRANSFER, &seven[..6])).is_ok());
        // trailing and missing bytes
        let mut v = transfer(PERMIT2_VARIANT_TRANSFER, &[[0xaa; 20]]);
        v.push(0);
        assert_eq!(decode_core(&v), Err(BadLength));
        v.truncate(v.len() - 2);
        assert_eq!(decode_core(&v), Err(BadLength));
        // zero spender / token, duplicate token
        let mut v = allowance(PERMIT2_VARIANT_SINGLE, &[[0xaa; 20]]);
        v[9..29].fill(0);
        assert_eq!(decode_core(&v), Err(ZeroSpender));
        assert_eq!(decode_core(&allowance(PERMIT2_VARIANT_SINGLE, &[[0; 20]])), Err(ZeroToken));
        assert_eq!(
            decode_core(&allowance(PERMIT2_VARIANT_BATCH, &[[0xaa; 20], [0xbb; 20], [0xaa; 20]])),
            Err(DuplicateToken)
        );
    }

    #[test]
    fn core_len_matches_layout() {
        assert_eq!(core_len(&allowance(PERMIT2_VARIANT_SINGLE, &[[1; 20]])), Ok(114));
        assert_eq!(core_len(&transfer(PERMIT2_VARIANT_TRANSFER, &[[1; 20]])), Ok(146));
        assert_eq!(core_len(&[PERMIT2_VARIANT_TRANSFER; 3]), Err(Permit2DecodeError::BadLength));
    }
}

// ---------------------------------------------------------------------------
// Bounded verification (Kani)
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod verification {
    use super::*;

    /// Largest input the harnesses explore: a two-entry transfer core. The
    /// unwind bound covers the 32-byte word comparisons (`memcmp`).
    const N: usize = PERMIT2_TRANSFER_HEAD_LEN + 2 * PERMIT2_ENTRY_LEN;

    /// Panic / overflow / slice-OOB freedom over every input up to `N` bytes.
    #[kani::proof]
    #[kani::unwind(34)]
    fn decode_core_panic_free() {
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let _ = decode_core(&data[..len]);
    }

    /// Decode-soundness: on accept, the input is exactly `head + count * 52`
    /// bytes, the count is in the variant's range, every field is the
    /// verbatim bytes at its offset, each widened amount word carries only
    /// zero bytes above its Solidity width, and spender and tokens are
    /// non-zero.
    #[kani::proof]
    #[kani::unwind(34)]
    fn decode_core_soundness() {
        let data: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let input = &data[..len];
        if let Ok(c) = decode_core(input) {
            let head = head_len(input[0]).unwrap();
            assert!(count_ok(input[0], c.count));
            assert!(len == head + usize::from(c.count) * PERMIT2_ENTRY_LEN);
            assert!(c.variant == input[0] && c.count == input[head - 1]);
            assert!(c.spender[..] == input[9..29] && c.spender != [0u8; 20]);
            let mut chain = [0u8; 8];
            chain.copy_from_slice(&input[1..9]);
            assert!(c.chain_id == u64::from_be_bytes(chain));
            let allowance = c.is_allowance();
            if allowance {
                assert!(c.deadline[..] == input[29..61] && c.nonce == [0u8; 32]);
            } else {
                assert!(c.nonce[..] == input[29..61] && c.deadline[..] == input[61..93]);
            }
            let k: usize = kani::any();
            kani::assume(k < usize::from(c.count));
            let e = &input[head + k * PERMIT2_ENTRY_LEN..head + (k + 1) * PERMIT2_ENTRY_LEN];
            let en = c.entries[k];
            assert!(en.token[..] == e[..20] && en.token != [0u8; 20]);
            if allowance {
                assert!(en.amount[..12] == [0u8; 12] && en.amount[12..] == e[20..40]);
                assert!(en.expiration < (1 << 48) && en.nonce < (1 << 48));
            } else {
                assert!(en.amount[..] == e[20..52]);
            }
        }
    }

    /// On accept, the live tokens are pairwise distinct.
    #[kani::proof]
    #[kani::unwind(34)]
    fn decode_core_rejects_duplicates() {
        let data: [u8; N] = kani::any();
        if let Ok(c) = decode_core(&data) {
            if c.count == 2 {
                assert!(c.entries[0].token != c.entries[1].token);
            }
        }
    }

    /// Non-vacuity: a concrete two-token batch transfer is accepted.
    #[kani::proof]
    #[kani::unwind(34)]
    fn decode_core_accepts_concrete() {
        let mut buf = [0u8; N];
        buf[0] = PERMIT2_VARIANT_BATCH_TRANSFER;
        buf[9] = 0x5a;
        buf[93] = 2;
        buf[94] = 0xaa;
        buf[94 + PERMIT2_ENTRY_LEN] = 0xbb;
        match decode_core(&buf) {
            Ok(c) => assert!(c.count == 2 && c.entries[1].token[0] == 0xbb),
            Err(_) => panic!("a well-formed two-token batch must decode"),
        }
    }
}

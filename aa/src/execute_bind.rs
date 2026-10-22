//! Strict decoder for the single-call `executeWithOffchainCount(...)`
//! calldata, used to bind what a handler is about to sign back to what
//! it showed the user (#846).
//!
//! `reconstruct_execute_calldata` copies the inner call's `data` out of a
//! shared snapshot buffer into a private [`ExecuteCallData`]; everything
//! signed afterwards is derived from that private copy. Decoding the
//! private copy and comparing it with a commitment taken before the
//! confirm dialog therefore checks the bytes that are actually signed,
//! not a second read of the shared buffer.
//!
//! The decoder accepts exactly the canonical encoding that
//! `reconstruct_execute_calldata` emits and nothing else: fixed selector,
//! `u64` owner index and count in their words, a left-padded address, the
//! constant `0xa0` tail offset, a length that accounts for every
//! remaining byte, and zero padding. A second, looser parser here would
//! be a place for the two to disagree.
//!
//! [`ExecuteCallData`]: crate::userop::ExecuteCallData

use crate::userop::{EXECUTE_SELECTOR, MAX_EXECUTE_CALLDATA_LEN};
use pqsigner_tx_core::erc8213::calldata_digest;

const WORD: usize = 32;
const SELECTOR_LEN: usize = 4;
/// `ownerIndex`, `newOffchainCount`, `target`, `value`, tail offset.
const HEAD_WORDS: usize = 5;
/// Selector, the five head words and the `bytes` length word.
const FIXED_LEN: usize = SELECTOR_LEN + (HEAD_WORDS + 1) * WORD;
/// Offset of the `bytes` tail from the start of the arguments: 5 * 32.
const TAIL_OFFSET: u8 = 0xa0;

/// The fields of one canonical `executeWithOffchainCount` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecuteCallFields<'a> {
    pub owner_index: u64,
    pub offchain_count: u64,
    pub target: [u8; 20],
    pub value: [u8; 32],
    pub data: &'a [u8],
}

fn u64_word(word: &[u8]) -> Option<u64> {
    if word.len() != WORD || word[..WORD - 8].iter().any(|b| *b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&word[WORD - 8..]);
    Some(u64::from_be_bytes(low))
}

/// Decode canonical `executeWithOffchainCount` calldata. `None` for any
/// deviation from the encoding `reconstruct_execute_calldata` produces.
#[must_use]
pub fn decode_execute_calldata(calldata: &[u8]) -> Option<ExecuteCallFields<'_>> {
    if calldata.len() < FIXED_LEN || calldata.len() > MAX_EXECUTE_CALLDATA_LEN {
        return None;
    }
    if calldata[..SELECTOR_LEN] != EXECUTE_SELECTOR {
        return None;
    }
    let word = |i: usize| &calldata[SELECTOR_LEN + i * WORD..SELECTOR_LEN + (i + 1) * WORD];

    let owner_index = u64_word(word(0))?;
    let offchain_count = u64_word(word(1))?;

    let target_word = word(2);
    if target_word[..WORD - 20].iter().any(|b| *b != 0) {
        return None;
    }
    let mut target = [0u8; 20];
    target.copy_from_slice(&target_word[WORD - 20..]);

    let mut value = [0u8; 32];
    value.copy_from_slice(word(3));

    let offset_word = word(4);
    if offset_word[..WORD - 1].iter().any(|b| *b != 0) || offset_word[WORD - 1] != TAIL_OFFSET {
        return None;
    }

    let data_len = usize::try_from(u64_word(word(5))?).ok()?;
    // The encoder refuses `data` over the protocol cap, so the canonical
    // encoding never carries more (the buffer bound alone leaves 31 B slack).
    if data_len > pqsigner_proto::MAX_TX_LEN {
        return None;
    }
    let padded_len = data_len.checked_add(WORD - 1)? & !(WORD - 1);
    if calldata.len() != FIXED_LEN.checked_add(padded_len)? {
        return None;
    }
    let data = &calldata[FIXED_LEN..FIXED_LEN + data_len];
    if calldata[FIXED_LEN + data_len..].iter().any(|b| *b != 0) {
        return None;
    }

    Some(ExecuteCallFields { owner_index, offchain_count, target, value, data })
}

/// `true` only when `calldata` is the canonical encoding of exactly this
/// owner index, off-chain count, target and value, and its `data` has the
/// ERC-8213 calldata digest `data_digest`.
///
/// All inputs are public, so the comparison is not constant-time. The
/// caller is expected to route the result through its fault-injection
/// sentinel idiom; this function only decides.
#[must_use]
pub fn execute_calldata_binds(
    calldata: &[u8],
    owner_index: u64,
    offchain_count: u64,
    target: &[u8; 20],
    value: &[u8; 32],
    data_digest: &[u8; 32],
) -> bool {
    let Some(fields) = decode_execute_calldata(calldata) else {
        return false;
    };
    let head = fields.owner_index == owner_index
        && fields.offchain_count == offchain_count
        && fields.target == *target
        && fields.value == *value;
    let data = calldata_digest(fields.data) == *data_digest;
    head & data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userop::reconstruct_execute_calldata;
    use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};

    const TARGET: [u8; 20] = [0xA1; 20];

    fn tx(value_tag: u8) -> Eip1559Tx {
        let mut value = [0u8; 32];
        value[31] = value_tag;
        Eip1559Tx { to: Some(TARGET), value: U256(value), ..Eip1559Tx::default() }
    }

    fn encode(owner: u64, count: u64, value_tag: u8, data: &[u8]) -> ([u8; MAX_EXECUTE_CALLDATA_LEN], usize) {
        let c = reconstruct_execute_calldata(owner, count, &tx(value_tag), data).expect("encodes");
        (c.buf, c.len)
    }

    fn pattern(len: usize) -> [u8; pqsigner_proto::MAX_TX_LEN] {
        let mut d = [0u8; pqsigner_proto::MAX_TX_LEN];
        for (i, b) in d.iter_mut().enumerate().take(len) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        d
    }

    #[test]
    fn decodes_exactly_what_the_encoder_wrote() {
        for len in [0usize, 1, 4, 31, 32, 33, 68, 100, 4095, 4096, 4097, 5050, 8191, 8192] {
            let d = pattern(len);
            let (buf, n) = encode(3, 9, 5, &d[..len]);
            let f = decode_execute_calldata(&buf[..n]).expect("canonical encoding decodes");
            assert_eq!(f.owner_index, 3);
            assert_eq!(f.offchain_count, 9);
            assert_eq!(f.target, TARGET);
            assert_eq!(f.value, tx(5).value.0);
            assert_eq!(f.data, &d[..len], "data length {len}");
        }
    }

    /// A canonically shaped encoding whose `data` is one byte over the
    /// protocol cap (it still fits the buffer's padding slack) is refused.
    #[test]
    fn data_over_max_tx_len_is_not_canonical() {
        let len = pqsigner_proto::MAX_TX_LEN + 1;
        let padded = (len + 31) & !31;
        let n = FIXED_LEN + padded;
        assert!(n <= MAX_EXECUTE_CALLDATA_LEN, "the case must fit the buffer to be meaningful");
        let (head, _) = encode(3, 9, 5, &[]);
        let mut buf = [0u8; MAX_EXECUTE_CALLDATA_LEN];
        buf[..FIXED_LEN].copy_from_slice(&head[..FIXED_LEN]);
        buf[FIXED_LEN - 8..FIXED_LEN].copy_from_slice(&(len as u64).to_be_bytes());
        buf[FIXED_LEN..FIXED_LEN + len].fill(0x42);
        assert!(decode_execute_calldata(&buf[..n]).is_none());
        // Control: the same construction at the cap decodes.
        let len = pqsigner_proto::MAX_TX_LEN;
        buf[FIXED_LEN - 8..FIXED_LEN].copy_from_slice(&(len as u64).to_be_bytes());
        buf[FIXED_LEN + len..].fill(0);
        assert!(decode_execute_calldata(&buf[..FIXED_LEN + len]).is_some());
    }

    #[test]
    fn honest_encoding_binds() {
        let d = pattern(68);
        let (buf, n) = encode(2, 7, 1, &d[..68]);
        let digest = calldata_digest(&d[..68]);
        assert!(execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &tx(1).value.0, &digest));
    }

    /// The #846 case: same length, same target, same value, different data.
    #[test]
    fn swapped_data_of_the_same_length_does_not_bind() {
        let shown = pattern(68);
        let mut signed = shown;
        signed[40] ^= 0x01;
        let (buf, n) = encode(2, 7, 1, &signed[..68]);
        let shown_digest = calldata_digest(&shown[..68]);
        assert!(!execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &tx(1).value.0, &shown_digest));
        // Control: the same buffer does bind to its own digest, so the
        // refusal above is the data comparison and not a decode failure.
        let signed_digest = calldata_digest(&signed[..68]);
        assert!(execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &tx(1).value.0, &signed_digest));
    }

    #[test]
    fn every_single_byte_change_in_the_encoding_is_refused() {
        let d = pattern(37);
        let (buf, n) = encode(2, 7, 1, &d[..37]);
        let digest = calldata_digest(&d[..37]);
        let value = tx(1).value.0;
        for i in 0..n {
            let mut m = buf;
            m[i] ^= 0x01;
            assert!(
                !execute_calldata_binds(&m[..n], 2, 7, &TARGET, &value, &digest),
                "a flipped bit at byte {i} must not bind"
            );
        }
    }

    #[test]
    fn wrong_head_fields_do_not_bind() {
        let d = pattern(8);
        let (buf, n) = encode(2, 7, 1, &d[..8]);
        let digest = calldata_digest(&d[..8]);
        let value = tx(1).value.0;
        assert!(execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &value, &digest));
        assert!(!execute_calldata_binds(&buf[..n], 3, 7, &TARGET, &value, &digest));
        assert!(!execute_calldata_binds(&buf[..n], 2, 8, &TARGET, &value, &digest));
        assert!(!execute_calldata_binds(&buf[..n], 2, 7, &[0xA2; 20], &value, &digest));
        assert!(!execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &tx(2).value.0, &digest));
    }

    #[test]
    fn changed_length_word_is_refused() {
        let d = pattern(40);
        let (mut buf, n) = encode(2, 7, 1, &d[..40]);
        // Length word is head word 5; claim one byte fewer and one more.
        let len_lsb = SELECTOR_LEN + 5 * WORD + WORD - 1;
        buf[len_lsb] = 39;
        assert!(decode_execute_calldata(&buf[..n]).is_none(), "shorter length exposes a non-zero pad byte");
        buf[len_lsb] = 41;
        assert!(decode_execute_calldata(&buf[..n]).is_some(), "41 still fits the same padded tail");
        assert!(!execute_calldata_binds(&buf[..n], 2, 7, &TARGET, &tx(1).value.0, &calldata_digest(&d[..40])));
        buf[len_lsb] = 96;
        assert!(decode_execute_calldata(&buf[..n]).is_none(), "length past the buffer");
    }

    #[test]
    fn changed_offset_word_is_refused() {
        let d = pattern(8);
        let (mut buf, n) = encode(2, 7, 1, &d[..8]);
        let off_lsb = SELECTOR_LEN + 4 * WORD + WORD - 1;
        buf[off_lsb] = 0xc0;
        assert!(decode_execute_calldata(&buf[..n]).is_none());
        buf[off_lsb] = TAIL_OFFSET;
        buf[off_lsb - 1] = 0x01;
        assert!(decode_execute_calldata(&buf[..n]).is_none());
    }

    #[test]
    fn truncated_extended_and_foreign_inputs_are_refused() {
        let d = pattern(8);
        let (buf, n) = encode(2, 7, 1, &d[..8]);
        assert!(decode_execute_calldata(&buf[..n - 1]).is_none());
        assert!(decode_execute_calldata(&buf[..n + 32]).is_none(), "trailing word");
        assert!(decode_execute_calldata(&buf[..FIXED_LEN - 1]).is_none());
        assert!(decode_execute_calldata(&[]).is_none());
        let mut other = buf;
        other[0] ^= 0xFF;
        assert!(decode_execute_calldata(&other[..n]).is_none(), "wrong selector");
        let mut dirty_addr = buf;
        dirty_addr[SELECTOR_LEN + 2 * WORD] = 1;
        assert!(decode_execute_calldata(&dirty_addr[..n]).is_none(), "address high bytes");
        let mut big_owner = buf;
        big_owner[SELECTOR_LEN] = 1;
        assert!(decode_execute_calldata(&big_owner[..n]).is_none(), "owner index above u64");
    }
}

//! Pure-logic ABI decoder for Safe v1.3.0+ `execTransaction(...)` calldata.
//!
//! Companion to [`super::mgmt_decode`] but for the *outer* Safe call rather
//! than the inner singleton-management ops: when the wallet's UserOp directly
//! invokes `execTransaction` on a Safe (i.e. the wallet is the
//! EOA-equivalent that triggers execution after collecting other owners'
//! approvals via the `signatures` argument), all SafeTx fields except `nonce`
//! are encoded straight into the calldata. There is no opaque digest to
//! re-derive, so unlike the [`approveHash`](`super::verify`) path this
//! module decodes directly out of `inner_data` without needing a separate
//! `safe_v1` trailer.
//!
//! ## Hardening rules
//!
//! * **Selector check** — `cd[..4] == EXEC_TRANSACTION_SELECTOR`.
//! * **Strict head length** — at least 4 + 10×32 + 2×32 bytes (selector +
//!   10 head words + the two dynamic-length words). Anything shorter is
//!   refused outright; on-chain Solidity would also revert.
//! * **Address-word canonicalness** — `to`, `gasToken`, `refundReceiver`
//!   must each be encoded as `[12 zero bytes || 20-byte address]`. The
//!   Solidity ABI accepts non-canonical zero-extension on input, but the
//!   firmware enforces canonical form so the on-device display can never
//!   disagree with the on-chain interpretation.
//! * **Operation gate** — `operation ∈ {0, 1}`. Anything else is a
//!   protocol-level error.
//! * **Dynamic-tail framing** — both `data_offset` and `signatures_offset`
//!   must point inside the head region, their length words must fit, and
//!   `offset + 32 + len` must not exceed the supplied calldata. No panics
//!   on any input.
//!
//! The decoder borrows `data` and `signatures` from the supplied slice;
//! callers must keep the input alive for the render lifetime (the
//! TOCTOU-snapshot buffer in `cmd_sign_userop` already does).

use sphincs_tz_shared::{EXEC_TRANSACTION_MIN_CALLDATA_LEN, EXEC_TRANSACTION_SELECTOR};

use super::Eip712Error;

/// Decoded `execTransaction` arguments. `data` and `signatures` borrow
/// from the input calldata; everything else is owned by value so the
/// struct is `Copy`-friendly except for those two slice fields.
#[derive(Clone, Copy, Debug)]
pub struct DecodedExec<'a> {
    pub to: [u8; 20],
    pub value: [u8; 32],
    /// `0` = `Call`, `1` = `DelegateCall`. Already range-checked.
    pub operation: u8,
    pub safe_tx_gas: [u8; 32],
    pub base_gas: [u8; 32],
    pub gas_price: [u8; 32],
    pub gas_token: [u8; 20],
    pub refund_receiver: [u8; 20],
    pub data: &'a [u8],
    pub signatures: &'a [u8],
}

/// Decode a 32-byte ABI word interpreted as a canonical `address`:
/// top 12 bytes MUST be zero, low 20 bytes are the address.
fn read_address_word_off(word: &[u8; 32]) -> Result<[u8; 20], Eip712Error> {
    if word[..12].iter().any(|&b| b != 0) {
        return Err(Eip712Error::NonCanonicalAddress);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&word[12..32]);
    Ok(a)
}

/// Decode a 32-byte ABI word as a `usize` (representing an offset or
/// length). Bits above 32 must be zero — offsets / lengths fit in u32 by
/// construction (calldata length is u16-bounded upstream anyway).
fn read_offset_word_off(word: &[u8; 32]) -> Result<usize, Eip712Error> {
    if word[..28].iter().any(|&b| b != 0) {
        return Err(Eip712Error::OffsetOverflow);
    }
    Ok(u32::from_be_bytes([word[28], word[29], word[30], word[31]]) as usize)
}

/// Parse `execTransaction(...)` calldata into structured fields.
///
/// Returns the decoded struct on success, or a specific `Eip712Error` on
/// any of the hardening-rule violations. Callers in the firmware drop
/// the trailer to "refuse to sign" on `Err`; tests can assert the exact
/// variant.
pub fn decode_exec_transaction(cd: &[u8]) -> Result<DecodedExec<'_>, Eip712Error> {
    // Minimum-length / selector gate.
    if cd.len() < EXEC_TRANSACTION_MIN_CALLDATA_LEN {
        return Err(Eip712Error::ShortInput);
    }
    if cd[..4] != EXEC_TRANSACTION_SELECTOR {
        return Err(Eip712Error::WrongSelector);
    }

    // The head starts immediately after the selector. All offsets in the
    // ABI encoding are measured from the start of this head region.
    let head = &cd[4..];

    // Helper that pulls a fixed-size word out of `head` by word index
    // (0..=9). Bounded by the `cd.len() >= MIN_CALLDATA_LEN` check above.
    let word_at = |idx: usize| -> &[u8; 32] {
        let off = idx * 32;
        let s: &[u8; 32] = head[off..off + 32].try_into().expect("word slice");
        s
    };

    // 10 head words = 320 bytes. We checked `cd.len() >= MIN_CALLDATA_LEN`
    // (selector + 10*32 + 2*32) so `head[..320]` always exists.
    let to = read_address_word_off(word_at(0))?;
    let value: [u8; 32] = *word_at(1);
    let data_off_w = *word_at(2);
    let operation_w = word_at(3);
    let safe_tx_gas: [u8; 32] = *word_at(4);
    let base_gas: [u8; 32] = *word_at(5);
    let gas_price: [u8; 32] = *word_at(6);
    let gas_token = read_address_word_off(word_at(7))?;
    let refund_receiver = read_address_word_off(word_at(8))?;
    let sigs_off_w = *word_at(9);

    // Operation = uint8 left-padded to 32. Top 31 bytes must be zero.
    if operation_w[..31].iter().any(|&b| b != 0) {
        return Err(Eip712Error::EnumOutOfRange);
    }
    let operation = operation_w[31];
    if operation > 1 {
        return Err(Eip712Error::EnumOutOfRange);
    }

    let data_off = read_offset_word_off(&data_off_w)?;
    let sigs_off = read_offset_word_off(&sigs_off_w)?;

    // Each tail starts with a u256 length, followed by the bytes. The
    // tails MUST sit after the 320-byte head; that's the canonical
    // encoding Solidity produces. Pathologically-formed calldata could
    // point earlier, which we refuse — the on-device display would
    // otherwise show whatever bytes were before the head.
    let data = read_dynamic_bytes(head, data_off)?;
    let signatures = read_dynamic_bytes(head, sigs_off)?;

    Ok(DecodedExec {
        to,
        value,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        data,
        signatures,
    })
}

/// Read a dynamic `bytes` argument out of `head` at the given offset.
/// The 32 bytes at `head[offset..offset+32]` are the length; the payload
/// follows. The function returns `Err` if the offset / length addresses
/// any byte outside `head`.
fn read_dynamic_bytes(head: &[u8], offset: usize) -> Result<&[u8], Eip712Error> {
    // Tail must start after the 320-byte head (10 words × 32). Solidity
    // encodes it that way; refusing earlier offsets prevents an attacker
    // from pointing the bytes argument back into the head and confusing
    // the renderer.
    if offset < 10 * 32 {
        return Err(Eip712Error::OffsetOverflow);
    }
    if offset.checked_add(32).map_or(true, |end| end > head.len()) {
        return Err(Eip712Error::TruncatedDynamic);
    }
    let len_word: &[u8; 32] = head[offset..offset + 32]
        .try_into()
        .expect("length word slice");
    let len = read_offset_word_off(len_word)?;
    let payload_start = offset + 32;
    let payload_end = payload_start
        .checked_add(len)
        .ok_or(Eip712Error::OffsetOverflow)?;
    if payload_end > head.len() {
        return Err(Eip712Error::TruncatedDynamic);
    }
    Ok(&head[payload_start..payload_end])
}

// ---------------------------------------------------------------------------
// Top-level verifier
// ---------------------------------------------------------------------------

/// A successfully-decoded `execTransaction` UserOp that the renderer can
/// trust.
///
/// Mirrors the role of `VerifiedSafeV1` in the approveHash path: a small
/// owned + borrowed struct that survives until the trusted-UI render
/// completes. The borrow is from the gateway's TOCTOU snapshot buffer.
///
/// `chain_id` and `safe_address` are taken from the outer UserOp header
/// — they are the binding facts for the renderer, and the firmware has
/// already verified them as part of its standard UserOp flow.
pub struct VerifiedSafeExec<'a> {
    pub chain_id: u64,
    pub safe_address: [u8; 20],
    pub decoded: DecodedExec<'a>,
}

/// End-to-end verification + bind of an `execTransaction` UserOp.
///
/// Returns `None` on selector mismatch, decode failure, or
/// `operation == 1` (DelegateCall — refused for the same reason as in
/// the approveHash path: DelegateCall replaces the Safe's code for the
/// duration of the call, so a non-expert user cannot meaningfully
/// confirm the inner action).
pub fn verify_and_bind_exec<'a>(
    inner_data: &'a [u8],
    chain_id: u64,
    userop_to: &[u8; 20],
) -> Option<VerifiedSafeExec<'a>> {
    let decoded = decode_exec_transaction(inner_data).ok()?;
    if decoded.operation != 0 {
        // Operation gate — DelegateCall (1) is structurally clear-sign-
        // unfriendly and refused here. `decode_exec_transaction` already
        // refuses values > 1.
        return None;
    }
    Some(VerifiedSafeExec {
        chain_id,
        safe_address: *userop_to,
        decoded,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// Build a syntactically-correct `execTransaction` calldata for the
    /// supplied fields. Tail layout = `data` then `signatures`, each
    /// 32-byte-padded. Returns the encoded bytes.
    fn encode_exec(
        to: [u8; 20],
        value: [u8; 32],
        data: &[u8],
        operation: u8,
        safe_tx_gas: [u8; 32],
        base_gas: [u8; 32],
        gas_price: [u8; 32],
        gas_token: [u8; 20],
        refund_receiver: [u8; 20],
        signatures: &[u8],
    ) -> Vec<u8> {
        let head_len = 10 * 32;
        let data_padded = ((data.len() + 31) / 32) * 32;
        let sigs_padded = ((signatures.len() + 31) / 32) * 32;
        let data_off = head_len; // first tail entry
        let sigs_off = head_len + 32 + data_padded;
        let total = 4 + head_len + 32 + data_padded + 32 + sigs_padded;
        let mut cd = alloc::vec![0u8; total];
        cd[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);

        let head = &mut cd[4..];
        let word_off = |i: usize| i * 32;
        // word 0: to (left-padded address: low 20 bytes of the 32-byte word)
        head[word_off(0) + 12..word_off(0) + 32].copy_from_slice(&to);
        // word 1: value
        head[word_off(1)..word_off(1) + 32].copy_from_slice(&value);
        // word 2: data offset (BE u32 in low 4 bytes)
        head[word_off(2) + 28..word_off(2) + 32].copy_from_slice(&(data_off as u32).to_be_bytes());
        // word 3: operation (uint8 in the low byte)
        head[word_off(3) + 31] = operation;
        // word 4: safe_tx_gas
        head[word_off(4)..word_off(4) + 32].copy_from_slice(&safe_tx_gas);
        // word 5: base_gas
        head[word_off(5)..word_off(5) + 32].copy_from_slice(&base_gas);
        // word 6: gas_price
        head[word_off(6)..word_off(6) + 32].copy_from_slice(&gas_price);
        // word 7: gas_token (left-padded address)
        head[word_off(7) + 12..word_off(7) + 32].copy_from_slice(&gas_token);
        // word 8: refund_receiver (left-padded address)
        head[word_off(8) + 12..word_off(8) + 32].copy_from_slice(&refund_receiver);
        // word 9: signatures offset
        head[word_off(9) + 28..word_off(9) + 32].copy_from_slice(&(sigs_off as u32).to_be_bytes());
        // data tail: length + bytes (padded)
        let data_pos = 4 + head_len;
        cd[data_pos + 28..data_pos + 32].copy_from_slice(&(data.len() as u32).to_be_bytes());
        cd[data_pos + 32..data_pos + 32 + data.len()].copy_from_slice(data);
        // signatures tail
        let sigs_pos = 4 + head_len + 32 + data_padded;
        cd[sigs_pos + 28..sigs_pos + 32].copy_from_slice(&(signatures.len() as u32).to_be_bytes());
        cd[sigs_pos + 32..sigs_pos + 32 + signatures.len()].copy_from_slice(signatures);
        cd
    }

    fn fixture_addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn fixture_u256(low: u8) -> [u8; 32] {
        let mut v = [0u8; 32];
        v[31] = low;
        v
    }

    #[test]
    fn positive_minimal_decodes() {
        let cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        let d = decode_exec_transaction(&cd).expect("decode ok");
        assert_eq!(d.to, fixture_addr(0xAA));
        assert_eq!(d.operation, 0);
        assert!(d.data.is_empty());
        assert!(d.signatures.is_empty());
    }

    #[test]
    fn positive_with_data_and_sigs() {
        let cd = encode_exec(
            fixture_addr(0x12),
            fixture_u256(7),
            &[0xab, 0xcd, 0xef],
            1,
            fixture_u256(0x10),
            fixture_u256(0x20),
            fixture_u256(0x30),
            fixture_addr(0x40),
            fixture_addr(0x50),
            &[0x01, 0x02, 0x03, 0x04, 0x05],
        );
        let d = decode_exec_transaction(&cd).expect("decode ok");
        assert_eq!(d.to, fixture_addr(0x12));
        assert_eq!(d.value, fixture_u256(7));
        assert_eq!(d.operation, 1);
        assert_eq!(d.data, &[0xab, 0xcd, 0xef]);
        assert_eq!(d.signatures, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(d.gas_token, fixture_addr(0x40));
        assert_eq!(d.refund_receiver, fixture_addr(0x50));
    }

    #[test]
    fn negative_wrong_selector_rejected() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        cd[0] ^= 0xFF;
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::WrongSelector
        );
    }

    #[test]
    fn negative_short_input_rejected() {
        let cd = [0u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN - 1];
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::ShortInput
        );
    }

    #[test]
    fn negative_operation_out_of_range() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // word 3 (operation) low byte
        cd[4 + 3 * 32 + 31] = 2;
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::EnumOutOfRange
        );
    }

    #[test]
    fn negative_operation_high_bits_nonzero() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // Set bit in the upper 31 bytes of the operation word.
        cd[4 + 3 * 32] = 1;
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::EnumOutOfRange
        );
    }

    #[test]
    fn negative_non_canonical_address_to() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // dirty the first byte of word 0's zero-padding region
        cd[4] = 1;
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::NonCanonicalAddress
        );
    }

    #[test]
    fn negative_data_offset_into_head_rejected() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // word 2 = data offset; set it to 0 (would point at word 0 of head)
        cd[4 + 2 * 32 + 28..4 + 2 * 32 + 32].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::OffsetOverflow
        );
    }

    #[test]
    fn negative_truncated_dynamic_length() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[1, 2, 3],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // Inflate the data length so the claimed payload runs past the
        // end of the calldata.
        let head = &mut cd[4..];
        let data_off = u32::from_be_bytes([
            head[2 * 32 + 28],
            head[2 * 32 + 29],
            head[2 * 32 + 30],
            head[2 * 32 + 31],
        ]) as usize;
        head[data_off + 28..data_off + 32].copy_from_slice(&100_000u32.to_be_bytes());
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::TruncatedDynamic
        );
    }

    #[test]
    fn negative_offset_high_bits_set() {
        let mut cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        // Set a high byte in the data offset (above u32 range).
        cd[4 + 2 * 32] = 1;
        assert_eq!(
            decode_exec_transaction(&cd).unwrap_err(),
            Eip712Error::OffsetOverflow
        );
    }

    #[test]
    fn verify_and_bind_exec_rejects_delegatecall() {
        let cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[],
            1,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        assert!(verify_and_bind_exec(&cd, 1, &fixture_addr(0xBB)).is_none());
    }

    #[test]
    fn verify_and_bind_exec_call_ok() {
        let cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(0),
            &[0xCA, 0xFE],
            0,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        let v = verify_and_bind_exec(&cd, 1, &fixture_addr(0xBB)).expect("bind");
        assert_eq!(v.chain_id, 1);
        assert_eq!(v.safe_address, fixture_addr(0xBB));
        assert_eq!(v.decoded.to, fixture_addr(0xAA));
        assert_eq!(v.decoded.data, &[0xCA, 0xFE]);
    }
}

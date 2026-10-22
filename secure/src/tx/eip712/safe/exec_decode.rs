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

// Re-exported for the tests below + `super::*` consumers. `pub use`
// keeps them used in the firmware (non-test) build too.
pub use sphincs_tz_shared::{
    EXEC_TRANSACTION_MAX_CALLDATA_LEN, EXEC_TRANSACTION_MIN_CALLDATA_LEN, EXEC_TRANSACTION_SELECTOR,
};

use super::Eip712Error;

/// Decoded `execTransaction` arguments — re-exported from the
/// host-compilable, Kani-verified [`pqsigner_tx::safe_tx`]
/// (panic / OOB-freedom over symbolic offset/length words +
/// fixed-field decode soundness). `data` and `signatures` borrow from
/// the input calldata; everything else is owned by value. Re-exported
/// here so the renderer, the CoW-binding glue, and every test/caller
/// stay byte-identical.
pub use pqsigner_tx::safe_tx::DecodedExec;

/// Map the pure-logic decode error onto the secure-world `Eip712Error`.
/// The variants correspond 1:1 (the decoder's failure modes are a subset
/// of `Eip712Error`), so the wrapper below returns exactly the same
/// variant the inline decoder used to — every test assertion is unchanged.
fn map_exec_err(e: pqsigner_tx::safe_tx::SafeExecDecodeError) -> Eip712Error {
    use pqsigner_tx::safe_tx::SafeExecDecodeError as E;
    match e {
        E::ShortInput => Eip712Error::ShortInput,
        E::WrongSelector => Eip712Error::WrongSelector,
        E::NonCanonicalAddress => Eip712Error::NonCanonicalAddress,
        E::OffsetOverflow => Eip712Error::OffsetOverflow,
        E::EnumOutOfRange => Eip712Error::EnumOutOfRange,
        E::TruncatedDynamic => Eip712Error::TruncatedDynamic,
    }
}

/// Parse `execTransaction(...)` calldata into structured fields.
///
/// Returns the decoded struct on success, or a specific `Eip712Error` on
/// any of the hardening-rule violations (selector / minimum-length /
/// canonical-address / `operation ∈ {0,1}` / dynamic-tail bounds).
/// Callers in the firmware drop the trailer to "refuse to sign" on `Err`;
/// tests assert the exact variant.
///
/// Thin shim over the Kani-verified
/// [`pqsigner_tx::safe_tx::decode_exec_transaction`]; maps its error onto
/// the secure-world [`Eip712Error`] so the signature and every caller
/// stay byte-identical.
pub fn decode_exec_transaction(cd: &[u8]) -> Result<DecodedExec<'_>, Eip712Error> {
    pqsigner_tx::safe_tx::decode_exec_transaction(cd).map_err(map_exec_err)
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
#[derive(Clone, Copy)]
pub struct VerifiedSafeExec<'a> {
    pub chain_id: u64,
    pub safe_address: [u8; 20],
    pub decoded: DecodedExec<'a>,
}

/// End-to-end verification + bind of an `execTransaction` UserOp.
///
/// Returns `None` on selector mismatch, decode failure, or a
/// disallowed `operation == 1` (DelegateCall). DelegateCall is
/// accepted ONLY for an allowlisted `MultiSendCallOnly` batch — same
/// predicate as the approveHash path's operation gate (see
/// [`super::multi_send::is_multisend_claim`]); any other DelegateCall
/// replaces the Safe's code for the duration of the call, so a
/// non-expert user cannot meaningfully confirm the inner action.
#[inline(never)]
pub fn verify_and_bind_exec<'a>(
    inner_data: &'a [u8],
    chain_id: u64,
    userop_to: &[u8; 20],
) -> Option<VerifiedSafeExec<'a>> {
    // Routing policy, not ABI shape: the Safe route keeps its pre-2026-10-22
    // 4096-B input domain (see `EXEC_TRANSACTION_MAX_CALLDATA_LEN`).
    if inner_data.len() > EXEC_TRANSACTION_MAX_CALLDATA_LEN {
        return None;
    }
    let decoded = decode_exec_transaction(inner_data).ok()?;
    if decoded.operation != 0
        && !super::multi_send::is_multisend_claim(decoded.operation, &decoded.to, decoded.data)
    {
        // Operation gate — DelegateCall (1) only for the pinned
        // multiSend shape; the payload's own hard rules run in the
        // handler's verdict gate. `decode_exec_transaction` already
        // refuses values > 1.
        return None;
    }
    Some(VerifiedSafeExec {
        chain_id,
        safe_address: *userop_to,
        decoded,
    })
}

const EXEC_VERIFY_CFI_STEP: u32 = 0xA24F_73C1;
pub(crate) const EXEC_VERIFY_CFI_EXPECTED: u32 = crate::cfi_expected!(EXEC_VERIFY_CFI_STEP);

/// Run the strict verifier into caller-owned, fail-initialized storage.
///
/// The caller must volatile-write `None` into `output` and pass a fresh CFI
/// counter before this non-inlined call. This operation repeats that volatile
/// fail initialization before doing its own strict decode and operation-policy
/// check, then publishes the final `None`/`Some` result directly into the
/// caller's slot. It deliberately does not call either value-returning
/// [`decode_exec_transaction`] or [`verify_and_bind_exec`]: there is no inner
/// decoder/verifier return/sret or local aggregate copy whose skipped
/// publication could be followed by a completed outer CFI receipt. The
/// returning decoder remains the Kani-backed test oracle; bytewise mutation
/// parity tests pin this in-operation decode to it.
///
/// The CFI step is minted only after the final volatile publication. If this
/// whole call is instruction-skipped, the caller's `None` remains and the
/// counter remains short. Callers execute this twice into distinct slots and
/// accept a Safe route only when both complete, equivalent `Some` results
/// agree with the selector receipt.
#[inline(never)]
pub(crate) fn verify_and_bind_exec_into<'a>(
    inner_data: &'a [u8],
    chain_id: u64,
    userop_to: &[u8; 20],
    output: &mut Option<VerifiedSafeExec<'a>>,
    cfi: &mut crate::fi::CfiCounter,
) {
    // Establish the fail state inside the non-inlined strict operation as
    // well as at each production call site. This also overwrites any stale
    // success if a caller ever reuses a slot incorrectly.
    // SAFETY: `output` is a unique caller-owned slot.
    unsafe { core::ptr::write_volatile(output, None) };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    // Complete a strict rejection without returning an aggregate through an
    // inner call. Every reject republishes the final `None`, fences it, and
    // only then mints the same one-step completion receipt as success.
    macro_rules! complete_reject {
        () => {{
            // SAFETY: same unique caller-owned slot.
            unsafe { core::ptr::write_volatile(output, None) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            cfi.bump(EXEC_VERIFY_CFI_STEP);
            return;
        }};
    }

    // Decode the strict ABI shape in this non-inlined operation. These checks
    // intentionally mirror the Kani-backed pure decoder used by
    // `decode_exec_transaction`, but no aggregate crosses a call boundary.
    if inner_data.len() < EXEC_TRANSACTION_MIN_CALLDATA_LEN {
        complete_reject!();
    }
    // Routing policy (same as `verify_and_bind_exec`): the Safe route keeps
    // its pre-2026-10-22 4096-B input domain now that MAX_TX_LEN is 8192.
    // The selector already claimed the Safe route, so this is a refusal.
    if inner_data.len() > EXEC_TRANSACTION_MAX_CALLDATA_LEN {
        complete_reject!();
    }
    if inner_data[..4] != EXEC_TRANSACTION_SELECTOR {
        complete_reject!();
    }
    let head = &inner_data[4..];

    if head[..12].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let mut to = [0u8; 20];
    to.copy_from_slice(&head[12..32]);

    let mut value = [0u8; 32];
    value.copy_from_slice(&head[32..64]);
    if head[64..92].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let data_offset = u32::from_be_bytes([head[92], head[93], head[94], head[95]]) as usize;

    if head[96..127].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let operation = head[127];
    if operation > 1 {
        complete_reject!();
    }

    let mut safe_tx_gas = [0u8; 32];
    safe_tx_gas.copy_from_slice(&head[128..160]);
    let mut base_gas = [0u8; 32];
    base_gas.copy_from_slice(&head[160..192]);
    let mut gas_price = [0u8; 32];
    gas_price.copy_from_slice(&head[192..224]);

    if head[224..236].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let mut gas_token = [0u8; 20];
    gas_token.copy_from_slice(&head[236..256]);

    if head[256..268].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let mut refund_receiver = [0u8; 20];
    refund_receiver.copy_from_slice(&head[268..288]);

    if head[288..316].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let signatures_offset =
        u32::from_be_bytes([head[316], head[317], head[318], head[319]]) as usize;

    if data_offset < 10 * 32 {
        complete_reject!();
    }
    let data_length_word_end = match data_offset.checked_add(32) {
        Some(end) if end <= head.len() => end,
        _ => complete_reject!(),
    };
    let data_length_word = &head[data_offset..data_length_word_end];
    if data_length_word[..28].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let data_length = u32::from_be_bytes([
        data_length_word[28],
        data_length_word[29],
        data_length_word[30],
        data_length_word[31],
    ]) as usize;
    let data_end = match data_length_word_end.checked_add(data_length) {
        Some(end) if end <= head.len() => end,
        _ => complete_reject!(),
    };
    let data = &head[data_length_word_end..data_end];

    if signatures_offset < 10 * 32 {
        complete_reject!();
    }
    let signatures_length_word_end = match signatures_offset.checked_add(32) {
        Some(end) if end <= head.len() => end,
        _ => complete_reject!(),
    };
    let signatures_length_word = &head[signatures_offset..signatures_length_word_end];
    if signatures_length_word[..28].iter().any(|&byte| byte != 0) {
        complete_reject!();
    }
    let signatures_length = u32::from_be_bytes([
        signatures_length_word[28],
        signatures_length_word[29],
        signatures_length_word[30],
        signatures_length_word[31],
    ]) as usize;
    let signatures_end = match signatures_length_word_end.checked_add(signatures_length) {
        Some(end) if end <= head.len() => end,
        _ => complete_reject!(),
    };
    let signatures = &head[signatures_length_word_end..signatures_end];

    if operation != 0 && !super::multi_send::is_multisend_claim(operation, &to, data) {
        complete_reject!();
    }

    // SAFETY: same unique caller-owned slot. Publish the completed successful
    // binding directly; no inner aggregate-returning decoder/verifier exists.
    unsafe {
        core::ptr::write_volatile(
            output,
            Some(VerifiedSafeExec {
                chain_id,
                safe_address: *userop_to,
                decoded: DecodedExec {
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
                },
            }),
        )
    };
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    cfi.bump(EXEC_VERIFY_CFI_STEP);
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
        // DelegateCall to a non-allowlisted target (0xAA..AA is not a
        // MultiSendCallOnly deployment) — refused regardless of payload.
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
    fn verify_and_bind_exec_accepts_allowlisted_multisend_delegatecall() {
        let ms = super::super::multi_send::test_util::cow_flow_calldata();
        let ms_target = sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0];
        let cd = encode_exec(
            ms_target,
            fixture_u256(0),
            &ms,
            1,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        let v = verify_and_bind_exec(&cd, 1, &fixture_addr(0xBB))
            .expect("op=1 to an allowlisted MultiSendCallOnly must pass the operation gate");
        assert_eq!(v.decoded.operation, 1);
        assert_eq!(v.decoded.to, ms_target);
        assert_eq!(v.decoded.data, &ms[..]);
    }

    #[test]
    fn verify_and_bind_exec_rejects_allowlisted_target_without_multisend_payload() {
        let ms_target = sphincs_tz_shared::MULTISEND_CALL_ONLY_ADDRESSES[0];
        let cd = encode_exec(
            ms_target,
            fixture_u256(0),
            &[0xde, 0xad, 0xbe, 0xef],
            1,
            fixture_u256(0),
            fixture_u256(0),
            fixture_u256(0),
            [0u8; 20],
            [0u8; 20],
            &[],
        );
        assert!(
            verify_and_bind_exec(&cd, 1, &fixture_addr(0xBB)).is_none(),
            "DelegateCall with a non-multiSend payload must be rejected even to an allowlisted target"
        );
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

    #[test]
    fn strict_into_valid_completion_publishes_result_and_cfi() {
        let cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(7),
            &[0xCA, 0xFE],
            0,
            fixture_u256(1),
            fixture_u256(2),
            fixture_u256(3),
            fixture_addr(0x40),
            fixture_addr(0x50),
            &[0x01, 0x02],
        );
        let mut output = None;
        let mut cfi = crate::fi::CfiCounter::new();
        unsafe { core::ptr::write_volatile(&mut output, None) };

        verify_and_bind_exec_into(&cd, 1, &fixture_addr(0xBB), &mut output, &mut cfi);

        assert_eq!(
            cfi.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "completed publication must mint exactly one verifier CFI step"
        );
        let verified = output.expect("valid strict operation must publish Some");
        assert_eq!(verified.chain_id, 1);
        assert_eq!(verified.safe_address, fixture_addr(0xBB));
        assert_eq!(verified.decoded.data, &[0xCA, 0xFE]);
        assert_eq!(verified.decoded.signatures, &[0x01, 0x02]);
    }

    /// The Safe route keeps its pre-2026-10-22 4096-B domain although a
    /// UserOp call may now carry 8192 B. Canonical encodings are 388 + 32k
    /// bytes long, so the edge is 4068 (largest accepted) vs 4100.
    #[test]
    fn safe_exec_route_keeps_the_4096_byte_domain() {
        let exec_with_data = |len: usize| {
            encode_exec(
                fixture_addr(0xAA),
                fixture_u256(0),
                &vec![0x5Au8; len],
                0,
                fixture_u256(0),
                fixture_u256(0),
                fixture_u256(0),
                [0u8; 20],
                [0u8; 20],
                &[],
            )
        };
        let strict = |cd: &[u8]| {
            let mut out = None;
            let mut cfi = crate::fi::CfiCounter::new();
            unsafe { core::ptr::write_volatile(&mut out, None) };
            verify_and_bind_exec_into(cd, 1, &fixture_addr(0xBB), &mut out, &mut cfi);
            // A refusal still completes (one CFI step), it just publishes None.
            assert_eq!(cfi.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED), crate::fi::OK_SENTINEL);
            out.is_some()
        };

        let at_edge = exec_with_data(115 * 32);
        assert_eq!(at_edge.len(), 4068);
        assert!(verify_and_bind_exec(&at_edge, 1, &fixture_addr(0xBB)).is_some());
        assert!(strict(&at_edge));

        for len in [115 * 32 + 1, 4096, 7700] {
            let over = exec_with_data(len);
            assert!(over.len() > EXEC_TRANSACTION_MAX_CALLDATA_LEN);
            assert!(over.len() <= sphincs_tz_shared::MAX_TX_LEN);
            // Well-formed (the pure decoder accepts it), so the refusal below
            // is the routing cap and not a decode failure.
            assert!(decode_exec_transaction(&over).is_ok());
            assert!(verify_and_bind_exec(&over, 1, &fixture_addr(0xBB)).is_none(), "len {len}");
            assert!(!strict(&over), "len {len}");
        }
    }

    #[test]
    fn strict_into_matches_returning_oracle_for_every_byte_and_prefix() {
        use super::super::verified_exec_equivalent;

        fn agrees_with_oracle(cd: &[u8]) -> bool {
            let expected = verify_and_bind_exec(cd, 7, &[0xBB; 20]);
            let mut published = None;
            let mut cfi = crate::fi::CfiCounter::new();
            unsafe { core::ptr::write_volatile(&mut published, None) };
            verify_and_bind_exec_into(cd, 7, &[0xBB; 20], &mut published, &mut cfi);
            if cfi.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED) != crate::fi::OK_SENTINEL {
                return false;
            }
            match (expected.as_ref(), published.as_ref()) {
                (None, None) => true,
                (Some(a), Some(b)) => verified_exec_equivalent(a, b),
                _ => false,
            }
        }

        // Non-word-aligned data and signature lengths ensure the sweep covers
        // both dynamic length words, both payloads (including signature
        // contents), and their ABI padding as well as every fixed-head byte.
        let base = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(7),
            &[0xCA, 0xFE, 0x01],
            0,
            fixture_u256(1),
            fixture_u256(2),
            fixture_u256(3),
            fixture_addr(0x40),
            fixture_addr(0x50),
            &[0x10, 0x11, 0x12],
        );
        assert!(agrees_with_oracle(&base), "canonical fixture parity");

        for len in 0..base.len() {
            assert!(
                agrees_with_oracle(&base[..len]),
                "strict decode diverged from oracle at prefix length {len}"
            );
        }
        for index in 0..base.len() {
            let mut mutated = base.clone();
            mutated[index] ^= 1;
            assert!(
                agrees_with_oracle(&mutated),
                "strict decode diverged from oracle at mutated byte {index}"
            );
        }
    }

    #[test]
    fn strict_into_invalid_completion_overwrites_stale_success_and_completes_cfi() {
        let valid_cd = encode_exec(
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
        let invalid_cd = encode_exec(
            fixture_addr(0xCC),
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
        let stale =
            verify_and_bind_exec(&valid_cd, 1, &fixture_addr(0xBB)).expect("valid stale fixture");
        let mut output = Some(stale);
        let mut cfi = crate::fi::CfiCounter::new();

        verify_and_bind_exec_into(&invalid_cd, 1, &fixture_addr(0xBB), &mut output, &mut cfi);

        assert!(
            output.is_none(),
            "a completed strict rejection must overwrite stale Some"
        );
        assert_eq!(
            cfi.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "a completed rejection is a completed strict operation"
        );
    }

    #[test]
    fn skipped_whole_strict_call_leaves_fail_output_and_short_cfi() {
        use super::super::{
            exec_claim_resolution_proof, prove_exec_transaction_claim, ExecClaimReceipt,
            EXEC_CLAIM_CFI_EXPECTED,
        };

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
        let mut receipt = ExecClaimReceipt::fail_closed();
        let mut claim_cfi = crate::fi::CfiCounter::new();
        prove_exec_transaction_claim(&cd, &mut receipt, &mut claim_cfi);
        assert_eq!(
            claim_cfi.check_into_sentinel(EXEC_CLAIM_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );

        let mut output: Option<VerifiedSafeExec<'_>> = None;
        let verify_cfi = crate::fi::CfiCounter::new();
        unsafe { core::ptr::write_volatile(&mut output, None) };
        // Model an instruction skip of the entire non-inlined
        // `verify_and_bind_exec_into` call: deliberately do not invoke it.
        assert!(output.is_none());
        assert_ne!(
            verify_cfi.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED),
            crate::fi::OK_SENTINEL,
            "a skipped whole call must not mint its completion receipt"
        );
        assert_ne!(
            exec_claim_resolution_proof(&receipt, output.as_ref(), output.as_ref()),
            crate::fi::OK_SENTINEL,
            "claimed selector plus skipped strict publication must fail closed"
        );
    }

    #[test]
    fn fi_receipt_requires_two_equivalent_strict_exec_verifications() {
        use super::super::{
            exec_claim_resolution_proof, prove_exec_transaction_claim, ExecClaimReceipt,
            EXEC_CLAIM_CFI_EXPECTED,
        };

        let cd = encode_exec(
            fixture_addr(0xAA),
            fixture_u256(7),
            &[0xCA, 0xFE],
            0,
            fixture_u256(1),
            fixture_u256(2),
            fixture_u256(3),
            fixture_addr(0x40),
            fixture_addr(0x50),
            &[0x01, 0x02],
        );
        let mut receipt = ExecClaimReceipt::fail_closed();
        let mut cfi = crate::fi::CfiCounter::new();
        prove_exec_transaction_claim(&cd, &mut receipt, &mut cfi);
        assert_eq!(
            cfi.check_into_sentinel(EXEC_CLAIM_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );

        let mut verified_a = None;
        let mut verified_b = None;
        let mut verify_cfi_a = crate::fi::CfiCounter::new();
        let mut verify_cfi_b = crate::fi::CfiCounter::new();
        // Mirror the production caller contract: both outputs begin as
        // independently materialized `None`, and each helper call must publish
        // both its result and its own complete CFI receipt.
        unsafe {
            core::ptr::write_volatile(&mut verified_a, None);
            core::ptr::write_volatile(&mut verified_b, None);
        }
        verify_and_bind_exec_into(
            &cd,
            1,
            &fixture_addr(0xBB),
            &mut verified_a,
            &mut verify_cfi_a,
        );
        verify_and_bind_exec_into(
            &cd,
            1,
            &fixture_addr(0xBB),
            &mut verified_b,
            &mut verify_cfi_b,
        );
        assert_eq!(
            verify_cfi_a.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        assert_eq!(
            verify_cfi_b.check_into_sentinel(EXEC_VERIFY_CFI_EXPECTED),
            crate::fi::OK_SENTINEL
        );
        let verified_a = verified_a.expect("first bind publication");
        let verified_b = verified_b.expect("second bind publication");
        assert_eq!(
            exec_claim_resolution_proof(&receipt, Some(&verified_a), Some(&verified_b)),
            crate::fi::OK_SENTINEL
        );
        assert_ne!(
            exec_claim_resolution_proof(&receipt, Some(&verified_a), None),
            crate::fi::OK_SENTINEL,
            "a skipped/disagreeing strict verifier must fail closed"
        );

        let mut disagreeing = verified_b;
        disagreeing.decoded.value[31] ^= 1;
        assert_ne!(
            exec_claim_resolution_proof(&receipt, Some(&verified_a), Some(&disagreeing)),
            crate::fi::OK_SENTINEL,
            "every bound Safe field participates in the pair proof"
        );
    }

    #[test]
    fn fi_receipt_rejects_one_fault_delegatecall_acceptance_and_skipped_classifier() {
        use super::super::{
            exec_claim_resolution_proof, prove_exec_transaction_claim, ExecClaimReceipt,
        };

        // The pure ABI decoder accepts operation=1, while the strict verifier
        // correctly rejects this non-allowlisted DelegateCall. Constructing a
        // `Some` from the decoded fields models one skipped operation-policy
        // reject in one verifier execution; the independent `None` result must
        // make the pair proof fail.
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
        let mut receipt = ExecClaimReceipt::fail_closed();
        let mut cfi = crate::fi::CfiCounter::new();
        prove_exec_transaction_claim(&cd, &mut receipt, &mut cfi);
        let faulted_accept = VerifiedSafeExec {
            chain_id: 1,
            safe_address: fixture_addr(0xBB),
            decoded: decode_exec_transaction(&cd).expect("ABI shape is valid"),
        };
        assert!(verify_and_bind_exec(&cd, 1, &fixture_addr(0xBB)).is_none());
        assert_ne!(
            exec_claim_resolution_proof(&receipt, Some(&faulted_accept), None),
            crate::fi::OK_SENTINEL,
            "one skipped DelegateCall reject must not authorize the Safe route"
        );

        let skipped = ExecClaimReceipt::fail_closed();
        assert_ne!(
            exec_claim_resolution_proof(&skipped, None, None),
            crate::fi::OK_SENTINEL,
            "a skipped classifier proof must not look like an unclaimed selector"
        );
    }
}

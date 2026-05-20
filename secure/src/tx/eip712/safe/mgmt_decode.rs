//! Safe-native owner / module / guard / fallback operation decoder.
//!
//! Pure-logic counterpart to the gated renderer at
//! [`crate::tx::display::safe_mgmt`]. Lives outside the display tree
//! because the display tree is `#[cfg(not(test))]`-gated at
//! `tx/mod.rs` (it depends on the secure-only UI layer), but the
//! classifier itself is pure data and host-testable.
//!
//! Fires when the outer Safe-tx render sees
//! `canonical.to == canonical.safe_address` and `raw_data[0..4]`
//! matches one of the eight Safe v1.3.0+ singleton selectors below.
//! The cryptographic bind between `raw_data` and the on-chain
//! `safeTxHash` is established upstream in [`super::verify`]; by the
//! time this module sees `raw_data` it is byte-equivalent to what
//! the on-chain Safe will execute once threshold approvals collect.
//!
//! ## Hardening rules (all enforced in `classify_safe_mgmt`)
//!
//! * **Strict length match** per selector. Truncated / over-long
//!   calldata never decodes; the caller treats `None` as "unknown
//!   Safe op" and renders the loud blind-sign branch.
//! * **Address-word canonicalness**: every address parameter must
//!   come encoded as `0..12` zero bytes + 20-byte address. Solidity's
//!   ABI accepts non-canonical encodings on input but rejects them
//!   here so the on-device display can never disagree with the
//!   on-chain interpretation.
//! * **Threshold-word canonicalness**: `uint256` words for `_threshold`
//!   must fit in `u16` (`bytes[0..30]` zero). Real Safes can't have
//!   more than 65535 owners; an out-of-range threshold is surfaced
//!   as [`ThresholdValue::Overflow`] so the user sees `>2^16`
//!   rather than a silently-truncated number.
//! * **No panics on any input** — every slice access is bounds-checked.

use sphincs_tz_shared::{
    SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD, SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD,
    SAFE_MGMT_SELECTOR_DISABLE_MODULE, SAFE_MGMT_SELECTOR_ENABLE_MODULE,
    SAFE_MGMT_SELECTOR_REMOVE_OWNER, SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER,
    SAFE_MGMT_SELECTOR_SET_GUARD, SAFE_MGMT_SELECTOR_SWAP_OWNER,
};

/// Decoded `_threshold` value from a Safe `uint256` parameter.
///
/// `Fits(n)` carries the threshold for display; `Overflow` means the
/// supplied uint256 had bits set beyond the low 16 — the renderer
/// surfaces this as `! >2^16` rather than truncating.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ThresholdValue {
    Fits(u16),
    Overflow,
}

/// A Safe-native owner/module/guard/fallback operation decoded out of
/// the SafeTx's inner calldata.
#[derive(Copy, Clone, Debug)]
pub enum SafeMgmtOp {
    AddOwnerWithThreshold {
        new_owner: [u8; 20],
        new_threshold: ThresholdValue,
    },
    RemoveOwner {
        prev_owner: [u8; 20],
        owner: [u8; 20],
        new_threshold: ThresholdValue,
    },
    SwapOwner {
        prev_owner: [u8; 20],
        old_owner: [u8; 20],
        new_owner: [u8; 20],
    },
    ChangeThreshold {
        new_threshold: ThresholdValue,
    },
    EnableModule {
        module: [u8; 20],
    },
    DisableModule {
        prev_module: [u8; 20],
        module: [u8; 20],
    },
    /// `guard == [0u8; 20]` means "removing guard".
    SetGuard {
        guard: [u8; 20],
    },
    /// `handler == [0u8; 20]` means "removing fallback handler".
    SetFallbackHandler {
        handler: [u8; 20],
    },
}

fn decode_addr_word(word: &[u8; 32]) -> Option<[u8; 20]> {
    if word[0..12].iter().any(|&b| b != 0) {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&word[12..32]);
    Some(addr)
}

fn decode_threshold_word(word: &[u8; 32]) -> ThresholdValue {
    if word[0..30].iter().any(|&b| b != 0) {
        return ThresholdValue::Overflow;
    }
    ThresholdValue::Fits(u16::from_be_bytes([word[30], word[31]]))
}

fn word_at(raw: &[u8], off: usize) -> Option<&[u8; 32]> {
    raw.get(off..off + 32)?.try_into().ok()
}

/// Classify a Safe self-call payload.
///
/// `None` means "unknown / non-canonical Safe self-call"; the caller
/// should render the loud blind-sign branch with `"Unknown Safe op"`.
pub fn classify_safe_mgmt(raw_data: &[u8]) -> Option<SafeMgmtOp> {
    if raw_data.len() < 4 {
        return None;
    }
    let selector: [u8; 4] = raw_data[0..4].try_into().ok()?;
    let body = &raw_data[4..];

    match selector {
        s if s == SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD => {
            if raw_data.len() != 68 {
                return None;
            }
            let new_owner = decode_addr_word(word_at(body, 0)?)?;
            let new_threshold = decode_threshold_word(word_at(body, 32)?);
            Some(SafeMgmtOp::AddOwnerWithThreshold {
                new_owner,
                new_threshold,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_REMOVE_OWNER => {
            if raw_data.len() != 100 {
                return None;
            }
            let prev_owner = decode_addr_word(word_at(body, 0)?)?;
            let owner = decode_addr_word(word_at(body, 32)?)?;
            let new_threshold = decode_threshold_word(word_at(body, 64)?);
            Some(SafeMgmtOp::RemoveOwner {
                prev_owner,
                owner,
                new_threshold,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_SWAP_OWNER => {
            if raw_data.len() != 100 {
                return None;
            }
            let prev_owner = decode_addr_word(word_at(body, 0)?)?;
            let old_owner = decode_addr_word(word_at(body, 32)?)?;
            let new_owner = decode_addr_word(word_at(body, 64)?)?;
            Some(SafeMgmtOp::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD => {
            if raw_data.len() != 36 {
                return None;
            }
            let new_threshold = decode_threshold_word(word_at(body, 0)?);
            Some(SafeMgmtOp::ChangeThreshold { new_threshold })
        }
        s if s == SAFE_MGMT_SELECTOR_ENABLE_MODULE => {
            if raw_data.len() != 36 {
                return None;
            }
            let module = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::EnableModule { module })
        }
        s if s == SAFE_MGMT_SELECTOR_DISABLE_MODULE => {
            if raw_data.len() != 68 {
                return None;
            }
            let prev_module = decode_addr_word(word_at(body, 0)?)?;
            let module = decode_addr_word(word_at(body, 32)?)?;
            Some(SafeMgmtOp::DisableModule {
                prev_module,
                module,
            })
        }
        s if s == SAFE_MGMT_SELECTOR_SET_GUARD => {
            if raw_data.len() != 36 {
                return None;
            }
            let guard = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::SetGuard { guard })
        }
        s if s == SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER => {
            if raw_data.len() != 36 {
                return None;
            }
            let handler = decode_addr_word(word_at(body, 0)?)?;
            Some(SafeMgmtOp::SetFallbackHandler { handler })
        }
        _ => None,
    }
}

/// Number of confirmation pages required to render a [`SafeMgmtOp`].
/// Top end is 3 pages (removeOwner / swapOwner).
pub fn page_count(op: &SafeMgmtOp) -> usize {
    match op {
        SafeMgmtOp::AddOwnerWithThreshold { .. } => 2,
        SafeMgmtOp::RemoveOwner { .. } => 3,
        SafeMgmtOp::SwapOwner { .. } => 3,
        SafeMgmtOp::ChangeThreshold { .. } => 1,
        SafeMgmtOp::EnableModule { .. } => 2,
        SafeMgmtOp::DisableModule { .. } => 2,
        SafeMgmtOp::SetGuard { .. } => 2,
        SafeMgmtOp::SetFallbackHandler { .. } => 2,
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host-runnable)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;
    use alloc::vec::Vec;

    fn hex(addr: [u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(&addr);
        w
    }

    fn u256_be(n: u64) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[24..32].copy_from_slice(&n.to_be_bytes());
        w
    }

    fn build(selector: [u8; 4], words: &[[u8; 32]]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + words.len() * 32);
        v.extend_from_slice(&selector);
        for w in words {
            v.extend_from_slice(w);
        }
        v
    }

    const A: [u8; 20] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xde,
        0xad, 0xbe, 0xef, 0x12, 0x34,
    ];
    const B: [u8; 20] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x01, 0x02, 0x03, 0x04,
    ];
    const C: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xba, 0xbe, 0xca, 0xfe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42,
    ];

    const ZERO_ADDR: [u8; 20] = [0u8; 20];

    #[test]
    fn add_owner_with_threshold_positive() {
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner,
                new_threshold,
            } => {
                assert_eq!(new_owner, A);
                assert_eq!(new_threshold, ThresholdValue::Fits(3));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn add_owner_truncated_returns_none() {
        let mut data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        data.pop();
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_over_long_returns_none() {
        let mut data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(3)],
        );
        data.push(0x00);
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_noncanonical_address_returns_none() {
        let mut addr_word = hex(A);
        addr_word[5] = 0xff;
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[addr_word, u256_be(3)],
        );
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn add_owner_threshold_overflow_surfaces() {
        let mut t_word = u256_be(0);
        t_word[29] = 0x01;
        let data = build(SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD, &[hex(A), t_word]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold { new_threshold, .. } => {
                assert_eq!(new_threshold, ThresholdValue::Overflow);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn add_owner_threshold_max_u16_fits() {
        let data = build(
            SAFE_MGMT_SELECTOR_ADD_OWNER_WITH_THRESHOLD,
            &[hex(A), u256_be(65535)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::AddOwnerWithThreshold { new_threshold, .. } => {
                assert_eq!(new_threshold, ThresholdValue::Fits(65535));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn remove_owner_positive_with_sentinel_prev() {
        let mut sentinel = [0u8; 32];
        sentinel[31] = 0x01;
        let data = build(
            SAFE_MGMT_SELECTOR_REMOVE_OWNER,
            &[sentinel, hex(A), u256_be(2)],
        );
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::RemoveOwner {
                prev_owner,
                owner,
                new_threshold,
            } => {
                let mut expected_prev = [0u8; 20];
                expected_prev[19] = 0x01;
                assert_eq!(prev_owner, expected_prev);
                assert_eq!(owner, A);
                assert_eq!(new_threshold, ThresholdValue::Fits(2));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn swap_owner_positive() {
        let data = build(SAFE_MGMT_SELECTOR_SWAP_OWNER, &[hex(A), hex(B), hex(C)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SwapOwner {
                prev_owner,
                old_owner,
                new_owner,
            } => {
                assert_eq!(prev_owner, A);
                assert_eq!(old_owner, B);
                assert_eq!(new_owner, C);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn change_threshold_one_is_multisig_off_signal() {
        let data = build(SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, &[u256_be(1)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(1),
            } => {}
            _ => panic!("expected ChangeThreshold(1)"),
        }
    }

    #[test]
    fn change_threshold_zero_decodes_faithfully() {
        let data = build(SAFE_MGMT_SELECTOR_CHANGE_THRESHOLD, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(0),
            } => {}
            _ => panic!("expected ChangeThreshold(0)"),
        }
    }

    #[test]
    fn enable_module_positive() {
        let data = build(SAFE_MGMT_SELECTOR_ENABLE_MODULE, &[hex(A)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::EnableModule { module } => assert_eq!(module, A),
            _ => panic!(),
        }
    }

    #[test]
    fn disable_module_positive() {
        let data = build(SAFE_MGMT_SELECTOR_DISABLE_MODULE, &[hex(B), hex(A)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::DisableModule {
                prev_module,
                module,
            } => {
                assert_eq!(prev_module, B);
                assert_eq!(module, A);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn set_guard_zero_is_removal() {
        let data = build(SAFE_MGMT_SELECTOR_SET_GUARD, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetGuard { guard } => assert_eq!(guard, ZERO_ADDR),
            _ => panic!(),
        }
    }

    #[test]
    fn set_guard_nonzero_positive() {
        let data = build(SAFE_MGMT_SELECTOR_SET_GUARD, &[hex(C)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetGuard { guard } => assert_eq!(guard, C),
            _ => panic!(),
        }
    }

    #[test]
    fn set_fallback_handler_zero_is_removal() {
        let data = build(SAFE_MGMT_SELECTOR_SET_FALLBACK_HANDLER, &[u256_be(0)]);
        match classify_safe_mgmt(&data).expect("decode") {
            SafeMgmtOp::SetFallbackHandler { handler } => assert_eq!(handler, ZERO_ADDR),
            _ => panic!(),
        }
    }

    #[test]
    fn unknown_selector_returns_none() {
        let data = build([0xde, 0xad, 0xbe, 0xef], &[u256_be(0)]);
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn short_data_returns_none() {
        let data: [u8; 3] = [0x69, 0x4e, 0x80];
        assert!(classify_safe_mgmt(&data).is_none());
    }

    #[test]
    fn empty_data_returns_none() {
        assert!(classify_safe_mgmt(&[]).is_none());
    }

    #[test]
    fn page_counts_within_envelope() {
        // Caller adds SAFE_HEADER_PAGES (3) + page_count + 1 (confirm).
        // Max should land at 3 + 3 + 1 = 7, well inside MAX_PAGES=22.
        for op in [
            SafeMgmtOp::ChangeThreshold {
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::AddOwnerWithThreshold {
                new_owner: A,
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::RemoveOwner {
                prev_owner: B,
                owner: A,
                new_threshold: ThresholdValue::Fits(2),
            },
            SafeMgmtOp::SwapOwner {
                prev_owner: A,
                old_owner: B,
                new_owner: C,
            },
            SafeMgmtOp::EnableModule { module: A },
            SafeMgmtOp::DisableModule {
                prev_module: B,
                module: A,
            },
            SafeMgmtOp::SetGuard { guard: C },
            SafeMgmtOp::SetFallbackHandler { handler: ZERO_ADDR },
        ] {
            assert!(page_count(&op) <= 3);
        }
    }
}

//! The value a structured off-chain sign (`SIGN_OFFCHAIN` kind 4 SafeTx,
//! kind 5 CoW order) commits to, recomputed straight from the wire payload.
//!
//! Pure and host-compiled so the equivalence with RAW32 is a host test
//! (`offchain_structured_tests` below): for the same typed data, kind 4/5
//! sign exactly `replay_safe_hash(chain, wallet, H)` — the value RAW32 signs
//! when a companion passes the dapp's `H` — with `H` recomputed on-device.
//! The handler (`nsc::cmd_sign_offchain_structured`) uses
//! [`structured_signed_value`] as the post-confirm re-derivation: a second,
//! independent parse + verify of the snapshot that must reproduce the value
//! it confirmed.

use sphincs_tz_shared::{OFFCHAIN_KIND_COW_ORDER, OFFCHAIN_KIND_SAFE_TX};

/// The EIP-712 digest `H` a kind-4 / kind-5 payload describes, after the
/// same framing and verification the handler applies; `None` for anything
/// the handler would refuse at that stage (other kinds included).
#[must_use]
pub fn structured_digest(kind: u8, payload: &[u8], chain_id: u64) -> Option<[u8; 32]> {
    match kind {
        OFFCHAIN_KIND_SAFE_TX => {
            let frame = pqsigner_aa::offchain_header::parse_safe_tx_frame(payload).ok()?;
            super::safe::verify_offchain_safe_tx(frame.safe_bundle, chain_id).map(|(_, h)| h)
        }
        OFFCHAIN_KIND_COW_ORDER => {
            let frame = pqsigner_aa::offchain_header::parse_cow_order_frame(payload).ok()?;
            super::cowswap::verify_offchain_cow_order(frame.canonical, frame.sell, frame.buy, chain_id)
                .map(|(_, h)| h)
        }
        _ => None,
    }
}

/// The value the slot key signs for a kind-4 / kind-5 payload:
/// `replay_safe_hash(chain_id, wallet, H)`.
#[must_use]
pub fn structured_signed_value(kind: u8, payload: &[u8], chain_id: u64, wallet: &[u8; 20]) -> Option<[u8; 32]> {
    let h = structured_digest(kind, payload, chain_id)?;
    Some(pqsigner_aa::eip1271::replay_safe_hash(chain_id, wallet, &h))
}

#[cfg(test)]
mod offchain_structured_tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;
    use sphincs_tz_shared::{EIP712_CANONICAL_LEN, SAFE_V1_CANONICAL_LEN};

    // Independent references from `cowswap/e2e_decode_tests.rs` (ethers v6
    // `TypedDataEncoder` over a real mainnet 1000 USDC -> >= 0.5 WETH order,
    // and the SafeTx wrapping its presign).
    const ORDER_DIGEST_HEX: &str = "f97aaf408259debcbe9b251ac5e1097174cf0084fb2f382d8056617068eaa43a";
    const CANONICAL_HEX: &str = "0000000000000001a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2742d35cc6634c0532925a3b844bc454e4438f44e000000000000000000000000000000000000000000000000000000003b9aca0000000000000000000000000000000000000000000000000006f05b59d3b200000000000000000000000000000000000000000000000000000000000000000000680000000000000083b9dcb2316e54fc04c10f74c9a3d5dd66a9e4c43c04ccefb9c0c03e61e5fb28";
    const SAFE_PRESIGN_HEX: &str = "ec6cb13f000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000038f97aaf408259debcbe9b251ac5e1097174cf0084fb2f382d8056617068eaa43a5afe3855358e112b5647b952709e6165e1c1eeee680000000000000000000000";
    const SAFE_CANON_HEX: &str = "00000000000000015afe3855358e112b5647b952709e6165e1c1eeee9008d19f58aabd9ed0d60971565aa8510560ab410000000000000000000000000000000000000000000000000000000000000000720774a1e1bb52a564f0c33e0ba05c1bac850d236bd19a8f1c4173364de2366400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const SAFE_TX_HASH_HEX: &str = "0e436954453310227409c573f988f1b7ff49cfe3588e493320396da72791bfaa";
    const MS_MULTISEND_HEX: &str = "8d80ff0a0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000019200a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000c92e8bdf79f0507f65a392b0ab4667716bfe0110000000000000000000000000000000000000000000000000000000003b9aca00009008d19f58aabd9ed0d60971565aa8510560ab41000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4ec6cb13f000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000038f97aaf408259debcbe9b251ac5e1097174cf0084fb2f382d8056617068eaa43a5afe3855358e112b5647b952709e6165e1c1eeee6800000000000000000000000000000000000000000000000000";
    const MS_SAFE_CANON_HEX: &str = "00000000000000015afe3855358e112b5647b952709e6165e1c1eeee40a2accbd92bca938b02010e17a5b8929b49130d0000000000000000000000000000000000000000000000000000000000000000044e1d2d0d84e26f34f54e2508eb075bf69058cde56c3bc78dfe645580a2114901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
    const MS_SAFE_TX_HASH_HEX: &str = "540f823dbf50531a2252d640ad52141b254bc5c6eecd1c705b6132c774842cac";
    const WALLET: [u8; 20] = [0xfb; 20];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }

    fn h32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    /// Kind-4 payload: `[safe_len][canonical || raw_len || raw][erc20_len=0]
    /// [cow_len][cow][names_count=0]`.
    fn safe_payload(canonical_hex: &str, raw: &[u8], cow: &[u8]) -> Vec<u8> {
        let canonical = unhex(canonical_hex);
        assert_eq!(canonical.len(), SAFE_V1_CANONICAL_LEN);
        let mut v = Vec::new();
        v.extend_from_slice(&((SAFE_V1_CANONICAL_LEN + 2 + raw.len()) as u16).to_be_bytes());
        v.extend_from_slice(&canonical);
        v.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        v.extend_from_slice(raw);
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&(cow.len() as u16).to_be_bytes());
        v.extend_from_slice(cow);
        v.push(0);
        v
    }

    /// Kind-5 payload: canonical + two empty leg words.
    fn cow_payload() -> Vec<u8> {
        let mut v = unhex(CANONICAL_HEX);
        assert_eq!(v.len(), EIP712_CANONICAL_LEN);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v
    }

    /// What `cmd_sign_offchain` signs for RAW32 given the dapp's `H`.
    fn raw32_signed_value(chain_id: u64, h: &[u8; 32]) -> [u8; 32] {
        pqsigner_aa::eip1271::replay_safe_hash(chain_id, &WALLET, h)
    }

    #[test]
    fn safe_tx_signs_exactly_what_raw32_signs_for_the_ethers_safe_tx_hash() {
        let raw = unhex(SAFE_PRESIGN_HEX);
        let cow = cow_payload();
        let p = safe_payload(SAFE_CANON_HEX, &raw, &cow);
        let reference = h32(SAFE_TX_HASH_HEX);
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &p, 1), Some(reference));
        assert_eq!(
            structured_signed_value(OFFCHAIN_KIND_SAFE_TX, &p, 1, &WALLET),
            Some(raw32_signed_value(1, &reference))
        );
        // The DELEGATECALL -> MultiSendCallOnly SafeTx too.
        let ms = safe_payload(MS_SAFE_CANON_HEX, &unhex(MS_MULTISEND_HEX), &cow);
        let ms_ref = h32(MS_SAFE_TX_HASH_HEX);
        assert_eq!(
            structured_signed_value(OFFCHAIN_KIND_SAFE_TX, &ms, 1, &WALLET),
            Some(raw32_signed_value(1, &ms_ref))
        );
    }

    #[test]
    fn cow_order_signs_exactly_what_raw32_signs_for_the_ethers_order_digest() {
        let p = cow_payload();
        let reference = h32(ORDER_DIGEST_HEX);
        assert_eq!(structured_digest(OFFCHAIN_KIND_COW_ORDER, &p, 1), Some(reference));
        assert_eq!(
            structured_signed_value(OFFCHAIN_KIND_COW_ORDER, &p, 1, &WALLET),
            Some(raw32_signed_value(1, &reference))
        );
    }

    #[test]
    fn structured_refusals() {
        let raw = unhex(SAFE_PRESIGN_HEX);
        let good = safe_payload(SAFE_CANON_HEX, &raw, &[]);
        assert!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &good, 1).is_some());
        // Chain mismatch: the canonical says chain 1.
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &good, 8453), None);
        assert_eq!(structured_digest(OFFCHAIN_KIND_COW_ORDER, &cow_payload(), 8453), None);
        // Data flip: keccak(raw) no longer matches the signed dataHash.
        let mut flipped = raw.clone();
        flipped[150] ^= 1;
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &safe_payload(SAFE_CANON_HEX, &flipped, &[]), 1), None);
        // Trailing byte on either kind.
        let mut t = good.clone();
        t.push(0);
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &t, 1), None);
        let mut t = cow_payload();
        t.push(0);
        assert_eq!(structured_digest(OFFCHAIN_KIND_COW_ORDER, &t, 1), None);
        // DELEGATECALL to anything but a pinned MultiSendCallOnly.
        let mut canon = unhex(SAFE_CANON_HEX);
        canon[sphincs_tz_shared::SAFE_OFF_OPERATION] = 1;
        let mut c = Vec::new();
        for b in &canon {
            c.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
        }
        let delegate = safe_payload(core::str::from_utf8(&c).unwrap(), &raw, &[]);
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &delegate, 1), None);
        // A zero Safe address.
        let mut zero = unhex(SAFE_CANON_HEX);
        zero[sphincs_tz_shared::SAFE_OFF_SAFE_ADDRESS..sphincs_tz_shared::SAFE_OFF_SAFE_ADDRESS + 20].fill(0);
        let mut c = Vec::new();
        for b in &zero {
            c.extend_from_slice(alloc::format!("{b:02x}").as_bytes());
        }
        assert_eq!(structured_digest(OFFCHAIN_KIND_SAFE_TX, &safe_payload(core::str::from_utf8(&c).unwrap(), &raw, &[]), 1), None);
        // A CoW enum out of range (kind byte at canonical offset 168).
        let mut bad = cow_payload();
        bad[168] = 2;
        assert_eq!(structured_digest(OFFCHAIN_KIND_COW_ORDER, &bad, 1), None);
        // Other kinds are not structured.
        assert_eq!(structured_digest(0, &good, 1), None);
    }

    /// Verifier parity: the off-chain verifier accepts a SafeTx exactly when
    /// the on-chain approveHash verifier accepts it bound to the same hash.
    #[test]
    fn offchain_safe_verifier_matches_the_approve_hash_verifier() {
        let raw = unhex(SAFE_PRESIGN_HEX);
        let canon = unhex(SAFE_CANON_HEX);
        let mut bundle = canon.clone();
        bundle.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        bundle.extend_from_slice(&raw);
        let (v, h) = super::super::safe::verify_offchain_safe_tx(&bundle, 1).expect("off-chain verify");
        let mut approve = Vec::from(sphincs_tz_shared::APPROVE_HASH_SELECTOR);
        approve.extend_from_slice(&h);
        let safe: [u8; 20] = canon[8..28].try_into().unwrap();
        let on = super::super::safe::verify_and_bind_trailer(&bundle, &approve, 1, &safe).expect("on-chain verify");
        assert_eq!(v.canonical, on.canonical);
        assert_eq!(v.raw_data, on.raw_data);
        // Every single-byte corruption of the canonical is refused by both or
        // neither (the bind compares against the off-chain verifier's own H,
        // so it cannot diverge on what the canonical says).
        for i in 0..SAFE_V1_CANONICAL_LEN {
            let mut b = bundle.clone();
            b[i] ^= 0x01;
            let off = super::super::safe::verify_offchain_safe_tx(&b, 1);
            let on = super::super::safe::verify_and_bind_trailer(&b, &approve, 1, &safe);
            assert!(on.is_none() || off.is_some(), "byte {i}: on-chain accepts, off-chain refuses");
        }
    }
}

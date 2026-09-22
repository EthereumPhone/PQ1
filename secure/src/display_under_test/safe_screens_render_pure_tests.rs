//! Render-faithfulness tests for the pixel-UI Safe screen emitter
//! (`crate::tx::display::safe_screens`) — the second painter over
//! `safe_display::classify`.
//!
//! Three properties per scenario:
//!
//! 1. **Agreement.** `emit_safe_v1` succeeds exactly when `render_safe_v1_pages`
//!    does, the receipt's `legacy_pages` equals the legacy page count, and the
//!    emitted screen count equals `expected_body_screens` (the lockstep the
//!    firmware self-check enforces).
//! 2. **Fact differential.** Every hex run of ≥ 8 characters and every decimal
//!    run of ≥ 2 digits in the legacy page text appears in the screen text —
//!    the screens may show MORE (full words where the pages truncated) but
//!    never less.
//! 3. **Golden.** A SHA-256 over the emitted records, re-blessed only on an
//!    intentional design change (the exported PNGs make the diff reviewable).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use sphincs_tz_shared::{
    GPV2_SETTLEMENT_ADDRESS, GPV2_VAULT_RELAYER_ADDRESS, MULTISEND_CALL_ONLY_ADDRESSES,
    SAFE_OFF_BASE_GAS, SAFE_OFF_GAS_PRICE, SAFE_OFF_REFUND_RECEIVER, SAFE_OFF_SAFE_TX_GAS,
    SAFE_OFF_VALUE,
};

use super::safe_display::render_safe_v1_pages;
use super::safe_display_render_pure_tests::{
    all_text, bound_cow_stub, build_raw_trailer, erc20_approve, erc20_transfer, usdc_meta,
    wsteth_meta, CHAIN_ID, SAFE_ADDR, TOKEN, WETH, WSTETH,
};
use super::px_lift;
use super::safe_screens::{emit_safe_v1, SafeBodyReceipt};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::test_util::{
    encode_multisend, pack_record, presign_calldata_stub, ZERO_VALUE,
};
use crate::tx::eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer};
use pqsigner_ui_px::{Kind, Screen, Screens, MAX_SCREENS};
use sphincs_tz_shared::{APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, SAFE_OFF_DATA_HASH};

/// A trailer whose canonical the caller can tweak (refund / value / gas
/// fields) before the hash binds it.
fn build_trailer_with(
    to: [u8; 20],
    operation: u8,
    raw: &[u8],
    tweak: impl FnOnce(&mut [u8]),
) -> (Vec<u8>, [u8; APPROVE_HASH_CALLDATA_LEN]) {
    let (mut bundle, _) = build_raw_trailer(to, operation, raw);
    let canonical_len = bundle.len() - 2 - raw.len();
    tweak(&mut bundle[..canonical_len]);
    // Re-bind the data hash (the tweak may not touch it) and recompute the
    // approveHash calldata over the tweaked canonical.
    bundle[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(raw));
    let mut c = [0u8; 281];
    c.copy_from_slice(&bundle[..canonical_len]);
    let h = compute_safe_tx_hash(&c).expect("safe tx hash");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    (bundle, cd)
}

struct Both {
    pages: Pages,
    screens: Screens,
    receipt: SafeBodyReceipt,
}

fn both_with(
    to: [u8; 20],
    operation: u8,
    raw: &[u8],
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
    tweak: impl FnOnce(&mut [u8]),
) -> Result<Both, ()> {
    let (bundle, cd) = build_trailer_with(to, operation, raw, tweak);
    let verified = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR)
        .expect("test Safe trailer must verify+bind");
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&verified, cow, erc20, &resolver);
    let mut screens = Screens::blank();
    let receipt = emit_safe_v1(&mut screens, &verified, cow, erc20, &resolver);
    match (pages, receipt) {
        (Ok(pages), Ok(receipt)) => Ok(Both {
            pages,
            screens,
            receipt,
        }),
        (Err(()), Err(())) => Err(()),
        (Ok(_), Err(())) => panic!("legacy renders but the screen emitter refuses"),
        (Err(()), Ok(_)) => panic!("screen emitter renders but legacy refuses"),
    }
}

fn both(to: [u8; 20], operation: u8, raw: &[u8], cow: Option<&VerifiedCowswapV3>, erc20: Option<&Erc20Metadata<'_>>) -> Both {
    both_with(to, operation, raw, cow, erc20, |_| {}).expect("scenario must render on both painters")
}

fn screen_text(screens: &Screens) -> String {
    let mut s = String::new();
    for sc in screens.as_slice() {
        for b in sc.id() {
            s.push(char::from(*b));
        }
        s.push('\n');
        for b in sc.label() {
            s.push(char::from(*b));
        }
        s.push('\n');
        for b in sc.caption() {
            s.push(char::from(*b));
        }
        s.push('\n');
        for p in 0..sc.npages() {
            for i in 0..sc.nlines(p) {
                let (_, line) = sc.line(p, i).expect("line within nlines");
                for b in line {
                    s.push(char::from(*b));
                }
                s.push('\n');
            }
        }
    }
    s
}

fn hex_only(s: &str) -> String {
    s.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_lowercase()
}

/// Every hex run ≥ 8 and decimal run ≥ 2 of the legacy page text is present in
/// the screen text.
fn assert_facts_carry_over(b: &Both) {
    // "ERC-20" is label vocabulary, not a signed fact; the screens name the
    // token instead ("SEND" / "USD Coin").
    let legacy = all_text(&b.pages).replace("ERC-20", "ERC");
    let screens = screen_text(&b.screens);
    let screens_hex = hex_only(&screens);
    for run in legacy.split(|c: char| !c.is_ascii_hexdigit()) {
        if run.len() >= 8 {
            assert!(
                screens_hex.contains(&run.to_lowercase()),
                "hex run {run:?} from the legacy pages is missing from the screens:\n{screens}"
            );
        }
    }
    for run in legacy.split(|c: char| !c.is_ascii_digit()) {
        if run.len() >= 2 {
            assert!(screens.contains(run), "decimal run {run:?} missing from the screens:\n{screens}");
        }
    }
}

fn assert_shape(b: &Both) {
    assert_eq!(b.receipt.legacy_pages, b.pages.len, "the two classifications must agree on the legacy page count");
    assert_eq!(b.receipt.screens, b.screens.len());
    assert!(b.screens.len() <= MAX_SCREENS);
    let first = &b.screens.as_slice()[0];
    assert_eq!(first.kind(), Some(Kind::Hero));
    assert!(first.commit());
    for (i, s) in b.screens.as_slice().iter().enumerate() {
        assert!(s.is_well_formed(), "screen {i} malformed: {s:?}");
        assert!(s.is_printable_ascii());
        if i > 0 {
            assert!(!s.commit(), "only the hero arms commit in the body");
            assert!(matches!(s.kind(), Some(Kind::Detail | Kind::Value)), "screen {i}: {:?}", s.kind());
        }
    }
}

fn golden(b: &Both) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((b.screens.len() as u32).to_be_bytes());
    for s in b.screens.as_slice() {
        h.update(&s.0[..]);
    }
    hex::encode(h.finalize())
}

fn assert_golden(name: &str, b: &Both, expected: &str) {
    let got = golden(b);
    assert_eq!(got, expected, "{name}: screen golden changed — re-bless after reviewing the exported PNGs:\n{}", screen_text(&b.screens));
}

fn recipient() -> [u8; 20] {
    core::array::from_fn(|i| 0xabu8.wrapping_add(i as u8))
}

#[test]
fn erc20_known_transfer_screens() {
    let meta = usdc_meta();
    let b = both(TOKEN, 0, &erc20_transfer(recipient(), 250_000_000), None, Some(&meta));
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("APPROVE SAFE TX?"));
    assert!(text.contains("on Mainnet"));
    assert!(text.contains("Nonce: 42"));
    // 15 characters exceed the one-line 36/32 budgets, so the amount breaks
    // once after the number (DESIGN.md "Numbers keep their unit").
    assert!(text.contains("250.000000\nUSDC\n"), "{text}");
    assert!(text.contains("USD Coin"));
    let ids: Vec<&[u8]> = b.screens.as_slice().iter().map(|s| s.id()).collect();
    assert_eq!(
        ids,
        [&b"APPROVE"[..], b"NETWORK", b"SAFEACCT", b"TXINFO", b"AMOUNT", b"TOKEN", b"TO", b"CONTRACT"]
    );
    assert_golden("erc20_known", &b, GOLDEN_ERC20_KNOWN);
}

#[test]
fn erc20_unknown_transfer_screens() {
    let b = both(TOKEN, 0, &erc20_transfer(recipient(), 250_000_000), None, None);
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("UNVERIFIED"));
    assert!(text.contains("250000000 units"));
    assert_golden("erc20_unknown", &b, GOLDEN_ERC20_UNKNOWN);
}

#[test]
fn empty_call_and_blind_screens() {
    let e = both([0x44; 20], 0, &[], None, None);
    assert_shape(&e);
    assert_facts_carry_over(&e);
    assert!(screen_text(&e.screens).contains("EMPTY CALL"));
    assert_golden("empty_call", &e, GOLDEN_EMPTY_CALL);

    let bl = both([0x44; 20], 0, &[0xde, 0xad, 0xbe, 0xef], None, None);
    assert_shape(&bl);
    assert_facts_carry_over(&bl);
    let text = screen_text(&bl.screens);
    assert!(text.contains("BLIND SIGN"));
    assert!(text.contains("Function: 0xdeadbeef"));
    assert!(text.contains("Data: 4 B"));
    // The screens show the FULL 32-byte data hash (the pages showed 16 bytes).
    let full = hex::encode(keccak(&[0xde, 0xad, 0xbe, 0xef]));
    assert!(hex_only(&text).contains(&full));
    assert_golden("blind", &bl, GOLDEN_BLIND);
}

#[test]
fn plain_eth_inner_value_and_safe_tx_gas_screens() {
    let b = both_with([0x44; 20], 0, &[], None, None, |c| {
        c[SAFE_OFF_VALUE + 24..SAFE_OFF_VALUE + 32].copy_from_slice(&1_500_000_000_000_000_000u64.to_be_bytes());
        c[SAFE_OFF_SAFE_TX_GAS + 24..SAFE_OFF_SAFE_TX_GAS + 32].copy_from_slice(&120_000u64.to_be_bytes());
    })
    .expect("renders");
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("1.500000 ETH"), "{text}");
    assert!(text.contains("120000 gas"));
    assert!(text.contains("inner may no-op"));
    assert_golden("plain_eth_gas", &b, GOLDEN_PLAIN_ETH_GAS);
}

#[test]
fn refund_block_screens() {
    let meta = usdc_meta();
    let b = both_with(TOKEN, 0, &erc20_transfer(recipient(), 5_000_000), None, Some(&meta), |c| {
        // 1 gwei gas price, 43,776 baseGas, native refund to a fixed receiver.
        c[SAFE_OFF_GAS_PRICE + 24..SAFE_OFF_GAS_PRICE + 32].copy_from_slice(&1_000_000_000u64.to_be_bytes());
        c[SAFE_OFF_BASE_GAS + 24..SAFE_OFF_BASE_GAS + 32].copy_from_slice(&43_776u64.to_be_bytes());
        c[SAFE_OFF_REFUND_RECEIVER..SAFE_OFF_REFUND_RECEIVER + 20].copy_from_slice(&[0x77; 20]);
    })
    .expect("renders");
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("REFUND TOKEN"));
    assert!(text.contains("ETH (native)"));
    assert!(text.contains("REFUND MAX"));
    assert!(text.contains("at 30M gas est"));
    assert!(text.contains("REFUND TO"));
    assert_golden("refund", &b, GOLDEN_REFUND);
}

#[test]
fn cow_presign_direct_screens() {
    let cow = bound_cow_stub();
    let b = both(GPV2_SETTLEMENT_ADDRESS, 0, &presign_calldata_stub(), Some(&cow), None);
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("COW ORDER"));
    assert!(text.contains("owner: this Safe"));
    assert!(text.contains("= the Safe"));
    assert!(text.contains("Partial: no"));
    assert!(text.contains("sell: erc20"));
    assert!(text.contains("APP DATA"));
    assert_golden("cow_direct", &b, GOLDEN_COW_DIRECT);
}

#[test]
fn multisend_approve_presign_screens() {
    let approve = erc20_approve(GPV2_VAULT_RELAYER_ADDRESS, 456);
    let mut packed = pack_record(0, &WSTETH, &ZERO_VALUE, &approve);
    packed.extend_from_slice(&pack_record(0, &GPV2_SETTLEMENT_ADDRESS, &ZERO_VALUE, &presign_calldata_stub()));
    let raw = encode_multisend(&packed);
    let meta = wsteth_meta();
    let cow = bound_cow_stub();
    let b = both(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &raw, Some(&cow), Some(&meta));
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("Op: MultiSend x2"));
    assert!(text.contains("RECORD 1/2"));
    assert!(text.contains("RECORD 2/2"));
    assert!(text.contains("CoW VaultRelayer"));
    assert!(text.contains("wstETH"));
    assert!(text.contains("COW ORDER"));
    assert_golden("multisend", &b, GOLDEN_MULTISEND);
}

#[test]
fn safe_mgmt_add_owner_screens() {
    // addOwnerWithThreshold(address,uint256) to the Safe itself.
    let mut raw = [0u8; 68];
    raw[..4].copy_from_slice(&[0x0d, 0x58, 0x2f, 0x13]);
    raw[16..36].copy_from_slice(&[0x99; 20]);
    raw[67] = 2;
    let b = both(SAFE_ADDR, 0, &raw, None, None);
    assert_shape(&b);
    assert_facts_carry_over(&b);
    let text = screen_text(&b.screens);
    assert!(text.contains("NEW OWNER"));
    assert!(text.contains("Threshold: 2"));
    assert_golden("mgmt_add_owner", &b, GOLDEN_MGMT_ADD_OWNER);
}

#[test]
fn known_call_without_proof_refuses_on_both_painters() {
    // A catalogued WETH deposit with no ERC-7730 proof: both painters refuse.
    assert!(both_with(WETH, 0, &[0xd0, 0xe3, 0x0d, 0xb0], None, None, |_| {}).is_err());
}

#[test]
fn every_screen_fits_its_tier_budget() {
    let meta = usdc_meta();
    let b = both(TOKEN, 0, &erc20_transfer(recipient(), 250_000_000), None, Some(&meta));
    for s in b.screens.as_slice() {
        if let Some(t) = s.tier() {
            let region = if s.kind() == Some(Kind::Value) {
                pqsigner_ui_px::fit::Region::Full
            } else {
                pqsigner_ui_px::fit::Region::Docked
            };
            for p in 0..s.npages() {
                for i in 0..s.nlines(p) {
                    let (_, line) = s.line(p, i).unwrap();
                    assert!(line.len() <= region.chars(t), "{:?}", s);
                }
            }
        }
    }
}

// Goldens — bless by copying the value printed in the assertion failure after
// reviewing `tools/ui_screens_export.py --px` output.
const GOLDEN_ERC20_KNOWN: &str = "57f08b2e33fce0268ecc501b064ac2f7c0838a882dec2c7898249867c8af608e";
const GOLDEN_ERC20_UNKNOWN: &str = "9e083da1840ad280f3caf8896b54cd41c50dd964c8dc2354c2f7008eb80600fb";
const GOLDEN_EMPTY_CALL: &str = "de2b23deff73755f21764265c533ffb8df47f601767665e3f2daf115c94b68b5";
const GOLDEN_BLIND: &str = "51c6ce0fb72241aac765dd0881d7e40b9ba685490e09d5eeaa305c961aaf9f32";
const GOLDEN_PLAIN_ETH_GAS: &str = "954789da07742f3e88a6442e6c729586d6e02e9077e522734b7a850caed01184";
const GOLDEN_REFUND: &str = "eb490a6d8528e87db86f3f2547ae9d900aa68f0b5f0b9dd5f5cc384f3c71d8d5";
const GOLDEN_COW_DIRECT: &str = "d8cd27c915b2ed64a8a388b65fe99f3fab1fe1bdb4f3b69b910b281c89020701";
const GOLDEN_MULTISEND: &str = "f270567f77d63ed96d4f19a4dae4f5fd81d90bc66dfa164c11b9725467b6cfd8";
const GOLDEN_MGMT_ADD_OWNER: &str = "1b2d79da3775b7e39dc384ce9899989b5ae5d39e060e1b429accd7bd87bbbfe5";


// ---------------------------------------------------------------------------
// The lift: legacy tail wrap + returning hero + Confirm? + transcript proof
// ---------------------------------------------------------------------------

/// A full pipeline for the ERC-20 known scenario with two synthetic trailer
/// pages appended after the Safe body (standing in for the dispatcher's
/// fee pages and the handler's mandatory trailers).
fn lifted() -> (Screens, Pages, usize, SafeBodyReceipt, Option<usize>) {
    let meta = usdc_meta();
    let (bundle, cd) = build_trailer_with(TOKEN, 0, &erc20_transfer(recipient(), 250_000_000), |_| {});
    let verified = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).unwrap();
    let resolver = NameResolver::new();
    let mut pages = render_safe_v1_pages(&verified, None, Some(&meta), &resolver).unwrap();
    let body_len = pages.len;
    for (i, label) in [&b"Fees: max / tip"[..], b"Worst-case:", b"Signer acct #0"].iter().enumerate() {
        let slot = pages.push_blank().expect("room");
        pages.buf[slot][0][..label.len()].copy_from_slice(label);
        pages.buf[slot][1][0] = b'0' + i as u8;
    }
    let mut screens = Screens::blank();
    let receipt = px_lift::emit_safe_body(&mut screens, Some(&verified), None, None, Some(&meta), &resolver).unwrap();
    assert_eq!(receipt.legacy_pages, body_len);
    let tail = px_lift::append_legacy_tail(&mut screens, &pages, body_len).unwrap();
    assert_eq!(tail, 3);
    px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = px_lift::insert_confirm(&mut screens).unwrap();
    (screens, pages, body_len, receipt, confirm_at)
}

#[test]
fn lift_proof_accepts_the_assembled_transcript() {
    let (screens, pages, body_len, receipt, confirm_at) = lifted();
    // 8 body screens + 3 tail + hero = 12 ≥ 7 details → Confirm? at 5.
    assert_eq!(confirm_at, Some(5));
    assert_eq!(screens.len(), receipt.screens + 3 + 1 + 1);
    assert_eq!(px_lift::transcript_proof(&screens, &pages, body_len, &receipt, confirm_at), crate::fi::OK_SENTINEL);
    // Legacy pages after the body are wrapped byte-exactly; the confirm
    // footer is the one page dropped.
    let text = screen_text(&screens);
    assert!(text.contains("Fees: max / tip"));
    assert!(!text.contains("Long-press to"));
    assert_eq!(screens.as_slice()[5].kind(), Some(Kind::Confirm));
    assert_eq!(screens.as_slice()[screens.len() - 1].kind(), Some(Kind::Hero));
}

#[test]
fn lift_proof_rejects_tampering() {
    let (screens, pages, body_len, receipt, confirm_at) = lifted();
    let ok = crate::fi::OK_SENTINEL;
    let proof = |s: &Screens, c: Option<usize>| px_lift::transcript_proof(s, &pages, body_len, &receipt, c);

    // A flipped byte in a wrapped trailer page.
    let mut t = Screens::blank();
    t.set_len(screens.len());
    t.buf = screens.buf;
    let tail_idx = receipt.screens + 1; // shifted by the Confirm? at 5
    t.buf[tail_idx].0[70] ^= 0x01;
    assert_ne!(proof(&t, confirm_at), ok, "flipped legacy byte");

    // A missing trailer screen.
    let mut t = Screens::blank();
    t.set_len(screens.len() - 1);
    t.buf = screens.buf;
    t.buf.copy_within(tail_idx + 1..screens.len(), tail_idx);
    assert_ne!(proof(&t, confirm_at), ok, "dropped trailer");

    // A duplicated trailer screen (replacing the next one).
    let mut t = Screens::blank();
    t.set_len(screens.len());
    t.buf = screens.buf;
    t.buf[tail_idx + 1] = t.buf[tail_idx];
    assert_ne!(proof(&t, confirm_at), ok, "duplicated trailer");

    // Wrong Confirm? index claim.
    assert_ne!(proof(&screens, Some(4)), ok, "wrong confirm index");
    assert_ne!(proof(&screens, None), ok, "confirm present but unclaimed");

    // A returning hero that is not the opening hero.
    let mut t = Screens::blank();
    t.set_len(screens.len());
    t.buf = screens.buf;
    let last = t.len() - 1;
    t.buf[last] = pqsigner_ui_px::ScreenBuilder::hero(b"OTHER", pqsigner_ui_px::Icon::Safe, b"OTHER ASK?").finish().unwrap();
    assert_ne!(proof(&t, confirm_at), ok, "different returning hero");

    // A detail that arms commit.
    let mut t = Screens::blank();
    t.set_len(screens.len());
    t.buf = screens.buf;
    t.buf[2].0[5] = b'Y';
    assert_ne!(proof(&t, confirm_at), ok, "commit-armed detail");

    // A body length that does not land on the legacy confirm footer.
    assert_ne!(px_lift::transcript_proof(&screens, &pages, body_len - 1, &receipt, confirm_at), ok);
    let _ = Screen::BLANK;
}

#[test]
fn lift_helpers_fail_closed() {
    let mut pages = Pages::with_len(0);
    let mut screens = Screens::blank();
    assert!(px_lift::append_legacy_tail(&mut screens, &pages, 0).is_err(), "empty");
    let slot = pages.push_blank().unwrap();
    pages.buf[slot][0][..5].copy_from_slice(b"Safe:");
    assert!(px_lift::append_legacy_tail(&mut screens, &pages, 1).is_err(), "not a confirm footer");
    assert!(px_lift::append_returning_hero(&mut screens).is_err(), "no hero");
    assert!(px_lift::emit_safe_body(&mut screens, None, None, None, None, &NameResolver::new()).is_err());
}

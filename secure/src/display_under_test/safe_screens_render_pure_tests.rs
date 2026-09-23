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
use super::trailer_screens::{self, TrailerFacts, TrailerReceipt};
use super::Pages;
use crate::tx::display::erc8213::Kind as FpKind;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::test_util::{
    encode_multisend, pack_record, presign_calldata_stub, ZERO_VALUE,
};
use crate::tx::eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer};
use pqsigner_ui_px::{Kind, Screen, Screens, MAX_SCREENS};
use super::deployment::DeploymentConfirmContext;
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
    // Decimal runs are amounts, counts and nonces — NOT the digit
    // substrings of a hex word (an address the design wraps at a different
    // column than the 16-col page did splits such a substring; the hex-run
    // check above already binds every hex word in full). Blank the hex runs
    // first, then require every decimal run verbatim.
    let mut numeric = String::with_capacity(legacy.len());
    for run in legacy.split_inclusive(|c: char| !c.is_ascii_hexdigit()) {
        let (body, sep) = match run.char_indices().last() {
            Some((i, c)) if !c.is_ascii_hexdigit() => (&run[..i], &run[i..]),
            _ => (run, ""),
        };
        if body.len() >= 8 {
            numeric.push(' ');
        } else {
            numeric.push_str(body);
        }
        numeric.push_str(sep);
    }
    for run in numeric.split(|c: char| !c.is_ascii_digit()) {
        if run.len() >= 2 {
            assert!(screens.contains(run), "decimal run {run:?} missing from the screens:\n{screens}");
        }
    }
}

fn assert_shape(b: &Both) {
    // The design rules as a checker (pqsigner_ui_px::check): every record
    // of every scenario, so an emitter cannot drift from the design without
    // a red test.
    assert_eq!(pqsigner_ui_px::check::check_screens(b.screens.as_slice()), Ok(()));
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
// The lift: native trailers + returning hero + Confirm? + transcript proof
// ---------------------------------------------------------------------------

fn u256(n: u64) -> U256 {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

fn word(n: u64) -> [u8; 32] {
    u256(n).0
}

/// The outer UserOp display shim the Safe routes carry (the same shape the
/// handler builds as `tx_for_display`).
fn outer_tx(value: u64) -> Eip1559Tx {
    let mut tx = Eip1559Tx::default();
    tx.chain_id = CHAIN_ID;
    tx.nonce = 0;
    tx.to = Some(SAFE_ADDR);
    tx.value = u256(value);
    tx.gas_limit = 210_000;
    tx.max_fee_per_gas = u256(30_000_000_000);
    tx.max_priority_fee_per_gas = u256(1_500_000_000);
    tx
}

/// Owns every trailer fact so a `TrailerFacts` can borrow them.
struct TrailerFixture {
    tx: Eip1559Tx,
    paymaster: [u8; 32],
    sender: [u8; 20],
    target: [u8; 20],
    nonce: [u8; 32],
    call: [u8; 32],
    verify: [u8; 32],
    prever: [u8; 32],
    fp: FpKind,
    deployment: DeploymentConfirmContext,
}

const SHA256_OF_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// `value` in wei; `lane` puts a non-zero key in the nonce; `deploy` sets
/// the initCode mode; `paymaster` marks a sponsor present.
fn fixture(value: u64, lane: bool, deploy: bool, paymaster: bool) -> TrailerFixture {
    let sender: [u8; 20] = core::array::from_fn(|i| 0x30u8.wrapping_add(i as u8));
    let mut nonce = [0u8; 32];
    if lane {
        nonce[..24].copy_from_slice(&[0x5a; 24]);
    }
    nonce[24..].copy_from_slice(&3u64.to_be_bytes());
    TrailerFixture {
        tx: outer_tx(value),
        paymaster: if paymaster { [0x11; 32] } else { SHA256_OF_EMPTY },
        sender,
        target: SAFE_ADDR,
        nonce,
        call: word(120_000),
        verify: word(80_000),
        prever: word(10_000),
        fp: FpKind::CalldataDigest(core::array::from_fn(|i| 0xc0u8.wrapping_add(i as u8))),
        deployment: DeploymentConfirmContext::new(deploy, CHAIN_ID, 0, 1, sender, nonce, [0xfa; 20]),
    }
}

impl TrailerFixture {
    fn facts(&self) -> TrailerFacts<'_> {
        TrailerFacts {
            tx: &self.tx,
            legacy_fee_required: true,
            paymaster_and_data_hash: &self.paymaster,
            account_index: 0,
            sender: &self.sender,
            target: &self.target,
            nonce: &self.nonce,
            call_gas: &self.call,
            verification_gas: &self.verify,
            pre_verification_gas: &self.prever,
            fingerprint: self.fp,
            deployment: &self.deployment,
        }
    }
}

/// Append the real trailer pages in the handler's order with the real
/// painters and their proofs (dispatcher native-value + fee splice, then
/// paymaster, signer, target, nonce lane, gas lane, ERC-8213, deployment).
fn append_trailer_pages(pages: &mut Pages, f: &TrailerFacts<'_>) {
    let ok = crate::fi::OK_SENTINEL;
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_native_value_page(pages, &f.tx.value, f.tx.chain_id, &mut cfi).unwrap();
    assert_eq!(super::value_page::native_value_page_proof(pages, before, &f.tx.value, f.tx.chain_id), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_gas_pages(pages, f.tx, &mut cfi).unwrap();
    assert_eq!(super::value_page::legacy_fee_pages_proof(pages, before, f.tx), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_paymaster_page(pages, f.paymaster_and_data_hash, &mut cfi).unwrap();
    assert_eq!(super::value_page::paymaster_page_proof(pages, before, f.paymaster_and_data_hash), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_from_page(pages, f.account_index, f.sender, &mut cfi).unwrap();
    assert_eq!(super::value_page::from_page_proof(pages, before, f.account_index, f.sender), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_target_page(pages, f.target, &mut cfi).unwrap();
    assert_eq!(super::value_page::target_page_proof(pages, before, f.target), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::nonce_lane::enforce_nonce_lane_page(pages, f.nonce, &mut cfi).unwrap();
    assert_eq!(super::nonce_lane::nonce_lane_page_proof(pages, before, f.nonce), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::userop_gas_lane::enforce_userop_gas_page(pages, f.call_gas, f.verification_gas, f.pre_verification_gas, &mut cfi).unwrap();
    assert_eq!(super::userop_gas_lane::userop_gas_page_proof(pages, before, f.call_gas, f.verification_gas, f.pre_verification_gas), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::erc8213::append_fingerprint_page(pages, f.fingerprint, &mut cfi).unwrap();
    assert_eq!(super::erc8213::fingerprint_page_proof(pages, before, f.fingerprint), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::deployment::enforce_deployment_page(pages, f.deployment, &mut cfi).unwrap();
    assert_eq!(super::deployment::deployment_page_proof(pages, before, f.deployment), ok);
}

struct Lifted {
    screens: Screens,
    pages: Pages,
    body_len: usize,
    receipt: px_lift::ContentReceipt,
    confirm_at: Option<usize>,
}

/// The full pipeline for the ERC-20 known scenario: the Safe body, the real
/// trailer pages, the content emit (body + native trailers), the returning
/// hero and the `Confirm?`.
fn lifted(fx: &TrailerFixture) -> Lifted {
    let meta = usdc_meta();
    let (bundle, cd) = build_trailer_with(TOKEN, 0, &erc20_transfer(recipient(), 250_000_000), |_| {});
    let verified = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).unwrap();
    let resolver = NameResolver::new();
    let mut pages = render_safe_v1_pages(&verified, None, Some(&meta), &resolver).unwrap();
    let body_len = pages.len;
    let facts = fx.facts();
    append_trailer_pages(&mut pages, &facts);
    let mut screens = Screens::blank();
    let inputs = px_lift::ContentInputs {
        safe_v1: Some(&verified),
        safe_exec: None,
        cow: None,
        erc20: Some(&meta),
        resolver: &resolver,
        trailers: &facts,
    };
    let receipt = px_lift::emit_content(&mut screens, &inputs).unwrap();
    assert_eq!(receipt.body.legacy_pages, body_len);
    assert_eq!(receipt.trailers.start, receipt.body.screens);
    assert_eq!(receipt.trailers.screens, pages.len - body_len, "one trailer screen per trailer page");
    px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = px_lift::insert_confirm(&mut screens).unwrap();
    // The finished transcript passes the design-rule checker (flow shape
    // included) — the gate the port plan's Phase 1 item 2 asks for.
    assert_eq!(pqsigner_ui_px::check::check_flow(&screens), Ok(()));
    Lifted { screens, pages, body_len, receipt, confirm_at }
}

fn ids(screens: &Screens) -> Vec<String> {
    screens.as_slice().iter().map(|s| String::from_utf8_lossy(s.id()).trim_end().to_owned()).collect()
}

fn proof(l: &Lifted, screens: &Screens, facts: &TrailerFacts<'_>, confirm_at: Option<usize>) -> u32 {
    px_lift::transcript_proof(screens, &l.pages, l.body_len, &l.receipt, facts, confirm_at)
}

fn copy_of(screens: &Screens) -> Screens {
    let mut t = Screens::blank();
    t.set_len(screens.len());
    t.buf = screens.buf;
    t
}

#[test]
fn lift_proof_accepts_the_assembled_transcript() {
    let fx = fixture(0, false, false, false);
    let l = lifted(&fx);
    // 8 body screens + 7 trailers + hero = 16 ≥ 7 details → Confirm? at 5.
    assert_eq!(l.confirm_at, Some(5));
    assert_eq!(l.receipt.trailers.screens, 7);
    assert_eq!(l.screens.len(), l.receipt.body.screens + 7 + 1 + 1);
    assert_eq!(proof(&l, &l.screens, &fx.facts(), l.confirm_at), crate::fi::OK_SENTINEL);
    let text = screen_text(&l.screens);
    assert!(text.contains("Fees: max / tip"), "{text}");
    assert!(text.contains("Worst-case:"));
    assert!(text.contains("Signer acct #0"));
    assert!(!text.contains("Long-press to"));
    assert!(!text.contains("> next"), "navigation footers are not facts");
    assert_eq!(l.screens.as_slice()[5].kind(), Some(Kind::Confirm));
    assert_eq!(l.screens.as_slice()[l.screens.len() - 1].kind(), Some(Kind::Hero));
    let id = ids(&l.screens);
    let start = l.receipt.trailers.start + 1; // shifted by the Confirm? at 5
    assert_eq!(&id[start..start + 7], &["MAXFEE", "WORST", "SIGNER", "TARGET", "GASLANE", "FP8213", "DIGEST"]);
    for s in l.screens.as_slice() {
        assert_ne!(s.kind(), Some(Kind::Legacy), "no page-wrapped record on the pixel route");
    }
    // The digest is a full-width value screen with the fingerprint identity.
    let digest = &l.screens.as_slice()[start + 6];
    assert_eq!(digest.kind(), Some(Kind::Value));
    assert_eq!(digest.icon(), Some(pqsigner_ui_px::Icon::Fingerprint));
}

#[test]
fn every_optional_trailer_renders_and_carries_its_facts() {
    let fx = fixture(1_500_000_000_000_000_000, true, true, true);
    let l = lifted(&fx);
    assert_eq!(l.receipt.trailers.screens, 11);
    assert_eq!(proof(&l, &l.screens, &fx.facts(), l.confirm_at), crate::fi::OK_SENTINEL);
    let id = ids(&l.screens);
    let start = l.receipt.trailers.start + 1;
    assert_eq!(
        &id[start..start + 11],
        &["NATIVE", "MAXFEE", "WORST", "PAYMSTR", "SIGNER", "TARGET", "LANE", "GASLANE", "FP8213", "DIGEST", "DEPLOY"]
    );
    // Loud trailers pulse; ordinary ones do not.
    let vis = l.screens.as_slice();
    assert!(vis[start].pulse() && vis[start + 3].pulse() && vis[start + 10].pulse());
    assert!(!vis[start + 1].pulse() && !vis[start + 4].pulse() && !vis[start + 7].pulse());
    // Every hex / decimal fact of the legacy trailer pages is on the screens.
    let both = Both { pages: l.pages, screens: copy_of(&l.screens), receipt: l.receipt.body };
    assert_facts_carry_over(&both);
    let text = screen_text(&l.screens);
    assert!(text.contains("! NATIVE"), "{text}");
    assert!(text.contains("1.5"), "{text}");
    assert!(text.contains("! PAYMASTER SET"));
    assert!(text.contains("5a5a5a5a5a5a5a5a"), "48-hex nonce lane key");
    assert!(text.contains("Call:120000") && text.contains("Total:210000"));
    assert!(text.contains("DEPLOY FACTORY:"));
    // Nothing truncates: every line fits its region at its tier.
    for s in vis {
        if let Some(t) = s.tier() {
            let region = if s.kind() == Some(Kind::Value) { pqsigner_ui_px::fit::Region::Full } else { pqsigner_ui_px::fit::Region::Docked };
            for p in 0..s.npages() {
                for i in 0..s.nlines(p) {
                    let (_, line) = s.line(p, i).unwrap();
                    assert!(line.len() <= region.chars(t), "{s:?}");
                }
            }
        }
    }
}

#[test]
fn lift_proof_rejects_tampering() {
    let fx = fixture(0, false, false, false);
    let l = lifted(&fx);
    let facts = fx.facts();
    let ok = crate::fi::OK_SENTINEL;
    let tail_idx = l.receipt.trailers.start + 1; // shifted by the Confirm? at 5

    // A flipped byte in a trailer screen.
    let mut t = copy_of(&l.screens);
    t.buf[tail_idx].0[70] ^= 0x01;
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "flipped trailer byte");

    // A missing trailer screen.
    let mut t = copy_of(&l.screens);
    t.set_len(l.screens.len() - 1);
    t.buf.copy_within(tail_idx + 1..l.screens.len(), tail_idx);
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "dropped trailer");

    // A duplicated trailer screen (replacing the next one).
    let mut t = copy_of(&l.screens);
    t.buf[tail_idx + 1] = t.buf[tail_idx];
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "duplicated trailer");

    // A trailer swapped with its neighbour (right screens, wrong order).
    let mut t = copy_of(&l.screens);
    t.buf.swap(tail_idx, tail_idx + 1);
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "reordered trailers");

    // A page-wrapped Legacy record standing in for a trailer.
    let mut t = copy_of(&l.screens);
    t.buf[tail_idx] = Screen::legacy(&l.pages.buf[l.body_len]);
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "legacy record");

    // Wrong Confirm? index claim.
    assert_ne!(proof(&l, &l.screens, &facts, Some(4)), ok, "wrong confirm index");
    assert_ne!(proof(&l, &l.screens, &facts, None), ok, "confirm present but unclaimed");

    // A returning hero that is not the opening hero.
    let mut t = copy_of(&l.screens);
    let last = t.len() - 1;
    t.buf[last] = pqsigner_ui_px::ScreenBuilder::hero(b"OTHER", pqsigner_ui_px::Icon::Safe, b"OTHER ASK?").finish().unwrap();
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "different returning hero");

    // A detail that arms commit.
    let mut t = copy_of(&l.screens);
    t.buf[2].0[5] = b'Y';
    assert_ne!(proof(&l, &t, &facts, l.confirm_at), ok, "commit-armed detail");

    // A body length that does not land on the legacy confirm footer.
    assert_ne!(px_lift::transcript_proof(&l.screens, &l.pages, l.body_len - 1, &l.receipt, &facts, l.confirm_at), ok);

    // Facts that disagree with the screens: a different target, a value
    // the screens do not show, a lane key they do not show.
    let mut other = fixture(0, false, false, false);
    other.target = [0x77; 20];
    assert_ne!(proof(&l, &l.screens, &other.facts(), l.confirm_at), ok, "target mismatch");
    let other = fixture(5, false, false, false);
    assert_ne!(proof(&l, &l.screens, &other.facts(), l.confirm_at), ok, "hidden native value");
    let other = fixture(0, true, false, false);
    assert_ne!(proof(&l, &l.screens, &other.facts(), l.confirm_at), ok, "hidden nonce lane");
    let other = fixture(0, false, true, false);
    assert_ne!(proof(&l, &l.screens, &other.facts(), l.confirm_at), ok, "hidden deployment");
    let other = fixture(0, false, false, true);
    assert_ne!(proof(&l, &l.screens, &other.facts(), l.confirm_at), ok, "hidden paymaster");
}

#[test]
fn trailer_slot_proofs_reject_a_present_screen_on_a_skip() {
    // Screens built for a non-zero value, proven against zero-value facts:
    // the NATIVEVAL screen is present but the facts say skip.
    let fx = fixture(5, false, false, false);
    let l = lifted(&fx);
    let zero = fixture(0, false, false, false);
    let mut receipt: TrailerReceipt = l.receipt.trailers;
    receipt.at[0] = None;
    assert_ne!(trailer_screens::trailer_set_proof(&l.screens, &receipt, &zero.facts(), l.confirm_at), crate::fi::OK_SENTINEL);
    assert_ne!(trailer_screens::trailer_screen_proof(&l.screens, 0, &l.receipt.trailers, &zero.facts(), l.confirm_at), crate::fi::OK_SENTINEL);
    // And the genuine receipt against the genuine facts passes per slot.
    for i in 0..trailer_screens::N_TRAILERS {
        assert_eq!(trailer_screens::trailer_screen_proof(&l.screens, i, &l.receipt.trailers, &fx.facts(), l.confirm_at), crate::fi::OK_SENTINEL, "slot {i}");
    }
}

#[test]
fn lift_helpers_fail_closed() {
    let fx = fixture(0, false, false, false);
    let facts = fx.facts();
    let mut screens = Screens::blank();
    assert!(px_lift::append_returning_hero(&mut screens).is_err(), "no hero");
    let inputs = px_lift::ContentInputs {
        safe_v1: None,
        safe_exec: None,
        cow: None,
        erc20: None,
        resolver: &NameResolver::new(),
        trailers: &facts,
    };
    assert!(px_lift::emit_content(&mut screens, &inputs).is_err());
    let _ = Screen::BLANK;
}

#[test]
fn worst_case_multisend_with_every_trailer_fits() {
    // The heaviest Safe body the tests exercise plus all eleven trailers,
    // the returning hero and the Confirm? stays under MAX_SCREENS.
    let approve = erc20_approve(GPV2_VAULT_RELAYER_ADDRESS, 456);
    let mut packed = pack_record(0, &WSTETH, &ZERO_VALUE, &approve);
    packed.extend_from_slice(&pack_record(0, &GPV2_SETTLEMENT_ADDRESS, &ZERO_VALUE, &presign_calldata_stub()));
    let raw = encode_multisend(&packed);
    let meta = wsteth_meta();
    let cow = bound_cow_stub();
    let b = both(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &raw, Some(&cow), Some(&meta));
    let body = b.screens.len();
    assert!(body + trailer_screens::N_TRAILERS + 2 <= MAX_SCREENS, "body {body} + 11 trailers + 2 > {MAX_SCREENS}");
}

#[test]
fn every_trailer_slot_renders_for_both_fixtures() {
    for (name, fx) in [("minimal", fixture(0, false, false, false)), ("maximal", fixture(1_500_000_000_000_000_000, true, true, true))] {
        let facts = fx.facts();
        for (i, slot) in trailer_screens::SLOTS.iter().enumerate() {
            let r = trailer_screens::expected(*slot, &facts, 9 + i);
            assert!(r.is_ok(), "{name}: slot {slot:?} refused to render");
        }
    }
}


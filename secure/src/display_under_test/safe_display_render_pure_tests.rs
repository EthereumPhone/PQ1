//! Render-faithfulness tests for the Safe transaction renderer
//! (`crate::tx::display::safe_display`), mounted host-side 2026-06-30.
//!
//! Closes the second half of item 1 of the 2026-06-29 coverage audit:
//! `safe_display` (the largest trusted-display renderer, 1575 LoC) had ZERO
//! host render tests — its ERC-20-in-Safe / exec / multiSend-record text was
//! pinned only by page *count*, so wrong text at the right count passed.
//!
//! These tests go through the REAL `verify_and_bind_trailer` decode (not a
//! bypass) to build a `VerifiedSafeV1`, then render it and assert the
//! ERC-20-inner amount DIGITS + the recipient HEX + the Safe address — the
//! same WYSIWYS bug class the audit flagged. The amount/recipient are read
//! from the bound `raw_data` (which `verify_and_bind_trailer` cross-checks
//! against the canonical `data_hash`), so the assertions bind the SIGNED
//! bytes to the screen. `negative_*_nonvacuous` flips the inner amount.

extern crate alloc;

use alloc::vec::Vec;

use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, EIP712_CANONICAL_LEN,
    GPV2_SETTLEMENT_ADDRESS, MULTISEND_CALL_ONLY_ADDRESSES, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
    SAFE_OFF_NONCE, SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_V1_CANONICAL_LEN,
};

use super::safe_display::render_safe_v1_pages;
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::{CowLeg, VerifiedCowswapV3};
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::test_util::{
    encode_multisend, pack_record, presign_calldata_stub, ZERO_VALUE,
};
use crate::tx::eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer};
use crate::ui::{DISPLAY_COLS, DISPLAY_ROWS};

pub(super) const CHAIN_ID: u64 = 1;
pub(super) const SAFE_ADDR: [u8; 20] = [
    0x5a, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
// Synthetic inner ERC-20 token (matches metadata but is deliberately absent
// from the ERC-7730 known-call filter), keeping the baseline render/golden
// tests independent of catalogue membership. Dedicated tests below exercise
// the narrow native-decoder exemption with catalogued wstETH.
pub(super) const TOKEN: [u8; 20] = [0x70; 20];
pub(super) const WETH: [u8; 20] = [
    0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08,
    0x3c, 0x75, 0x6c, 0xc2,
];
pub(super) const WSTETH: [u8; 20] = [
    0x7f, 0x39, 0xc5, 0x81, 0xf5, 0x95, 0xb5, 0x3c, 0x5c, 0xb1, 0x9b, 0xd0, 0xb3, 0xf8, 0xda, 0x6c,
    0x93, 0x5e, 0x2c, 0xa0,
];
const LIDO_WITHDRAWAL_QUEUE_ERC721: [u8; 20] = [
    0x88, 0x9e, 0xdc, 0x2e, 0xda, 0xb5, 0xf4, 0x0e, 0x90, 0x2b, 0x86, 0x4a, 0xd4, 0xd7, 0xad, 0xe8,
    0xe4, 0x12, 0xf9, 0xb1,
];

pub(super) fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    for &b in row.iter() {
        assert!(
            (0x20..=0x7e).contains(&b),
            "non-printable byte {b:#x} on a rendered row"
        );
    }
    row.iter()
        .map(|&b| b as char)
        .collect::<String>()
        .trim_end()
        .to_string()
}

pub(super) fn all_text(pages: &Pages) -> String {
    (0..pages.len)
        .flat_map(|p| (0..DISPLAY_ROWS).map(move |r| (p, r)))
        .map(|(p, r)| row_str(&pages.buf[p][r]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// All ASCII-hex digits across every row of every page, lowercased — so a
/// full 40-hex address (split across rows, with "0x"/space framing) matches.
pub(super) fn all_hex(pages: &Pages) -> String {
    all_text(pages)
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase()
}

/// Build the verifier trailer bundle + approveHash calldata for an inner
/// `transfer(recipient, amount)` on `TOKEN`. Returns `(bundle, calldata)`;
/// `verify_and_bind_trailer` borrows `raw_data` out of `bundle`, so the caller
/// must keep `bundle` alive across the render.
pub(super) fn build_raw_trailer(
    to: [u8; 20],
    operation: u8,
    raw: &[u8],
) -> (Vec<u8>, [u8; APPROVE_HASH_CALLDATA_LEN]) {
    // Canonical SafeTx whose data_hash binds the inner calldata.
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&CHAIN_ID.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(&SAFE_ADDR);
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(&to);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(raw));
    c[SAFE_OFF_OPERATION] = operation;
    let mut nonce = [0u8; 32];
    nonce[31] = 42;
    c[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32].copy_from_slice(&nonce);

    // approveHash(safeTxHash) calldata (the on-chain call being signed).
    let h = compute_safe_tx_hash(&c).expect("safe tx hash");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);

    // Trailer bundle = canonical ‖ raw_len(2 BE) ‖ raw_data.
    let mut b = Vec::with_capacity(SAFE_V1_CANONICAL_LEN + 2 + raw.len());
    b.extend_from_slice(&c);
    b.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    b.extend_from_slice(raw);
    (b, cd)
}

pub(super) fn build_trailer(recipient: [u8; 20], amount: u64) -> (Vec<u8>, [u8; APPROVE_HASH_CALLDATA_LEN]) {
    build_raw_trailer(TOKEN, 0, &erc20_transfer(recipient, amount))
}

pub(super) fn erc20_transfer(recipient: [u8; 20], amount: u64) -> [u8; 68] {
    // ERC-20 transfer(recipient, amount) = selector ‖ arg1 ‖ arg2.
    let mut raw = [0u8; 68];
    raw[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer(address,uint256)
    raw[16..36].copy_from_slice(&recipient); // 20-byte recipient, right-aligned
    raw[60..68].copy_from_slice(&amount.to_be_bytes()); // amount in the low 8 bytes
    raw
}

pub(super) fn render_raw(to: [u8; 20], operation: u8, raw: &[u8]) -> Result<Pages, ()> {
    render_raw_with_context(to, operation, raw, None, None)
}

pub(super) fn render_raw_with_context(
    to: [u8; 20],
    operation: u8,
    raw: &[u8],
    cow: Option<&VerifiedCowswapV3>,
    erc20: Option<&Erc20Metadata<'_>>,
) -> Result<Pages, ()> {
    let (bundle, cd) = build_raw_trailer(to, operation, raw);
    let verified = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR)
        .expect("test Safe trailer must verify+bind");
    render_safe_v1_pages(&verified, cow, erc20, &NameResolver::new())
}

pub(super) fn erc20_approve(spender: [u8; 20], amount_or_token_id: u64) -> [u8; 68] {
    let mut raw = [0u8; 68];
    raw[..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    raw[16..36].copy_from_slice(&spender);
    raw[60..68].copy_from_slice(&amount_or_token_id.to_be_bytes());
    raw
}

pub(super) fn usdc_meta() -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: TOKEN,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    }
}

pub(super) fn wsteth_meta() -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: WSTETH,
        decimals: 18,
        name: b"Wrapped liquid staked Ether 2.0",
        symbol: b"wstETH",
    }
}

#[test]
fn exact_preflight_refuses_safe_erc20_value_too_wide_for_exact_display() {
    let amount = 1_000_000_000_000_000_000_001u128; // 10^21 + 1.
    let mut raw = erc20_transfer([0x21; 20], 0);
    raw[52..68].copy_from_slice(&amount.to_be_bytes());
    let meta = Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: TOKEN,
        decimals: 18,
        name: b"Dust token",
        symbol: b"DUST",
    };

    assert!(
        render_raw_with_context(TOKEN, 0, &raw, None, Some(&meta)).is_err(),
        "Safe must refuse when neither the scaled amount nor signed base units fit exactly"
    );
}

pub(super) fn bound_cow_stub() -> VerifiedCowswapV3 {
    // The renderer accepts this type only after `verify_and_bind_trailer` has
    // bound it to the selected Safe presign bytes. This focused renderer test
    // materialises that capability directly; the CoW verifier's own tests pin
    // the cryptographic construction.
    let mut canonical = [0u8; EIP712_CANONICAL_LEN];
    canonical[..8].copy_from_slice(&CHAIN_ID.to_be_bytes());
    VerifiedCowswapV3 {
        canonical,
        sell: CowLeg::AddrHex,
        buy: CowLeg::AddrHex,
    }
}

#[test]
fn positive_safe_erc20_inner_binds_amount_recipient_and_safe_address() {
    let recipient: [u8; 20] = core::array::from_fn(|i| 0xabu8.wrapping_add(i as u8));
    let (bundle, cd) = build_trailer(recipient, 250_000_000); // 250.000000 USDC
    let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR)
        .expect("trailer must verify+bind");
    let meta = usdc_meta();
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");

    let text = all_text(&pages);
    let hex = all_hex(&pages);

    // Inner ERC-20 amount digits + symbol (read from the bound raw_data).
    assert!(
        text.contains("250"),
        "Safe-wrapped ERC-20 amount must render 250; pages:\n{text}"
    );
    assert!(
        text.contains("USDC"),
        "inner token symbol must render; pages:\n{text}"
    );

    // Full 40-hex recipient (the destination of funds).
    let recip_hex: String = recipient.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        hex.contains(&recip_hex),
        "recipient {recip_hex} must render in full"
    );

    // The Safe address must be shown (the user must see WHICH Safe is signing).
    let safe_hex: String = SAFE_ADDR.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        hex.contains(&safe_hex),
        "the Safe address {safe_hex} must render"
    );
}

#[test]
fn positive_safe_exact_zero_erc20_approve_renders_revoke_and_all_identities() {
    let spender = [0x44u8; 20];
    let meta = usdc_meta();
    let pages = render_raw_with_context(TOKEN, 0, &erc20_approve(spender, 0), None, Some(&meta))
        .expect("metadata-bound Safe ERC-20 zero approval must render");
    let text = all_text(&pages);
    let hex = all_hex(&pages);

    assert!(text.contains("Revoke approval"), "pages:\n{text}");
    assert!(
        text.contains("0.000000") && text.contains("USDC"),
        "pages:\n{text}"
    );
    let spender_hex: String = spender.iter().map(|b| format!("{b:02x}")).collect();
    let token_hex: String = TOKEN.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        hex.contains(&spender_hex),
        "spender must remain fully visible"
    );
    assert!(
        hex.contains(&token_hex),
        "token contract must remain fully visible"
    );
    assert!(
        text.contains("Chain: 1"),
        "chain must remain visible: {text}"
    );
}

#[test]
fn positive_safe_golden_grid_hash() {
    // te-2: full-grid golden over the canonical Safe-wrapped ERC-20 render.
    // The per-substring asserts above check that specific fields render; this
    // binds EVERY rendered cell, so a layout / divider / truncation / page-
    // count regression anywhere on the page trips here even if the checked
    // substrings survive. Re-bless GOLDEN only for an INTENTIONAL layout change.
    let recipient: [u8; 20] = core::array::from_fn(|i| 0xabu8.wrapping_add(i as u8));
    let (bundle, cd) = build_trailer(recipient, 250_000_000);
    let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).expect("bind");
    let meta = usdc_meta();
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");
    let h = super::golden_grid_hash(&pages);

    // Non-vacuity: a different inner amount MUST change the digest, proving
    // the hash actually binds rendered content (not a constant).
    let (b2, cd2) = build_trailer(recipient, 999_000_000);
    let v2 = verify_and_bind_trailer(&b2, &cd2, CHAIN_ID, &SAFE_ADDR).expect("bind");
    let h2 = super::golden_grid_hash(
        &render_safe_v1_pages(&v2, None, Some(&meta), &resolver).expect("render"),
    );
    assert_ne!(
        h, h2,
        "golden hash must bind rendered content (amount change did not move it)"
    );

    // Re-blessed when the positive fixture moved from real (catalogued) USDC
    // to a synthetic token, isolating this layout golden from known-call
    // catalogue churn. The catalogued native-decoder path has its own test.
    const GOLDEN: [u8; 32] = [
        246, 87, 33, 235, 111, 77, 217, 140, 222, 210, 50, 58, 156, 135, 47, 98, 71, 52, 226, 242,
        89, 124, 112, 131, 202, 63, 92, 131, 230, 172, 129, 209,
    ];
    assert_eq!(
        h, GOLDEN,
        "Safe render golden changed — re-bless if intentional. got={h:?}"
    );
}

#[test]
fn negative_safe_erc20_amount_nonvacuous() {
    // Flip the inner amount: the rendered digits must track the bound raw_data,
    // not be a constant. 250 vs 777 USDC; neither appears in the fixed addresses.
    let recipient = [0x33u8; 20];
    let render_amount = |amount: u64| -> String {
        let (bundle, cd) = build_trailer(recipient, amount);
        let v = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR).expect("verify");
        let meta = usdc_meta();
        let resolver = NameResolver::new();
        let pages = render_safe_v1_pages(&v, None, Some(&meta), &resolver).expect("render");
        all_text(&pages)
    };
    let t250 = render_amount(250_000_000); // 250 USDC
    let t777 = render_amount(777_000_000); // 777 USDC
    assert!(t250.contains("250") && !t250.contains("777"));
    assert!(t777.contains("777") && !t777.contains("250"));
}

#[test]
fn known_weth_direct_call_requires_inner_erc7730_proof() {
    assert!(
        render_raw(WETH, 0, &[0xd0, 0xe3, 0x0d, 0xb0]).is_err(),
        "Safe-wrapped WETH.deposit() is Bloom-positive and must not downgrade to blind pages"
    );
}

#[test]
fn known_lido_erc721_approve_rejects_even_when_classified_as_erc20() {
    // ERC-721 approve(address,uint256) is ABI-identical to ERC-20 approve.
    // The native classifier would call the request ID an ERC-20 amount; the
    // exact Lido tuple is in ERC-7730 and therefore must require that proof.
    let raw = erc20_approve([0x44; 20], 0x1234);
    assert!(
        render_raw(LIDO_WITHDRAWAL_QUEUE_ERC721, 0, &raw).is_err(),
        "ERC-20 classification must not bypass the exact known-call gate"
    );
}

#[test]
fn catalogued_erc20_needs_exact_metadata_and_strict_calldata() {
    let approve = erc20_approve([0x47; 20], 123);
    assert!(pqsigner_erc7730::known_calls::may_contain(
        crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
        CHAIN_ID,
        &WSTETH,
        &[0x09, 0x5e, 0xa7, 0xb3],
    ));

    assert!(
        render_raw(WSTETH, 0, &approve).is_err(),
        "an ERC-20-shaped known call without verified metadata must reject"
    );

    let wrong_meta = usdc_meta();
    assert!(
        render_raw_with_context(WSTETH, 0, &approve, None, Some(&wrong_meta)).is_err(),
        "metadata for another contract must not grant the native exemption"
    );

    let exact_meta = wsteth_meta();
    let pages = render_raw_with_context(WSTETH, 0, &approve, None, Some(&exact_meta))
        .expect("exact verified metadata + strict ERC-20 decode must stay usable");
    assert!(all_text(&pages).contains("wstETH"));

    let malformed = [0x09, 0x5e, 0xa7, 0xb3];
    assert!(
        render_raw_with_context(WSTETH, 0, &malformed, None, Some(&exact_meta)).is_err(),
        "selector-only calldata must not borrow the ERC-20 exemption"
    );
}

#[test]
fn supported_cow_multisend_keeps_exact_erc20_native_record_live() {
    // This is the Safe UI's supported shape: approve the vault relayer, then
    // bind the verified CoW order through setPreSignature. The approve tuple
    // is catalogued, so this succeeds only through exact token metadata +
    // strict ABI decode; the CoW capability applies only to the unique second
    // record and cannot excuse the approve.
    let approve = erc20_approve([0x48; 20], 456);
    let mut packed = pack_record(0, &WSTETH, &ZERO_VALUE, &approve);
    packed.extend_from_slice(&pack_record(
        0,
        &GPV2_SETTLEMENT_ADDRESS,
        &ZERO_VALUE,
        &presign_calldata_stub(),
    ));
    let raw = encode_multisend(&packed);
    let meta = wsteth_meta();
    let cow = bound_cow_stub();
    let pages = render_raw_with_context(
        MULTISEND_CALL_ONLY_ADDRESSES[0],
        1,
        &raw,
        Some(&cow),
        Some(&meta),
    )
    .expect("verified CoW [approve, presign] flow must remain live");
    let text = all_text(&pages);
    assert!(text.contains("wstETH"));
    assert!(text.contains("CowSwap order"));
}

#[test]
fn multisend_metadata_is_scoped_to_its_exact_record_contract() {
    // The one metadata bundle may describe record A only. Record B must not
    // borrow A's symbol/decimals merely because both records decode as the
    // same standard ERC-20 ABI shape.
    const SECOND_TOKEN: [u8; 20] = [0x71; 20];
    let first = erc20_transfer([0x21; 20], 1_500_000);
    let second = erc20_transfer([0x22; 20], 7_000_000);
    let mut packed = pack_record(0, &TOKEN, &ZERO_VALUE, &first);
    packed.extend_from_slice(&pack_record(0, &SECOND_TOKEN, &ZERO_VALUE, &second));
    let raw = encode_multisend(&packed);

    let meta = usdc_meta();
    let pages =
        render_raw_with_context(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &raw, None, Some(&meta))
            .expect("two strict synthetic ERC-20 records should render");
    let text = all_text(&pages);
    assert!(
        text.contains("USDC"),
        "record A must use its verified metadata"
    );

    let (_, second_section) = text
        .split_once("MSend rec 2/2")
        .expect("second record divider must be present");
    assert!(second_section.contains("ERC-20 call"));
    assert!(second_section.contains("(unverified)"));
    assert!(second_section.contains("Raw amount:"));
    assert!(!second_section.contains("USDC"));
    assert!(!second_section.contains("USD Coin"));

    let rendered_hex: String = second_section
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase();
    let second_hex: String = SECOND_TOKEN.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        rendered_hex.contains(&second_hex),
        "record B must display its full token contract {second_hex}"
    );
}

#[test]
fn canonical_multisend_checks_every_record_not_only_the_first_or_opaque_ones() {
    // First record is unknown; the Bloom-positive WETH record is SECOND. This
    // catches an early-return/first-record-only walk and the former
    // classification-dependent opaque filter.
    let mut packed = pack_record(0, &[0x44; 20], &ZERO_VALUE, &[0xfe, 0xed, 0xfa, 0xce]);
    packed.extend_from_slice(&pack_record(
        0,
        &WETH,
        &ZERO_VALUE,
        &[0xd0, 0xe3, 0x0d, 0xb0],
    ));
    let raw = encode_multisend(&packed);
    assert!(
        render_raw(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &raw).is_err(),
        "every exact MultiSend record tuple must be checked"
    );
}

#[test]
fn canonical_multisend_lido_erc721_record_cannot_hide_as_erc20() {
    let approve = erc20_approve([0x45; 20], 7);
    let raw = encode_multisend(&pack_record(
        0,
        &LIDO_WITHDRAWAL_QUEUE_ERC721,
        &ZERO_VALUE,
        &approve,
    ));
    assert!(
        render_raw(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &raw).is_err(),
        "record classification must not exempt a Bloom-positive ERC-721 call"
    );
}

#[test]
fn safe_route_errors_fail_closed_and_short_direct_selector_is_zero_padded() {
    // Correct claim selector + malformed body reaches the renderer through the
    // verifier's claim gate, then must fail the proof's strict route parse.
    let malformed = [0x8d, 0x80, 0xff, 0x0a, 0xde, 0xad];
    assert!(
        render_raw(MULTISEND_CALL_ONLY_ADDRESSES[0], 1, &malformed).is_err(),
        "claimed-but-malformed MultiSend must fail closed"
    );

    // A short direct call is still queried as [de,ad,be,00], not bypassed.
    let pages = render_raw([0x46; 20], 0, &[0xde, 0xad, 0xbe])
        .expect("unknown zero-padded short selector should remain renderable");
    assert!(all_text(&pages).contains("Unknown call"));
}

#[test]
fn safe_known_call_fi_source_has_ab_route_proof_and_two_final_gates() {
    const SOURCE: &str = include_str!("../tx/display/safe_display.rs");
    let count = |needle: &str| SOURCE.match_indices(needle).count();

    assert!(SOURCE.contains("#[inline(never)]\nfn prove_safe_inner_calls_unknown("));
    assert_eq!(
        count("let permitted_a = safe_inner_calls_unknown_once(input, cow, erc20);"),
        1
    );
    assert!(SOURCE.contains(
        "let permitted_b = safe_inner_calls_unknown_once(\n        core::hint::black_box(input),\n        core::hint::black_box(cow),\n        core::hint::black_box(erc20),\n    );"
    ));
    assert!(SOURCE.contains("core::ptr::write_volatile(verdict_out, verdict)"));
    assert_eq!(
        count("core::ptr::read_volatile(&unknown_verdict_slot)"),
        2,
        "each final gate needs an independent volatile read"
    );
    assert_eq!(
        count("unknown_cfi.check_into_sentinel(CFI_SAFE_ROUTE_EXPECTED)"),
        2
    );
    assert_eq!(count("if unknown_gate_a != crate::fi::OK_SENTINEL"), 1);
    assert_eq!(count("if unknown_gate_b != crate::fi::OK_SENTINEL"), 1);

    let proof_call = SOURCE
        .find("prove_safe_inner_calls_unknown(")
        .expect("proof call/definition");
    let render_body = SOURCE
        .find("fn render_safe_pages_inner(")
        .expect("render body");
    let render_proof = SOURCE[render_body..]
        .find("prove_safe_inner_calls_unknown(")
        .map(|p| render_body + p)
        .expect("proof invoked by renderer");
    let classify = SOURCE[render_body..]
        .find("let inner_kind = if")
        .map(|p| render_body + p)
        .expect("classification ladder");
    let gate_a = SOURCE[render_proof..]
        .find("if unknown_gate_a != crate::fi::OK_SENTINEL")
        .map(|p| render_proof + p)
        .expect("final gate A");
    let gate_b = SOURCE[gate_a..]
        .find("if unknown_gate_b != crate::fi::OK_SENTINEL")
        .map(|p| gate_a + p)
        .expect("final gate B");
    assert!(proof_call < render_proof && render_proof < gate_a && gate_a < gate_b);
    assert!(
        gate_b < classify,
        "both rejects must precede classification"
    );
    assert_eq!(
        SOURCE[render_proof..classify]
            .match_indices("return Err(());")
            .count(),
        2,
        "both final gates must terminate directly; one `?` propagation is insufficient"
    );

    assert!(SOURCE.contains("let mut selector = [0u8; 4];"));
    assert!(SOURCE.contains("selector[..n].copy_from_slice(&data[..n]);"));
    assert!(SOURCE.contains("meta.chain_id == chain_id"));
    assert!(SOURCE.contains("meta.contract == *target"));
    assert!(SOURCE.contains("parse_erc20_calldata(data).is_some()"));
    assert!(SOURCE.contains("summary.presign_claims == 1"));
    assert!(SOURCE.contains("summary.presign_idx == seen"));
    assert!(SOURCE.contains("safe_inner_is_cow_presign(&record.to, record.data)"));
    assert!(!SOURCE.contains("require_opaque_call_proven_unknown"));
    assert!(!SOURCE.contains("require_multisend_opaque_calls_proven_unknown"));
    assert!(!SOURCE.contains("let opaque = match raw_kind"));
}

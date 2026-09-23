//! Render-faithfulness tests for the pixel-UI structured routes (port step
//! 3): the direct CoW order (`cowswap_screens`), the ERC-7730 page lift
//! (`erc7730_screens`), the off-chain EIP-1271 bodies (`offchain_screens`)
//! and the batch framing (`batch_screens`).
//!
//! Same harness and assertions as `userop_screens_render_pure_tests`: the
//! REAL dispatcher / page painters and trailer gates in handler order, the
//! lift, the lift proof, the fact differential (every hex run ≥ 8 and decimal
//! run ≥ 2 of the legacy pages is in the screen text), the design-rule
//! checker, and a record golden (`UI_PX_EXPORT=1` exports the fixture for the
//! crate's frame goldens).

extern crate alloc;

use super::dispatch::{pick_sign_pages, DispatchPageProofs};
use super::px_lift::{Body, ContentInputs};
use super::safe_screens_render_pure_tests::screen_text;
use super::trailer_screens::TrailerSet;
use super::userop_screens_render_pure_tests::{
    append_handler_trailers, check, finish, finish_ref, hero_caption, ids, tx, Facts, Lifted, RECIPIENT,
};
use super::Pages;
use alloc::boxed::Box;
use crate::names::NameResolver;
use crate::tx::eip712::cowswap::{CowLeg, VerifiedCowswapV3};
use pqsigner_ui_px::Icon;

const MAINNET: u64 = 1;

// ---------------------------------------------------------------------------
// CoW Swap (direct order)
// ---------------------------------------------------------------------------

const GPV2_SETTLEMENT: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6, 0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51,
    0x05, 0x60, 0xab, 0x41,
];
const WETH: [u8; 20] = [
    0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08,
    0x3c, 0x75, 0x6c, 0xc2,
];
const USDC_MAINNET: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];

fn put(c: &mut [u8; 204], off: usize, v: u128) {
    c[off..off + 32].fill(0);
    c[off + 16..off + 32].copy_from_slice(&v.to_be_bytes());
}

fn cow_leg(symbol: &[u8], name: &[u8], decimals: u8) -> CowLeg {
    let mut s = [0u8; 64];
    s[..symbol.len()].copy_from_slice(symbol);
    let mut n = [0u8; 64];
    n[..name.len()].copy_from_slice(name);
    CowLeg::Decoded {
        decimals,
        symbol: s,
        symbol_len: symbol.len() as u8,
        name: n,
        name_len: name.len() as u8,
    }
}

/// `SELL 0.5 WETH for at least 1,842.31 USDC` to `RECIPIENT`, 0.001 WETH fee.
fn cow_order(decoded: bool) -> VerifiedCowswapV3 {
    let mut c = [0u8; 204];
    c[..8].copy_from_slice(&MAINNET.to_be_bytes());
    c[8..28].copy_from_slice(&WETH);
    c[28..48].copy_from_slice(&USDC_MAINNET);
    c[48..68].copy_from_slice(&RECIPIENT);
    put(&mut c, 68, 500_000_000_000_000_000);
    put(&mut c, 100, 1_842_310_000);
    put(&mut c, 132, 1_000_000_000_000_000);
    c[164..168].copy_from_slice(&1_790_000_000u32.to_be_bytes());
    c[168] = 0; // SELL
    c[169] = 0; // fill-or-kill
    c[172..204].copy_from_slice(&[0xa7; 32]);
    let (sell, buy) = if decoded {
        (cow_leg(b"WETH", b"Wrapped Ether", 18), cow_leg(b"USDC", b"USD Coin", 6))
    } else {
        (CowLeg::AddrHex, CowLeg::AddrHex)
    };
    VerifiedCowswapV3 { canonical: c, sell, buy }
}

fn lift_cow(v3: &VerifiedCowswapV3) -> Lifted {
    let t = tx(MAINNET, GPV2_SETTLEMENT, 0, 100);
    let data = [0x5au8; 100];
    let f = Facts::new(MAINNET, GPV2_SETTLEMENT, &data, false, false, false);
    let r = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(&t, &data, &f.sender, Some(v3), None, None, None, None, None, &r, &mut proofs)
        .expect("CoW order must render");
    let mut facts = f.trailer(&t, TrailerSet::Sign);
    // The dispatcher splices the legacy fee pair for the CoW surface.
    facts.legacy_fee_required = true;
    append_handler_trailers(&mut pages, &facts);
    let inputs = ContentInputs {
        body: Body::Cow { v3 },
        trailers: &facts,
    };
    finish(pages, &inputs, "cow")
}

#[test]
fn cow_direct_decoded_screens() {
    let v3 = cow_order(true);
    let l = lift_cow(&v3);
    assert_eq!(hero_caption(&l), "SIGN COWSWAP?");
    assert_eq!(l.screens.as_slice()[0].icon(), Some(Icon::Cowswap));
    let ids = ids(&l.screens);
    for want in ["NETWORK", "ORDER", "SELL", "SELLTOK", "BUY", "BUYTOK", "RECEIVER", "EXPIRES", "FEE", "SOURCES", "APPDATA", "MAXFEE", "WORST"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    let text = screen_text(&l.screens);
    assert!(text.contains("Wrapped Ether") && text.contains("USD Coin"), "{text}");
    check("cowswap", "swap", &l, MAINNET, "cow", "589b8768201c58ff511eca72a06e66f5da49b8e3c940c7862bc2fb53517ff6ce");
}

#[test]
fn cow_direct_address_mode_screens() {
    let v3 = cow_order(false);
    let l = lift_cow(&v3);
    let ids = ids(&l.screens);
    for want in ["SELLTOK", "SELLAMT", "BUYTOK", "BUYAMT"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    check("cowswap", "address_mode", &l, MAINNET, "cow", "864e0b9d03864da2a7bbf6e90a6d3073a6f8651d5f1d014bd9c5c509145625d0");
}

#[test]
fn cow_direct_binding_rejects_a_different_order() {
    // The lift re-runs the direct page painter: an order whose body differs
    // from the proven pages is refused by the transcript proof.
    let v3 = cow_order(true);
    let t = tx(MAINNET, GPV2_SETTLEMENT, 0, 100);
    let data = [0x5au8; 100];
    let f = Facts::new(MAINNET, GPV2_SETTLEMENT, &data, false, false, false);
    let r = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(&t, &data, &f.sender, Some(&v3), None, None, None, None, None, &r, &mut proofs).unwrap();
    let mut facts = f.trailer(&t, TrailerSet::Sign);
    facts.legacy_fee_required = true;
    append_handler_trailers(&mut pages, &facts);
    let mut other = cow_order(true);
    put(&mut other.canonical, 100, 1_842_310_001);
    let inputs = ContentInputs {
        body: Body::Cow { v3: &other },
        trailers: &facts,
    };
    let mut screens = pqsigner_ui_px::Screens::blank();
    let receipt = super::px_lift::emit_content(&mut screens, &inputs).unwrap();
    super::px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = super::px_lift::insert_confirm(&mut screens, &receipt.family).unwrap();
    assert_ne!(
        super::px_lift::transcript_proof(&screens, &pages, &inputs.body, receipt.body.legacy_pages, &receipt, &facts, confirm_at),
        crate::fi::OK_SENTINEL
    );
}

// ---------------------------------------------------------------------------
// ERC-7730 (contract call)
// ---------------------------------------------------------------------------

fn lift_erc7730(tx: &crate::tx::eip1559::Eip1559Tx, data: &[u8], verified: &pqsigner_erc7730::bundle::VerifiedDescriptor<'_>) -> Lifted {
    let target = tx.to.unwrap();
    let f = Facts::new(tx.chain_id, target, data, false, false, false);
    let r = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(tx, data, &f.sender, None, None, None, Some(verified), None, None, &r, &mut proofs)
        .expect("7730 call must render");
    let facts = f.trailer(tx, TrailerSet::Sign);
    append_handler_trailers(&mut pages, &facts);
    let body_len = pages.len - super::trailer_screens::expected_trailer_count(&facts);
    let family = super::erc7730_screens::family(super::erc7730_screens::Surface::Contract, &target);
    // `finish` consumes the pages; the lift reads the same buffer, so bind
    // the body through a pinned copy.
    let pinned: &'static Pages = Box::leak(Box::new(pages));
    let inputs = ContentInputs {
        body: Body::Erc7730 {
            pages: pinned,
            start: 0,
            body_len,
            chain_id: tx.chain_id,
            family,
        },
        trailers: &facts,
    };
    finish_ref(pinned, &inputs, "erc7730")
}

#[test]
fn erc7730_uniswap_exact_input_screens() {
    use super::erc7730_render_pure_tests::{
        build_registry, calldata_uniswap_exact_input, envelope, find_leaf, synth_bundle, UNI_V3,
    };
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = pqsigner_erc7730::bundle::verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let t = envelope(1, UNI_V3);
    let data = calldata_uniswap_exact_input(RECIPIENT);
    let l = lift_erc7730(&t, &data, &verified);
    let text = screen_text(&l.screens);
    assert!(hero_caption(&l).starts_with("SIGN "), "{text}");
    assert!(ids(&l.screens).iter().any(|i| i == "INTENT"), "{text}");
    assert!(ids(&l.screens).iter().any(|i| i == "NETWORK"), "{text}");
    check("erc7730", "uniswap_exact_input", &l, 1, "erc7730", "1a1279b615f1c17b6e0670755eeadbe633263b828f35ae64635a6b78c2126208");
}

// ---------------------------------------------------------------------------
// Off-chain (EIP-1271 / ERC-6492)
// ---------------------------------------------------------------------------

use super::eip1271::{append_eip1271_context_pages, OffchainConfirmContext};
use super::offchain_screens::{OffchainBody, OffchainFacts};
use super::trailer_screens::TrailerFacts;
use crate::tx::display::erc8213::Kind as FpKind;

const WALLET: [u8; 20] = [
    0x5e, 0xa1, 0xc7, 0xd9, 0x3b, 0x04, 0xf6, 0xa2, 0x8e, 0x7c, 0x3d, 0x0b, 0x9f, 0x1e, 0x6a, 0x4c,
    0x8b, 0x2d, 0x7e, 0x05,
];

fn offchain_facts(deployed: bool) -> OffchainFacts<'static> {
    OffchainFacts {
        chain_id: 8453,
        account_index: 1,
        slot_index: 3,
        wallet: &WALLET,
        local_after: 1,
        last_userop: 0,
        cap: 65_536,
        deployed,
    }
}

fn context(kind: u8, deployed: bool, hash: [u8; 32]) -> OffchainConfirmContext {
    OffchainConfirmContext::new(kind, 8453, 1, 3, WALLET, deployed, 1, 0, 65_536, hash)
}

/// The off-chain dialog's tail in handler order: fingerprint, [RAW32:
/// replay-safe fingerprint], [RAW32 / typed: the context suffix].
fn offchain_trailers<'a>(
    pages: &mut Pages,
    tx: &'a crate::tx::eip1559::Eip1559Tx,
    zeros: &'a [u8; 32],
    sender: &'a [u8; 20],
    fp: FpKind,
    fp2: Option<FpKind>,
    ctx: Option<&'a OffchainConfirmContext>,
) -> TrailerFacts<'a> {
    let ok = crate::fi::OK_SENTINEL;
    for kind in core::iter::once(fp).chain(fp2) {
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        super::erc8213::append_fingerprint_page(pages, kind, &mut cfi).unwrap();
        assert_eq!(super::erc8213::fingerprint_page_proof(pages, before, kind), ok);
    }
    if let Some(c) = ctx {
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        append_eip1271_context_pages(pages, c, &mut cfi).unwrap();
        assert_eq!(super::eip1271::eip1271_context_page_proof(pages, before, c), ok);
    }
    TrailerFacts {
        tx,
        legacy_fee_required: false,
        paymaster_and_data_hash: zeros,
        account_index: 0,
        sender,
        target: sender,
        nonce: zeros,
        call_gas: zeros,
        verification_gas: zeros,
        pre_verification_gas: zeros,
        fingerprint: fp,
        deployment: None,
        set: TrailerSet::Offchain,
        fingerprint2: fp2,
        offchain: ctx,
    }
}

#[test]
fn offchain_personal_sign_counterfactual_screens() {
    let msg = b"Login to app.example.com? Nonce: 8f3a9c2e1b, issued 2026-09-23T10:00:00Z";
    let body = OffchainBody::Personal { facts: offchain_facts(false), msg };
    let mut pages = super::offchain_screens::render_pages(&body);
    let t = crate::tx::eip1559::Eip1559Tx::default();
    let fp = FpKind::CalldataDigest(pqsigner_tx_core::erc8213::calldata_digest(msg));
    let facts = offchain_trailers(&mut pages, &t, &[0u8; 32], &WALLET, fp, None, None);
    let inputs = ContentInputs {
        body: Body::Offchain(body),
        trailers: &facts,
    };
    let l = finish(pages, &inputs, "personal");
    assert_eq!(hero_caption(&l), "SIGN EIP-1271?");
    let text = screen_text(&l.screens).replace('\n', "");
    assert!(text.contains("app.example.com?") && text.contains("8f3a9c2e1b"), "{text}");
    assert!(l.screens.as_slice().iter().any(|s| s.label() == b"! UNDEPLOYED" && s.pulse()));
    check("eip1271", "personal_counterfactual", &l, 8453, "personal", "c27c4fc07dbe9a757373bbbfe8ff2940542b2d9175bfb049dff12a3f8d40465c");
}

#[test]
fn offchain_raw32_screens() {
    let h = [0x7d; 32];
    let body = OffchainBody::Raw32 { facts: offchain_facts(true), hash: &h };
    let mut pages = super::offchain_screens::render_pages(&body);
    let t = crate::tx::eip1559::Eip1559Tx::default();
    let replay = [0x3a; 32];
    let ctx = context(0, true, replay);
    let facts = offchain_trailers(&mut pages, &t, &[0u8; 32], &WALLET, FpKind::Raw32(h), Some(FpKind::ReplaySafeHash(replay)), Some(&ctx));
    let inputs = ContentInputs {
        body: Body::Offchain(body),
        trailers: &facts,
    };
    let l = finish(pages, &inputs, "raw32");
    assert_eq!(hero_caption(&l), "SIGN BLIND HASH?");
    assert_eq!(l.screens.as_slice()[0].icon(), Some(Icon::Blind));
    let ids = ids(&l.screens);
    for want in ["BLIND", "HASH", "FP8213", "DIGEST", "FP8213B", "DIGEST2", "OFFSIGNR", "WALLET", "MODE", "KEYS"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    check("eip1271", "raw32", &l, 8453, "raw32", "e33ec6cc19073648d44699ee7e4129c1d45fa529f80c916e64113ee1f464c609");
}

#[test]
fn offchain_eip712_typed_screens() {
    use super::erc7730_render_pure_tests::{build_fixture_registry, find_leaf, synth_bundle};
    let res = build_fixture_registry();
    let entry = find_leaf(res, "eip712-static-scalars.json", 1);
    let bundle = synth_bundle(&res.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = pqsigner_erc7730::bundle::verify_erc7730_bundle(&bundle, &res.root).expect("verify Ballot leaf");
    let pth = crate::tx::eip712::keccak(b"Ballot(uint256 proposalId,uint8 support)");
    let mut encoded = [0u8; 64];
    encoded[31] = 7;
    encoded[63] = 1;
    let (mut pages, _proof) = super::erc7730_secure_shim::render_erc7730_eip712_pages_checked(
        1,
        &entry.contract,
        &pth,
        &encoded,
        &verified,
        None,
        &NameResolver::new(),
    )
    .expect("Ballot renders");
    let t = crate::tx::eip1559::Eip1559Tx::default();
    let final_hash = [0x19; 32];
    let ctx = context(2, true, [0x2b; 32]);
    let facts = offchain_trailers(&mut pages, &t, &[0u8; 32], &WALLET, FpKind::Eip712Final(final_hash), None, Some(&ctx));
    let body_len = pages.len - super::trailer_screens::expected_trailer_count(&facts);
    let family = super::erc7730_screens::family(super::erc7730_screens::Surface::Typed, &entry.contract);
    let pinned: &'static Pages = Box::leak(Box::new(pages));
    let inputs = ContentInputs {
        body: Body::Erc7730 {
            pages: pinned,
            start: 0,
            body_len,
            chain_id: 1,
            family,
        },
        trailers: &facts,
    };
    let l = finish_ref(pinned, &inputs, "typed");
    assert!(hero_caption(&l).starts_with("SIGN "));
    check("eip1271", "typed_ballot", &l, 1, "typed", "903d6bac036afaad6f52c0b84fb9a69fbef0bcee21b344b6ee4d207454fd431f");
}


// ---------------------------------------------------------------------------
// Batch (atomic multi-UserOp: N member asks + the whole-batch ask)
// ---------------------------------------------------------------------------

use super::userop_screens::UserOpInputs;
use super::userop_screens_render_pure_tests::{usdc, BASE, USDC_BASE};

/// A member's handler-owned pages after the wrapped dispatcher output:
/// signer, target, nonce lane, gas lane, the member's fingerprint.
fn append_member_trailers(pages: &mut Pages, f: &TrailerFacts<'_>) {
    let ok = crate::fi::OK_SENTINEL;
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_from_page(pages, f.account_index, f.sender, &mut cfi).unwrap();
    assert_eq!(super::value_page::from_page_proof(pages, before, f.account_index, f.sender), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    super::value_page::enforce_target_page(pages, f.target, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::nonce_lane::enforce_nonce_lane_page(pages, f.nonce, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::userop_gas_lane::enforce_userop_gas_page(pages, f.call_gas, f.verification_gas, f.pre_verification_gas, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::erc8213::append_fingerprint_page(pages, f.fingerprint, &mut cfi).unwrap();
    assert_eq!(super::erc8213::fingerprint_page_proof(pages, before, f.fingerprint), ok);
}

fn lift_batch_member(index: usize, total: usize, amount: u64) -> Lifted {
    let data = super::safe_display_render_pure_tests::erc20_transfer(RECIPIENT, amount);
    let t = tx(BASE, USDC_BASE, 0, data.len());
    let f = Facts::new(BASE, USDC_BASE, &data, false, false, false);
    let r = NameResolver::new();
    let m = usdc();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let inner = pick_sign_pages(&t, &data, &f.sender, None, None, None, None, Some(&m), None, &r, &mut proofs).unwrap();
    let mut pages = Pages::with_len(0);
    let mut cfi = crate::fi::CfiCounter::new();
    super::batch::wrap_pages_with_batch_banner(&inner, index, total, &mut pages, &mut cfi).unwrap();
    let mut facts = f.trailer(&t, TrailerSet::BatchMember);
    facts.deployment = None;
    append_member_trailers(&mut pages, &facts);
    let body = Body::UserOp(UserOpInputs {
        tx: &t,
        inner_data: &data,
        erc20: Some(&m),
        selector: None,
        resolver: &r,
    });
    let inputs = ContentInputs {
        body: Body::BatchMember { index, total, inner: &body },
        trailers: &facts,
    };
    finish(pages, &inputs, "batch_member")
}

#[test]
fn batch_member_screens() {
    let l = lift_batch_member(1, 3, 840_500_000);
    assert_eq!(hero_caption(&l), "SEND 840.500000 USDC?");
    let ids = ids(&l.screens);
    assert_eq!(ids[1], "BATCH", "{ids:?}");
    let text = screen_text(&l.screens);
    assert!(text.contains("BATCH SIGN") && text.contains("Tx 2 of 3"), "{text}");
    // The disc keeps alternating after the inserted position screen.
    let sides: alloc::vec::Vec<_> = l.screens.as_slice().iter().filter_map(|s| s.side()).filter(|s| *s != pqsigner_ui_px::Side::None).collect();
    assert!(sides.windows(2).all(|w| w[0] != w[1]) || sides.len() < 2, "{sides:?}");
    check("batch", "member_2_of_3", &l, BASE, "batch_member", "397a1690f9538ba8374bf7705b22c1d7a78b4e3ef02e51798dfb2b936dbf9716");
}

#[test]
fn batch_summary_screens() {
    let t = tx(BASE, USDC_BASE, 0, 0);
    let f = Facts::new(BASE, USDC_BASE, &[], true, true, true);
    let mut pages = super::batch::build_final_summary_pages(3);
    let mut facts = f.trailer(&t, TrailerSet::BatchFinal);
    facts.fingerprint = FpKind::Raw32([0x42; 32]);
    facts.deployment = Some(&f.deployment);
    let ok = crate::fi::OK_SENTINEL;
    let mut cfi = crate::fi::CfiCounter::new();
    super::value_page::enforce_paymaster_page(&mut pages, facts.paymaster_and_data_hash, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::value_page::enforce_from_page(&mut pages, facts.account_index, facts.sender, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::nonce_lane::enforce_nonce_lane_page(&mut pages, facts.nonce, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::userop_gas_lane::enforce_userop_gas_page(&mut pages, facts.call_gas, facts.verification_gas, facts.pre_verification_gas, &mut cfi).unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    super::erc8213::append_fingerprint_page(&mut pages, facts.fingerprint, &mut cfi).unwrap();
    let d = facts.deployment.unwrap();
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::deployment::enforce_deployment_page(&mut pages, d, &mut cfi).unwrap();
    assert_eq!(super::deployment::deployment_page_proof(&pages, before, d), ok);
    let inputs = ContentInputs {
        body: Body::BatchSummary { total: 3 },
        trailers: &facts,
    };
    let l = finish(pages, &inputs, "batch_summary");
    assert_eq!(hero_caption(&l), "SIGN 3 TXS?");
    let ids = ids(&l.screens);
    for want in ["BATCH", "PAYMSTR", "SIGNER", "LANE", "GASLANE", "FP8213", "DIGEST", "DEPLOY"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    check("batch", "summary", &l, BASE, "batch_summary", "df927a92246ed289adb9f93ed97c70d347666e703290b346a2b92b9917cd2c08");
}

#[test]
fn batch_member_binding_rejects_the_wrong_position() {
    // The same member proven as tx 2 of 3 but lifted as tx 1 of 3: the
    // banner page differs, the proof refuses.
    let data = super::safe_display_render_pure_tests::erc20_transfer(RECIPIENT, 5);
    let t = tx(BASE, USDC_BASE, 0, data.len());
    let f = Facts::new(BASE, USDC_BASE, &data, false, false, false);
    let r = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let inner = pick_sign_pages(&t, &data, &f.sender, None, None, None, None, None, None, &r, &mut proofs).unwrap();
    let mut pages = Pages::with_len(0);
    let mut cfi = crate::fi::CfiCounter::new();
    super::batch::wrap_pages_with_batch_banner(&inner, 1, 3, &mut pages, &mut cfi).unwrap();
    let facts = f.trailer(&t, TrailerSet::BatchMember);
    append_member_trailers(&mut pages, &facts);
    let body = Body::UserOp(UserOpInputs {
        tx: &t,
        inner_data: &data,
        erc20: None,
        selector: None,
        resolver: &r,
    });
    let inputs = ContentInputs {
        body: Body::BatchMember { index: 0, total: 3, inner: &body },
        trailers: &facts,
    };
    let mut screens = pqsigner_ui_px::Screens::blank();
    let receipt = super::px_lift::emit_content(&mut screens, &inputs).unwrap();
    super::px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = super::px_lift::insert_confirm(&mut screens, &receipt.family).unwrap();
    assert_ne!(
        super::px_lift::transcript_proof(&screens, &pages, &inputs.body, receipt.body.legacy_pages, &receipt, &facts, confirm_at),
        crate::fi::OK_SENTINEL
    );
}

#[test]
fn erc7730_userop_envelope_screens() {
    // With UserOp fields the envelope shows the full 256-bit nonce in hex
    // over two pages; the lift keeps it one two-page NONCE screen.
    use super::erc7730_render_pure_tests::{
        build_registry, calldata_uniswap_exact_input, envelope, find_leaf, synth_bundle, UNI_V3,
    };
    let registry = build_registry();
    let entry = find_leaf(registry, "calldata-UniswapV3Router02.json", 1);
    let bundle = synth_bundle(&registry.blob, &entry.ir_bytes, entry.leaf_index);
    let verified = pqsigner_erc7730::bundle::verify_erc7730_bundle(&bundle, &registry.root).expect("verify Router02 leaf");
    let mut t = envelope(1, UNI_V3);
    let mut nonce = [0u8; 32];
    nonce[31] = 0x53;
    t.userop_fields = Some(pqsigner_tx_core::eip1559::UserOpDisplayFields {
        nonce: crate::tx::eip1559::U256(nonce),
        call_gas_limit: super::userop_screens_render_pure_tests::u256(60_000),
        verification_gas_limit: super::userop_screens_render_pure_tests::u256(400_000),
        pre_verification_gas: super::userop_screens_render_pure_tests::u256(120_000),
    });
    let data = calldata_uniswap_exact_input(RECIPIENT);
    let l = lift_erc7730(&t, &data, &verified);
    let nonce_screen = l.screens.as_slice().iter().find(|s| s.id() == b"NONCE").expect("one NONCE screen");
    assert_eq!(nonce_screen.npages(), 2);
    check("erc7730", "uniswap_userop", &l, 1, "erc7730", "372980cbb960712b2d4a556fecf283097c7d2b84ff5d6d5fe27714f5fa1c3cba");
}

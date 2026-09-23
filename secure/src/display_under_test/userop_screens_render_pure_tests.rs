//! Render-faithfulness tests for the pixel-UI single-UserOp and rotation
//! emitters (port step 2): `value_transfer_screens`, `erc20_screens`,
//! `blind_sign_screens`, `typed_call::screens`, `slot_rotation_screens`.
//!
//! Each scenario runs the REAL dispatcher (`pick_sign_pages`) and the real
//! trailer painters in handler order, then the lift (`px_lift` over
//! `Body::UserOp` / `Body::Rotation`), and asserts:
//!
//! 1. **Route + binding.** The emitter's classification names the route the
//!    dispatcher took (its body pages re-render byte-for-byte), and the lift
//!    proof accepts the assembled transcript.
//! 2. **Fact differential.** Every hex run ≥ 8 and decimal run ≥ 2 of the
//!    legacy pages (body AND trailers) is in the screen text. The one
//!    normalisation: a named chain's `Chain: <id>` row is carried by the
//!    `NETWORK` screen's name (the firmware table maps them 1:1).
//! 3. **Design rules.** `pqsigner_ui_px::check::check_flow` on the finished
//!    transcript.
//! 4. **Golden.** A SHA-256 over the records; `UI_PX_EXPORT=1` writes them to
//!    `pqsigner-ui-px/tests/fixtures/<family>/<name>.hex` for the frame goldens.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::deployment::DeploymentConfirmContext;
use super::dispatch::{pick_sign_pages, DispatchPageProofs};
use super::px_lift::{self, Body, ContentInputs};
use super::safe_display_render_pure_tests::{all_text, erc20_approve, erc20_transfer};
use super::safe_screens_render_pure_tests::{hex_only, screen_text};
use super::trailer_screens::{TrailerFacts, TrailerSet};
use super::userop_screens::{classify, Route, UserOpInputs};
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::names::NameResolver;
use crate::selectors::{SelectorMeta, SelectorProvenance};
use crate::tx::display::erc8213::Kind as FpKind;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::eip712::keccak;
use pqsigner_ui_px::{Icon, Kind, Screens};

const BASE: u64 = 8453;
const SEPOLIA: u64 = 11_155_111;

const SHA256_OF_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

const USDC_BASE: [u8; 20] = [
    0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b, 0x54,
    0xbd, 0xa0, 0x29, 0x13,
];
const TOSHI: [u8; 20] = [0x5a; 20];
const UNKNOWN_TOKEN: [u8; 20] = [
    0x3c, 0xa9, 0xe5, 0xf1, 0xb7, 0x2d, 0x04, 0xe8, 0xa6, 0xc1, 0xd9, 0xb3, 0xf5, 0x7e, 0x28, 0xa0,
    0xc4, 0xd6, 0xb1, 0xe9,
];
const RECIPIENT: [u8; 20] = [
    0x78, 0xd8, 0x52, 0x62, 0x82, 0xac, 0x09, 0xf1, 0x88, 0x5d, 0x0f, 0x39, 0xb8, 0x87, 0x5a, 0x01,
    0x80, 0xfc, 0x08, 0x1e,
];
const CONTRACT: [u8; 20] = [
    0x9e, 0x3b, 0x5c, 0x0f, 0x7a, 0x1d, 0x24, 0xe8, 0x6c, 0x3f, 0x0b, 0x7d, 0x5a, 0x2e, 0x4c, 0x6f,
    0x8b, 0x1d, 0x3a, 0x7c,
];

fn u256(n: u128) -> U256 {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&n.to_be_bytes());
    U256(out)
}

fn word(n: u64) -> [u8; 32] {
    u256(u128::from(n)).0
}

fn tx(chain_id: u64, to: [u8; 20], value: u128, data_len: usize) -> Eip1559Tx {
    let mut tx = Eip1559Tx::default();
    tx.chain_id = chain_id;
    tx.nonce = 42;
    tx.to = Some(to);
    tx.value = u256(value);
    tx.data_len = data_len;
    tx.gas_limit = 210_000;
    tx.max_fee_per_gas = u256(45_500_000_000);
    tx.max_priority_fee_per_gas = u256(2_000_000_000);
    tx
}

fn usdc() -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: BASE,
        contract: USDC_BASE,
        decimals: 6,
        name: b"USD Coin",
        symbol: b"USDC",
    }
}

fn toshi() -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: BASE,
        contract: TOSHI,
        decimals: 18,
        name: b"Toshi",
        symbol: b"TOSHI",
    }
}

fn erc20_transfer_from(from: [u8; 20], to: [u8; 20], amount: u64) -> [u8; 100] {
    let mut d = [0u8; 100];
    d[..4].copy_from_slice(&[0x23, 0xb8, 0x72, 0xdd]);
    d[16..36].copy_from_slice(&from);
    d[48..68].copy_from_slice(&to);
    d[68..].copy_from_slice(&word(amount));
    d
}

/// Every handler-owned trailer fact for one scenario.
struct Facts {
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

impl Facts {
    fn new(chain_id: u64, target: [u8; 20], data: &[u8], lane: bool, deploy: bool, paymaster: bool) -> Self {
        let sender: [u8; 20] = core::array::from_fn(|i| 0x30u8.wrapping_add(i as u8));
        let mut nonce = [0u8; 32];
        if lane {
            nonce[..24].copy_from_slice(&[0x5a; 24]);
        }
        nonce[24..].copy_from_slice(&42u64.to_be_bytes());
        Self {
            paymaster: if paymaster { [0x11; 32] } else { SHA256_OF_EMPTY },
            sender,
            target,
            nonce,
            call: word(120_000),
            verify: word(80_000),
            prever: word(10_000),
            fp: FpKind::CalldataDigest(pqsigner_tx_core::erc8213::calldata_digest(data)),
            deployment: DeploymentConfirmContext::new(deploy, chain_id, 0, 0, sender, nonce, [0xfa; 20]),
        }
    }

    fn trailer<'a>(&'a self, tx: &'a Eip1559Tx, set: TrailerSet) -> TrailerFacts<'a> {
        TrailerFacts {
            tx,
            legacy_fee_required: false,
            paymaster_and_data_hash: &self.paymaster,
            account_index: 0,
            sender: &self.sender,
            target: &self.target,
            nonce: &self.nonce,
            call_gas: &self.call,
            verification_gas: &self.verify,
            pre_verification_gas: &self.prever,
            fingerprint: self.fp,
            deployment: if set == TrailerSet::Sign { Some(&self.deployment) } else { None },
            set,
        }
    }
}

/// The handler's own trailer pages after the dispatcher (paymaster, signer,
/// target, nonce lane, gas lane, ERC-8213, deployment), with their proofs.
fn append_handler_trailers(pages: &mut Pages, f: &TrailerFacts<'_>) {
    let ok = crate::fi::OK_SENTINEL;
    if f.set == TrailerSet::Sign {
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        super::value_page::enforce_paymaster_page(pages, f.paymaster_and_data_hash, &mut cfi).unwrap();
        assert_eq!(super::value_page::paymaster_page_proof(pages, before, f.paymaster_and_data_hash), ok);
    }
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::value_page::enforce_from_page(pages, f.account_index, f.sender, &mut cfi).unwrap();
    assert_eq!(super::value_page::from_page_proof(pages, before, f.account_index, f.sender), ok);
    if f.set == TrailerSet::Sign {
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        super::value_page::enforce_target_page(pages, f.target, &mut cfi).unwrap();
        assert_eq!(super::value_page::target_page_proof(pages, before, f.target), ok);
    }
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::nonce_lane::enforce_nonce_lane_page(pages, f.nonce, &mut cfi).unwrap();
    assert_eq!(super::nonce_lane::nonce_lane_page_proof(pages, before, f.nonce), ok);
    let mut cfi = crate::fi::CfiCounter::new();
    let before = pages.len;
    super::userop_gas_lane::enforce_userop_gas_page(pages, f.call_gas, f.verification_gas, f.pre_verification_gas, &mut cfi).unwrap();
    assert_eq!(
        super::userop_gas_lane::userop_gas_page_proof(pages, before, f.call_gas, f.verification_gas, f.pre_verification_gas),
        ok
    );
    if f.set == TrailerSet::Sign {
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        super::erc8213::append_fingerprint_page(pages, f.fingerprint, &mut cfi).unwrap();
        assert_eq!(super::erc8213::fingerprint_page_proof(pages, before, f.fingerprint), ok);
        let d = f.deployment.unwrap();
        let mut cfi = crate::fi::CfiCounter::new();
        let before = pages.len;
        super::deployment::enforce_deployment_page(pages, d, &mut cfi).unwrap();
        assert_eq!(super::deployment::deployment_page_proof(pages, before, d), ok);
    }
}

struct Lifted {
    pages: Pages,
    screens: Screens,
    route: &'static str,
}

fn route_name(r: &Route<'_>) -> &'static str {
    match r {
        Route::Value => "value",
        Route::Erc20Known(..) => "erc20_known",
        Route::Erc20Unknown(..) => "erc20_unknown",
        Route::Typed(..) => "typed_call",
        Route::Blind => "blind_sign",
    }
}

/// The full sign-dialog pipeline for one single-UserOp scenario.
fn lift_userop(
    tx: &Eip1559Tx,
    data: &[u8],
    erc20: Option<&Erc20Metadata<'_>>,
    selector: Option<&SelectorMeta<'_>>,
    resolver: &NameResolver<'_>,
    f: &Facts,
) -> Lifted {
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(tx, data, &f.sender, None, None, None, None, erc20, selector, resolver, &mut proofs)
        .expect("scenario must render");
    let facts = f.trailer(tx, TrailerSet::Sign);
    append_handler_trailers(&mut pages, &facts);
    let body = UserOpInputs {
        tx,
        inner_data: data,
        erc20,
        selector,
        resolver,
    };
    let route = route_name(&classify(&body).expect("route"));
    let inputs = ContentInputs {
        body: Body::UserOp(body),
        trailers: &facts,
    };
    finish(pages, &inputs, route)
}

fn finish(pages: Pages, inputs: &ContentInputs<'_>, route: &'static str) -> Lifted {
    let mut screens = Screens::blank();
    let receipt = px_lift::emit_content(&mut screens, inputs).expect("emit");
    let body_len = receipt.body.legacy_pages;
    assert_eq!(receipt.trailers.screens, pages.len - body_len, "one trailer screen per trailer page");
    px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = px_lift::insert_confirm(&mut screens, &receipt.family).unwrap();
    assert_eq!(pqsigner_ui_px::check::check_flow(&screens), Ok(()), "{}", screen_text(&screens));
    assert_eq!(
        px_lift::transcript_proof(&screens, &pages, &inputs.body, body_len, &receipt, inputs.trailers, confirm_at),
        crate::fi::OK_SENTINEL,
        "lift proof:\n{}",
        screen_text(&screens)
    );
    for (i, s) in screens.as_slice().iter().enumerate() {
        assert!(s.is_well_formed(), "screen {i}");
        assert_ne!(s.kind(), Some(Kind::Legacy));
    }
    Lifted { pages, screens, route }
}

/// Every hex run ≥ 8 and decimal run ≥ 2 of the legacy page text is in the
/// screen text (the named chain id is carried by the `NETWORK` name).
fn assert_facts(l: &Lifted, chain_id: u64) {
    let mut legacy = all_text(&l.pages).replace("ERC-20", "ERC");
    let name = super::primitives::chain_name(chain_id);
    if name != "(unknown chain)" && legacy.contains("Chain: ") {
        legacy = legacy.replace(&format!("Chain: {chain_id}"), "");
        let screens = screen_text(&l.screens);
        assert!(screens.contains(&name[1..name.len() - 1]), "chain name missing:\n{screens}");
    }
    let screens = screen_text(&l.screens);
    let screens_hex = hex_only(&screens);
    for run in legacy.split(|c: char| !c.is_ascii_hexdigit()) {
        if run.len() >= 8 {
            assert!(screens_hex.contains(&run.to_lowercase()), "hex run {run:?} missing:\n{screens}");
        }
    }
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
            assert!(screens.contains(run), "decimal run {run:?} missing:\n{screens}");
        }
    }
}

fn golden(screens: &Screens) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((screens.len() as u32).to_be_bytes());
    for s in screens.as_slice() {
        h.update(&s.0[..]);
    }
    hex::encode(h.finalize())
}

/// With `UI_PX_EXPORT=1`, write the records to
/// `pqsigner-ui-px/tests/fixtures/<family>/<name>.hex`.
fn export(family: &str, name: &str, screens: &Screens) {
    if std::env::var_os("UI_PX_EXPORT").is_none() {
        return;
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pqsigner-ui-px/tests/fixtures").join(family);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let mut out = String::new();
    for s in screens.as_slice() {
        out.push_str(&hex::encode(s.0));
        out.push('\n');
    }
    std::fs::write(dir.join(format!("{name}.hex")), out).expect("fixture write");
}

fn check(family: &str, name: &str, l: &Lifted, chain_id: u64, route: &str, expected: &str) {
    assert_eq!(l.route, route, "{name}: route");
    assert_facts(l, chain_id);
    export(family, name, &l.screens);
    let got = golden(&l.screens);
    assert_eq!(got, expected, "{name}: screen golden changed — re-bless after reviewing the PNGs:\n{}", screen_text(&l.screens));
}

fn ids(screens: &Screens) -> Vec<String> {
    screens.as_slice().iter().map(|s| String::from_utf8_lossy(s.id()).trim_end().to_owned()).collect()
}

fn hero_caption(l: &Lifted) -> String {
    String::from_utf8_lossy(l.screens.as_slice()[0].caption()).into_owned()
}

// ---------------------------------------------------------------------------
// value transfer / contract call
// ---------------------------------------------------------------------------

#[test]
fn send_eth_screens() {
    let t = tx(BASE, RECIPIENT, 5_250_000_000_000_000_000, 0);
    let f = Facts::new(BASE, RECIPIENT, &[], false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &[], None, None, &r, &f);
    assert_eq!(hero_caption(&l), "SEND 5.250000 ETH?");
    assert_eq!(l.screens.as_slice()[0].icon(), Some(Icon::Eth));
    check("value_transfer", "send", &l, BASE, "value", "43fda765377fd1867383686e540511d29495a663a143e026adcf7ca44fc72fe3");
}

#[test]
fn contract_call_screens() {
    let t = tx(SEPOLIA, CONTRACT, 0, 0);
    let f = Facts::new(SEPOLIA, CONTRACT, &[], false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &[], None, None, &r, &f);
    assert_eq!(hero_caption(&l), "CONFIRM CONTRACT CALL?");
    check("value_transfer", "contract_call", &l, SEPOLIA, "value", "f2c972e79ffe7a5a6a5a3539d179fcd5d7a852f36d64f6004420e0542d062816");
}

#[test]
fn send_with_every_trailer_screens() {
    // Paymaster + nonce lane + deployment: every optional trailer twin.
    let t = tx(BASE, RECIPIENT, 250_000_000_000_000_000, 0);
    let f = Facts::new(BASE, RECIPIENT, &[], true, true, true);
    let r = NameResolver::new();
    let l = lift_userop(&t, &[], None, None, &r, &f);
    let ids = ids(&l.screens);
    for want in ["NATIVE", "PAYMSTR", "SIGNER", "TARGET", "LANE", "GASLANE", "FP8213", "DIGEST", "DEPLOY"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    check("value_transfer", "send_all_trailers", &l, BASE, "value", "0e715afb7c8c938e5b7b85225af600f367343bd4863212953b040b42639e56b7");
}

// ---------------------------------------------------------------------------
// ERC-20
// ---------------------------------------------------------------------------

#[test]
fn erc20_known_transfer_screens() {
    let data = erc20_transfer(RECIPIENT, 1_250_000_000);
    let t = tx(BASE, USDC_BASE, 0, data.len());
    let f = Facts::new(BASE, USDC_BASE, &data, false, false, false);
    let r = NameResolver::new();
    let m = usdc();
    let l = lift_userop(&t, &data, Some(&m), None, &r, &f);
    assert_eq!(hero_caption(&l), "SEND 1250.000000 USDC?");
    assert_eq!(l.screens.as_slice()[0].icon(), Some(Icon::Usdc));
    check("erc20", "send_usdc", &l, BASE, "erc20_known", "571e4389416083160cb3e74df8e4df815e71e26c2af34758eb44fb6d3af59641");
}

#[test]
fn erc20_known_unlimited_approve_screens() {
    let mut data = erc20_approve(RECIPIENT, 0);
    data[36..68].copy_from_slice(&[0xff; 32]);
    let t = tx(BASE, USDC_BASE, 0, data.len());
    let f = Facts::new(BASE, USDC_BASE, &data, false, false, false);
    let r = NameResolver::new();
    let m = usdc();
    let l = lift_userop(&t, &data, Some(&m), None, &r, &f);
    assert_eq!(hero_caption(&l), "APPROVE USDC?");
    assert!(screen_text(&l.screens).contains("unlimited"));
    check("erc20", "approve_usdc_unlimited", &l, BASE, "erc20_known", "5a25a8e554927c7636e9e545445cfa37adefbbb15a7c68fdbc3c2528d9090aa0");
}

#[test]
fn erc20_known_placeholder_token_transfer_from_screens() {
    let from: [u8; 20] = [0x42; 20];
    let data = erc20_transfer_from(from, RECIPIENT, 12_500);
    let t = tx(BASE, TOSHI, 0, data.len());
    let f = Facts::new(BASE, TOSHI, &data, false, false, false);
    let r = NameResolver::new();
    let m = toshi();
    let l = lift_userop(&t, &data, Some(&m), None, &r, &f);
    let hero = &l.screens.as_slice()[0];
    assert_eq!(hero.icon(), Some(Icon::Eth));
    assert_eq!(hero.tint(), Some(pqsigner_ui_px::placeholder_ramp(b"TOSHI")));
    assert!(ids(&l.screens).iter().any(|i| i == "FROM"));
    check("erc20", "pull_toshi", &l, BASE, "erc20_known", "cc51c9349fd511243b08a20ae45f3c0941f3a17a73877f693820e0179334d0ce");
}

#[test]
fn erc20_unknown_transfer_screens() {
    let data = erc20_transfer(RECIPIENT, 1_234_567_890);
    let t = tx(BASE, UNKNOWN_TOKEN, 0, data.len());
    let f = Facts::new(BASE, UNKNOWN_TOKEN, &data, false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &data, None, None, &r, &f);
    assert_eq!(hero_caption(&l), "TRANSFER UNKNOWN TOKEN?");
    // The design reference's own sample: this contract hashes to ramp 1.
    assert_eq!(l.screens.as_slice()[0].tint(), Some(1));
    check("erc20", "transfer_unknown", &l, BASE, "erc20_unknown", "370310fdbf413ecce47d8b847ff3a649e12fff3b11761df2e46bafd52294e97e");
}

// ---------------------------------------------------------------------------
// typed call / blind sign
// ---------------------------------------------------------------------------

fn selector_meta(text_sig: &'static [u8], provenance: SelectorProvenance) -> SelectorMeta<'static> {
    let h = keccak(text_sig);
    SelectorMeta {
        selector: [h[0], h[1], h[2], h[3]],
        text_sig,
        provenance,
    }
}

#[test]
fn typed_call_screens() {
    let meta = selector_meta(b"stake(address,uint256,bool)", SelectorProvenance::Curated);
    let mut data = Vec::new();
    data.extend_from_slice(&meta.selector);
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&RECIPIENT);
    data.extend_from_slice(&a);
    data.extend_from_slice(&u256(1_000_000_000_000_000_000).0);
    data.extend_from_slice(&word(1));
    let t = tx(BASE, CONTRACT, 0, data.len());
    let f = Facts::new(BASE, CONTRACT, &data, false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &data, None, Some(&meta), &r, &f);
    assert_eq!(hero_caption(&l), "CONFIRM BLIND SIGN?");
    let ids = ids(&l.screens);
    for want in ["FUNCTION", "ARG0", "ARG1", "ARG2"] {
        assert!(ids.iter().any(|i| i == want), "{want} missing from {ids:?}");
    }
    assert!(screen_text(&l.screens).contains("stake(address,uint256,bool)") || screen_text(&l.screens).contains("stake(address,"));
    check("typed_call", "stake", &l, BASE, "typed_call", "3b90f5aa5f01c5ea036bebe45c17c39a1d836ae0ce1151873f3ac43ec8380130");
}

#[test]
fn blind_sign_screens() {
    let data: Vec<u8> = (0u8..100).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
    let t = tx(BASE, CONTRACT, 250_000_000_000_000_000, data.len());
    let f = Facts::new(BASE, CONTRACT, &data, false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &data, None, None, &r, &f);
    assert_eq!(hero_caption(&l), "CONFIRM UNKNOWN CALL?");
    assert_eq!(l.screens.as_slice()[0].icon(), Some(Icon::Blind));
    check("blind_sign", "call_with_value", &l, BASE, "blind_sign", "083a84d04e0b61b59b37198e8e6e755d5007beebf20df90ab0e800b046f7e371");
}

#[test]
fn blind_sign_with_function_name_screens() {
    // A curated name whose typed walk declines (dynamic bytes payload) —
    // the blind flow with its FUNCTION screen, the full signature shown.
    let meta = selector_meta(
        b"swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        SelectorProvenance::Curated,
    );
    let mut data = Vec::new();
    data.extend_from_slice(&meta.selector);
    data.extend_from_slice(&[0x77; 256]);
    let t = tx(BASE, CONTRACT, 0, data.len());
    let f = Facts::new(BASE, CONTRACT, &data, false, false, false);
    let r = NameResolver::new();
    let l = lift_userop(&t, &data, None, Some(&meta), &r, &f);
    let text = screen_text(&l.screens).replace('\n', "");
    assert!(text.contains("swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"), "{text}");
    check("blind_sign", "unknown_call_named", &l, BASE, "blind_sign", "4b9461f37a35f60719adaeba3d55d1a8b75ec4033f34db527f651bd69585117d");
}

// ---------------------------------------------------------------------------
// slot rotation
// ---------------------------------------------------------------------------

#[test]
fn slot_rotation_screens() {
    let t = tx(BASE, RECIPIENT, 0, 0);
    let f = Facts::new(BASE, RECIPIENT, &[], true, false, false);
    let mut pages = super::slot_rotation::build_slot_rotation_pages(4);
    let facts = f.trailer(&t, TrailerSet::Rotation);
    append_handler_trailers(&mut pages, &facts);
    let inputs = ContentInputs {
        body: Body::Rotation { chain_id: BASE, slot_index: 4 },
        trailers: &facts,
    };
    let l = finish(pages, &inputs, "rotation");
    assert_eq!(hero_caption(&l), "ROTATE SLOT?");
    assert_eq!(ids(&l.screens), ["ROTATE", "ROTATE", "COST", "SIGNER", "LANE", "GASLANE", "ROTATE"]);
    check("slot_rotation", "rotate_slot", &l, BASE, "rotation", "0353a21f4454310694b97830b7feb6439ca89176c82f8cb3e4c62cf1011899f5");
}

// ---------------------------------------------------------------------------
// binding
// ---------------------------------------------------------------------------

#[test]
fn a_body_the_dispatcher_did_not_paint_is_refused() {
    // Route the lift at the value-transfer body while the pages carry the
    // blind-sign body: the re-rendered painter differs and the proof fails.
    let data: Vec<u8> = (0u8..40).collect();
    let t = tx(BASE, CONTRACT, 0, data.len());
    let f = Facts::new(BASE, CONTRACT, &data, false, false, false);
    let r = NameResolver::new();
    let mut proofs = DispatchPageProofs::new();
    proofs.fail_initialize();
    let mut pages = pick_sign_pages(&t, &data, &f.sender, None, None, None, None, None, None, &r, &mut proofs).unwrap();
    let facts = f.trailer(&t, TrailerSet::Sign);
    append_handler_trailers(&mut pages, &facts);
    let lying = UserOpInputs {
        tx: &t,
        inner_data: &[],
        erc20: None,
        selector: None,
        resolver: &r,
    };
    let inputs = ContentInputs {
        body: Body::UserOp(lying),
        trailers: &facts,
    };
    let mut screens = Screens::blank();
    let receipt = px_lift::emit_content(&mut screens, &inputs).unwrap();
    px_lift::append_returning_hero(&mut screens).unwrap();
    let confirm_at = px_lift::insert_confirm(&mut screens, &receipt.family).unwrap();
    assert_ne!(
        px_lift::transcript_proof(&screens, &pages, &inputs.body, receipt.body.legacy_pages, &receipt, &facts, confirm_at),
        crate::fi::OK_SENTINEL
    );
}


//! ERC-20 bundle SET (`CAP_ERC20_BUNDLE_SET`) on the Safe painters.
//!
//! Before the set, one request carried one ERC-20 bundle. A Safe multiSend
//! with two catalogued tokens therefore refused, and a refund paid in an
//! ERC-20 `gasToken` showed base units. These tests drive both painters
//! (legacy pages + pixel screens) through `safe_route_meta`, the same filter
//! the sign handlers use, and pin:
//!
//! * two catalogued multiSend records render with both entries, refuse with one;
//! * a gasToken refund shows decimals + symbol;
//! * **H1:** a gasToken entry never labels the inner call;
//! * an entry no signed address names, or for another chain, changes nothing.

extern crate alloc;

use alloc::string::String;

use sphincs_tz_shared::{
    MULTISEND_CALL_ONLY_ADDRESSES, SAFE_OFF_BASE_GAS, SAFE_OFF_GAS_PRICE, SAFE_OFF_GAS_TOKEN,
};

use super::dispatch::safe_route_meta;
use super::golden_grid_hash;
use super::safe_display::render_safe_v1_pages;
use super::safe_display_render_pure_tests::{
    all_text, build_raw_trailer, erc20_approve, erc20_transfer, usdc_meta, wsteth_meta, CHAIN_ID,
    SAFE_ADDR, TOKEN, WSTETH,
};
use super::safe_screens::emit_safe_v1;
use super::safe_screens_render_pure_tests::screen_text;
use super::Pages;
use crate::erc20::bundle::Erc20Metadata;
use crate::erc20::set::{Erc20Scope, Erc20Set, InsertOutcome};
use crate::names::NameResolver;
use crate::tx::eip712::keccak;
use crate::tx::eip712::safe::multi_send::test_util::{encode_multisend, pack_record, ZERO_VALUE};
use crate::tx::eip712::safe::{compute_safe_tx_hash, verify_and_bind_trailer};
use pqsigner_ui_px::Screens;
use sphincs_tz_shared::{
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, SAFE_OFF_DATA_HASH, SAFE_V1_CANONICAL_LEN,
};

const GAS_TOKEN: [u8; 20] = [0x72; 20];
const STETH: [u8; 20] = [
    0xae, 0x7a, 0xb9, 0x65, 0x20, 0xde, 0x3a, 0x18, 0xe5, 0xe1, 0x11, 0xb5, 0xea, 0xab, 0x09, 0x53,
    0x12, 0xd7, 0xfe, 0x84,
];
const USDC_MAINNET: [u8; 20] = [
    0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce,
    0x36, 0x06, 0xeb, 0x48,
];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

fn set_of<'a>(metas: &[Erc20Metadata<'a>]) -> Erc20Set<'a> {
    let mut set = Erc20Set::new();
    for m in metas {
        assert_eq!(set.insert(*m), InsertOutcome::Added);
    }
    set
}

/// Legacy + pixel render of an approveHash Safe trailer, ERC-20 scope routed
/// through `safe_route_meta` exactly as the sign handlers do.
fn render_both(
    to: [u8; 20],
    operation: u8,
    raw: &[u8],
    scope: Erc20Scope<'_, '_>,
    tweak: impl FnOnce(&mut [u8]),
) -> Result<(Pages, String), ()> {
    let (mut bundle, _) = build_raw_trailer(to, operation, raw);
    let canonical_len = bundle.len() - 2 - raw.len();
    tweak(&mut bundle[..canonical_len]);
    bundle[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&keccak(raw));
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c.copy_from_slice(&bundle[..canonical_len]);
    let h = compute_safe_tx_hash(&c).expect("safe tx hash");
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(&h);
    let verified = verify_and_bind_trailer(&bundle, &cd, CHAIN_ID, &SAFE_ADDR)
        .expect("test Safe trailer must verify+bind");
    let routed = safe_route_meta(CHAIN_ID, Some(&verified), None, scope);
    let resolver = NameResolver::new();
    let pages = render_safe_v1_pages(&verified, None, routed, &resolver);
    let mut screens = Screens::blank();
    let receipt = emit_safe_v1(&mut screens, &verified, None, routed, &resolver);
    match (pages, receipt) {
        (Ok(p), Ok(_)) => Ok((p, screen_text(&screens))),
        (Err(()), Err(())) => Err(()),
        (p, r) => panic!("painters disagree: legacy ok={} pixel ok={}", p.is_ok(), r.is_ok()),
    }
}

fn second_catalogued_token() -> Erc20Metadata<'static> {
    let (contract, decimals, name, symbol): ([u8; 20], u8, &[u8], &[u8]) = [
        (STETH, 18u8, &b"Liquid staked Ether 2.0"[..], &b"stETH"[..]),
        (USDC_MAINNET, 6, b"USD Coin", b"USDC"),
    ]
    .into_iter()
    .find(|(c, ..)| {
        pqsigner_erc7730::known_calls::may_contain(
            crate::db_roots::ERC7730_KNOWN_CALLS_BLOOM,
            CHAIN_ID,
            c,
            &APPROVE,
        )
    })
    .expect("a second catalogued ERC-20 approve tuple on chain 1");
    Erc20Metadata { chain_id: CHAIN_ID, contract, decimals, name, symbol }
}

#[test]
fn multisend_with_two_catalogued_tokens_renders_with_both_entries_and_refuses_with_one() {
    let second = second_catalogued_token();
    let mut packed = pack_record(0, &WSTETH, &ZERO_VALUE, &erc20_approve([0x48; 20], 2_000_000));
    packed.extend_from_slice(&pack_record(
        0,
        &second.contract,
        &ZERO_VALUE,
        &erc20_approve([0x49; 20], 3_000_000),
    ));
    let raw = encode_multisend(&packed);
    let ms = MULTISEND_CALL_ONLY_ADDRESSES[0];

    let wst = wsteth_meta();
    let one = set_of(&[wst]);
    assert!(
        render_both(ms, 1, &raw, one.scope_all(), |_| {}).is_err(),
        "a catalogued record without its own metadata must still refuse"
    );

    let both = set_of(&[wst, second]);
    let (pages, screens) = render_both(ms, 1, &raw, both.scope_all(), |_| {})
        .expect("both catalogued records pinned by their own entries");
    let text = all_text(&pages);
    let sym = core::str::from_utf8(second.symbol).unwrap();
    let (first, rest) = text.split_once("MSend rec 2/2").expect("record divider");
    assert!(first.contains("Approve wstETH") && !first.contains(&alloc::format!("Approve {sym}")));
    assert!(rest.contains(&alloc::format!("Approve {sym}")));
    assert!(!rest.contains("wstETH"));
    assert!(!text.contains("dec=?") && !text.contains("units"));
    assert!(screens.contains("wstETH"));
    assert!(screens.contains(core::str::from_utf8(second.symbol).unwrap()));
}

fn gas_refund(c: &mut [u8]) {
    c[SAFE_OFF_GAS_PRICE + 24..SAFE_OFF_GAS_PRICE + 32].copy_from_slice(&3u64.to_be_bytes());
    c[SAFE_OFF_BASE_GAS + 24..SAFE_OFF_BASE_GAS + 32].copy_from_slice(&40_000u64.to_be_bytes());
    c[SAFE_OFF_GAS_TOKEN..SAFE_OFF_GAS_TOKEN + 20].copy_from_slice(&GAS_TOKEN);
}

fn gas_meta() -> Erc20Metadata<'static> {
    Erc20Metadata {
        chain_id: CHAIN_ID,
        contract: GAS_TOKEN,
        decimals: 6,
        name: b"Gas Dollar",
        symbol: b"GUSD",
    }
}

/// The refund block (`Refund up to:` .. `Refund to:`) and the inner-call
/// pages after it.
fn refund_and_inner(text: &str) -> (&str, &str) {
    let (_, from_refund) = text.split_once("Refund up to:").expect("refund page");
    from_refund.split_once("Refund to:").expect("refund receiver page")
}

#[test]
fn gas_token_refund_shows_decimals_and_never_labels_the_inner_call() {
    // H1: inner transfer on TOKEN (no entry), refund in GAS_TOKEN (entry).
    let raw = erc20_transfer([0x21; 20], 5_000_000);
    let set = set_of(&[gas_meta()]);
    let (pages, screens) =
        render_both(TOKEN, 0, &raw, set.scope_all(), gas_refund).expect("renders");
    let text = all_text(&pages);
    let (refund, inner) = refund_and_inner(&text);
    assert!(inner.contains("(unverified)"), "inner call must stay unverified:\n{inner}");
    assert!(!inner.contains("GUSD") && !inner.contains("Gas Dollar"), "gasToken entry labelled the inner call");
    assert!(refund.contains("GUSD"), "refund must name the gas token:\n{refund}");
    assert!(!refund.contains("units"), "refund fell back to base units:\n{refund}");
    assert!(screens.contains("GUSD"));

    // Without the entry the refund is the loud base-unit integer, as before.
    let none = Erc20Set::new();
    let (pages, _) = render_both(TOKEN, 0, &raw, none.scope_all(), gas_refund).expect("renders");
    let text = all_text(&pages);
    let (refund, _) = refund_and_inner(&text);
    assert!(refund.contains("units") && !refund.contains("GUSD"));
}

#[test]
fn inner_and_gas_token_entries_each_label_only_their_own_address() {
    let usdc = usdc_meta(); // contract TOKEN, symbol USDC
    let raw = erc20_transfer([0x21; 20], 5_000_000);
    let set = set_of(&[usdc, gas_meta()]);
    let (pages, _) = render_both(TOKEN, 0, &raw, set.scope_all(), gas_refund).expect("renders");
    let text = all_text(&pages);
    let (refund, inner) = refund_and_inner(&text);
    assert!(inner.contains("USDC") && !inner.contains("GUSD"));
    assert!(refund.contains("GUSD") && !refund.contains("USDC"));
}

#[test]
fn unbound_or_wrong_chain_entries_change_nothing() {
    let raw = erc20_transfer([0x21; 20], 5_000_000);
    let usdc = usdc_meta();
    let base = set_of(&[usdc]);
    let (want, want_px) = render_both(TOKEN, 0, &raw, base.scope_all(), |_| {}).unwrap();

    let unbound = Erc20Metadata { contract: [0x5c; 20], symbol: b"ZZZ", ..usdc_meta() };
    let other_chain = Erc20Metadata { chain_id: 10, symbol: b"OPX", ..usdc_meta() };
    let noisy = set_of(&[unbound, usdc, other_chain]);
    let (got, got_px) = render_both(TOKEN, 0, &raw, noisy.scope_all(), |_| {}).unwrap();
    assert_eq!(golden_grid_hash(&got), golden_grid_hash(&want));
    assert_eq!(got_px, want_px);

    // A wrong-chain entry for the very contract is no entry at all.
    let wrong = set_of(&[other_chain]);
    let empty = Erc20Set::new();
    let (a, _) = render_both(TOKEN, 0, &raw, wrong.scope_all(), |_| {}).unwrap();
    let (b, _) = render_both(TOKEN, 0, &raw, empty.scope_all(), |_| {}).unwrap();
    assert_eq!(golden_grid_hash(&a), golden_grid_hash(&b));
    assert!(all_text(&a).contains("(unverified)"));
}

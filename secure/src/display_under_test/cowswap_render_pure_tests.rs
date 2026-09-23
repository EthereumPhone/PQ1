//! Render-faithfulness tests for the CowSwap order renderer
//! (`crate::tx::eip712::cowswap_display`).
//!
//! Closes the highest-priority gap from the 2026-06-29 coverage audit: this
//! renderer is the SOLE binding from a verified order to the screen (the
//! keccak orderDigest cross-check binds the signed *digest*, not the displayed
//! rows), it had ZERO host render tests, and it has a documented misrender-bug
//! history — a 100-WETH fee shown as ~0.06 because the retired `write_fee_row`
//! read only the low 7 of 32 bytes (`cowswap_display.rs:198-200`).
//!
//! These tests drive the REAL formatter (`primitives::write_cow_leg_amount`
//! → `write_token_amount_two_rows`, the post-fix code) over hand-built
//! CANONICAL bytes and assert the rendered amount digits / token address /
//! fee — binding the SIGNED bytes to the SCREEN. The amount is read purely
//! from `canonical[..]` by the renderer; the `CowLeg` only supplies render
//! metadata (decimals/symbol), so the assertions are NOT circular against the
//! convenience struct. `negative_*_nonvacuous` flips the bytes and proves the
//! assertion tracks them.

use crate::tx::eip712::cowswap::CowLeg;
use crate::tx::eip712::cowswap_display::{
    amounts_are_exactly_renderable, order_kind_label, render_cowswap_pages,
};
use crate::ui::DISPLAY_COLS;

// Canonical field offsets (mirror cowswap_display.rs / cowswap/mod.rs §7-23).
const OFF_SELL_TOKEN: usize = 8;
const OFF_SELL_AMOUNT: usize = 68;
const OFF_FEE_AMOUNT: usize = 132;
const OFF_KIND: usize = 168;

fn row_str(row: &[u8; DISPLAY_COLS]) -> String {
    for &b in row.iter() {
        assert!(
            (0x20..=0x7e).contains(&b),
            "non-printable byte {b:#x} on a rendered row"
        );
    }
    let s: String = row.iter().map(|&b| b as char).collect();
    s.trim_end().to_string()
}

/// Concatenate the 4 rows of a page (trim-joined) so a multi-row field can be
/// asserted regardless of which row it lands on.
fn page_concat(pages: &super::Pages, page: usize) -> String {
    (0..4)
        .map(|r| row_str(&pages.buf[page][r]))
        .collect::<Vec<_>>()
        .join("|")
}

/// First page whose row 0 trims to exactly `label`.
fn find_page_by_label(pages: &super::Pages, label: &str) -> usize {
    (0..pages.len)
        .find(|&p| row_str(&pages.buf[p][0]) == label)
        .unwrap_or_else(|| panic!("no page labelled {label:?}"))
}

fn assert_all_printable(pages: &super::Pages) {
    for p in 0..pages.len {
        for r in 0..4 {
            let _ = row_str(&pages.buf[p][r]); // panics on non-printable
        }
    }
}

/// Put `v` big-endian into the low 16 bytes of the 32-byte BE field at
/// `canonical[off..off+32]`.
fn put_amount(canonical: &mut [u8; 204], off: usize, v: u128) {
    canonical[off..off + 32].fill(0);
    canonical[off + 16..off + 32].copy_from_slice(&v.to_be_bytes());
}

/// A decoded leg with the given decimals + symbol (the render metadata).
fn leg(symbol: &[u8], decimals: u8) -> CowLeg {
    let mut s = [0u8; 64];
    s[..symbol.len()].copy_from_slice(symbol);
    let mut name = [0u8; 64];
    name[..3].copy_from_slice(b"tok");
    CowLeg::Decoded {
        decimals,
        symbol: s,
        symbol_len: symbol.len() as u8,
        name,
        name_len: 3,
    }
}

/// Build a SELL-kind canonical with the given sell token + amount; other
/// fields zeroed (receiver=0, fee=0, etc.).
fn sell_canonical(sell_token: [u8; 20], sell_amount: u128) -> [u8; 204] {
    let mut c = [0u8; 204];
    c[OFF_SELL_TOKEN..OFF_SELL_TOKEN + 20].copy_from_slice(&sell_token);
    put_amount(&mut c, OFF_SELL_AMOUNT, sell_amount);
    c[OFF_KIND] = 0; // SELL
    c
}

#[test]
fn exact_preflight_accepts_decoded_dust_via_base_units() {
    let c = sell_canonical([0x33; 20], 1);
    let sell = leg(b"DUST", 18);

    assert!(
        amounts_are_exactly_renderable(&c, &sell, &CowLeg::AddrHex),
        "one signed base unit must remain available without rounding"
    );

    let pages = render_cowswap_pages(&c, &sell, &CowLeg::AddrHex);
    assert!(
        page_concat(&pages, 1).contains("base DUST"),
        "the accepted value must use the exact base-unit fallback"
    );
}

#[test]
fn exact_preflight_wraps_full_precision_value_exactly() {
    // 10^21 + 1 = 1000.000000000000000001 at 18 decimals — the shape of a
    // CoW quote-derived limit. Neither the two-row decimal form nor the
    // base-unit form fits; the exact wrapped form does.
    let c = sell_canonical([0x33; 20], 1_000_000_000_000_000_000_001);
    let sell = leg(b"DUST", 18);

    assert!(
        amounts_are_exactly_renderable(&c, &sell, &CowLeg::AddrHex),
        "a full-precision amount must wrap exactly instead of refusing"
    );
    let pages = render_cowswap_pages(&c, &sell, &CowLeg::AddrHex);
    let text = page_concat(&pages, 1);
    assert!(
        text.contains("1000.0000000000>") && text.contains(">00000001 DUST"),
        "every digit shown across the two rows: {text}"
    );
}

#[test]
fn exact_preflight_refuses_value_too_wide_for_scaled_or_base_units() {
    // 10^25 + 1 = 10000000.000000000000000001: its wrapped row 2 needs 18
    // columns with a four-byte symbol, its raw base-unit form 26 digits.
    let c = sell_canonical([0x33; 20], 10_000_000_000_000_000_000_000_001);
    let sell = leg(b"DUST", 18);

    assert!(
        !amounts_are_exactly_renderable(&c, &sell, &CowLeg::AddrHex),
        "the preflight must refuse when no exact representation fits"
    );
}

#[test]
fn exact_preflight_accepts_addrhex_high_byte_sell() {
    let mut c = sell_canonical([0x33; 20], 0);
    c[OFF_SELL_AMOUNT] = 1; // 2^248, exact in the fallback leg's full-U256 hex.

    assert!(
        amounts_are_exactly_renderable(&c, &CowLeg::AddrHex, &CowLeg::AddrHex),
        "AddrHex legs use an exact hex painter and must not inherit decimal-width refusal"
    );
}

#[test]
fn positive_sell_amount_and_symbol_bind_to_canonical_bytes() {
    // sellAmount = 1500 USDC (6 decimals) = 1_500_000_000 raw, placed at
    // canonical[68..100]. The renderer reads the digits from THOSE bytes.
    let token = [0x33u8; 20];
    let c = sell_canonical(token, 1_500_000_000);
    let pages = render_cowswap_pages(&c, &leg(b"USDC", 6), &leg(b"WETH", 18));
    assert_all_printable(&pages);

    // Header + kind banner.
    assert_eq!(row_str(&pages.buf[0][0]), "Sign CowSwap?");
    assert_eq!(row_str(&pages.buf[0][3]), "kind=SELL");
    assert_eq!(order_kind_label(&c), "kind=SELL");

    // Sell leg page A: label + amount + symbol. Page 1 (header is page 0).
    assert_eq!(row_str(&pages.buf[1][0]), "Sell exactly:");
    let amount_rows = format!(
        "{}|{}",
        row_str(&pages.buf[1][1]),
        row_str(&pages.buf[1][2])
    );
    assert!(
        amount_rows.contains("1500"),
        "sell amount must render the integer 1500 from canonical[68..100]; got {amount_rows:?}"
    );
    assert!(
        amount_rows.contains("USDC"),
        "sell amount must carry the symbol; got {amount_rows:?}"
    );

    // Sell leg page B carries the FULL 40-hex sell-token contract (anti-spoof);
    // it's "0x"+addr split across rows 1-3. Strip non-hex and join, then the
    // 40-hex must be present contiguously (the anti-DB-spoof backstop).
    let token_hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
    let rendered_hex: String = (1..4)
        .flat_map(|r| row_str(&pages.buf[2][r]).chars().collect::<Vec<_>>())
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_lowercase();
    assert!(
        rendered_hex.contains(&token_hex),
        "sell-token page must show the full 40-hex contract {token_hex}; rendered {rendered_hex:?}"
    );
}

#[test]
fn cowswap_chain_id_is_lossless_for_full_u64() {
    let mut c = sell_canonical([0x33; 20], 1_500_000_000);
    c[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    let pages = render_cowswap_pages(&c, &leg(b"USDC", 6), &leg(b"WETH", 18));
    assert_eq!(row_str(&pages.buf[0][1]), "chain 184467440>");
    assert_eq!(row_str(&pages.buf[0][2]), "73709551615");
}

#[test]
fn negative_sell_amount_nonvacuous() {
    // Same render path, different canonical amount bytes → different digits.
    // Proves the test tracks the SIGNED bytes, not the CowLeg struct.
    let token = [0x33u8; 20];
    let c1 = sell_canonical(token, 1_500_000_000); // 1500 USDC
    let c2 = sell_canonical(token, 2_700_000_000); // 2700 USDC
    let p1 = render_cowswap_pages(&c1, &leg(b"USDC", 6), &leg(b"WETH", 18));
    let p2 = render_cowswap_pages(&c2, &leg(b"USDC", 6), &leg(b"WETH", 18));

    let a1 = format!("{}|{}", row_str(&p1.buf[1][1]), row_str(&p1.buf[1][2]));
    let a2 = format!("{}|{}", row_str(&p2.buf[1][1]), row_str(&p2.buf[1][2]));
    assert!(a1.contains("1500") && !a1.contains("2700"));
    assert!(a2.contains("2700") && !a2.contains("1500"));
    assert_ne!(
        a1, a2,
        "flipping canonical sellAmount must change the rendered amount"
    );
}

#[test]
fn positive_cowswap_golden_grid_hash() {
    // te-2: full-grid golden over the canonical CowSwap SELL render. Binds
    // every rendered cell (header/kind banner, both legs, the 40-hex token
    // pages, dividers) so a layout regression the per-substring asserts miss
    // still trips. Re-bless GOLDEN only for an INTENTIONAL layout change.
    let token = [0x33u8; 20];
    let c = sell_canonical(token, 1_500_000_000);
    let pages = render_cowswap_pages(&c, &leg(b"USDC", 6), &leg(b"WETH", 18));
    let h = super::golden_grid_hash(&pages);

    // Non-vacuity: flipping the canonical sellAmount MUST move the digest.
    let c2 = sell_canonical(token, 2_700_000_000);
    let h2 = super::golden_grid_hash(&render_cowswap_pages(
        &c2,
        &leg(b"USDC", 6),
        &leg(b"WETH", 18),
    ));
    assert_ne!(
        h, h2,
        "golden hash must bind rendered content (sellAmount change did not move it)"
    );

    const GOLDEN: [u8; 32] = [
        142, 85, 132, 133, 106, 125, 212, 52, 60, 225, 218, 75, 139, 0, 3, 193, 120, 121, 210, 134,
        178, 254, 10, 88, 186, 141, 14, 183, 134, 47, 238, 228,
    ];
    assert_eq!(
        h, GOLDEN,
        "CowSwap render golden changed — re-bless if intentional. got={h:?}"
    );
}

#[test]
fn negative_fee_high_bytes_never_collapse_to_small_number() {
    // THE documented bug class: a fee whose value lives in the HIGH bytes of
    // the 32-byte word must never render as a small number (the retired
    // formatter showed only the low 7 bytes → a 100-WETH fee read as ~0.06,
    // any multiple of 2^56 read as zero). Set fee = 2^248 (top byte = 0x01,
    // all low bytes zero): the post-fix formatter must fail SAFE to
    // "(amount too big)", never "0".
    let token = [0x44u8; 20];
    let mut c = sell_canonical(token, 1_000_000); // benign sell amount
    c[OFF_FEE_AMOUNT] = 0x01; // value = 2^248, everything below it zero

    // AddrHex sell leg → fee renders as a raw integer (decimals=0), exercising
    // the same magnitude path without a decimals shift hiding the point.
    let pages = render_cowswap_pages(&c, &CowLeg::AddrHex, &CowLeg::AddrHex);
    assert_all_printable(&pages);

    let fee_page = find_page_by_label(&pages, "Fee (sell tok):");
    let fee_rows = page_concat(&pages, fee_page);
    // Must NOT have collapsed the 2^248 value to "0" / a tiny number.
    assert!(
        fee_rows.contains("(amount too big)"),
        "a 2^248 fee must fail safe to the overflow banner, never a small number; got {fee_rows:?}"
    );
    // Belt-and-braces: the fee value rows are not a bare "0".
    assert_ne!(row_str(&pages.buf[fee_page][1]), "0");
}

#[test]
fn addrhex_fallback_renders_middle_token_bytes_in_full() {
    // The retired two-row fallback showed bytes 0..7 and 14..20 only. Two
    // contracts differing solely in the omitted middle therefore produced
    // identical trusted pages. The no-metadata path must remain injective.
    let mut token_a = [0x31u8; 20];
    let mut token_b = token_a;
    token_a[9] = 0x42;
    token_b[9] = 0xa7;

    let pages_a = render_cowswap_pages(
        &sell_canonical(token_a, 1_000_000),
        &CowLeg::AddrHex,
        &CowLeg::AddrHex,
    );
    let pages_b = render_cowswap_pages(
        &sell_canonical(token_b, 1_000_000),
        &CowLeg::AddrHex,
        &CowLeg::AddrHex,
    );

    let rendered = |pages: &super::Pages| {
        (1..4)
            .flat_map(|row| row_str(&pages.buf[1][row]).chars().collect::<Vec<_>>())
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_lowercase()
    };
    let token_a_hex: String = token_a.iter().map(|b| format!("{b:02x}")).collect();
    let token_b_hex: String = token_b.iter().map(|b| format!("{b:02x}")).collect();

    assert_eq!(row_str(&pages_a.buf[1][0]), "Sell addr;amtHex");
    assert!(rendered(&pages_a).contains(&token_a_hex));
    assert!(rendered(&pages_b).contains(&token_b_hex));
    assert_ne!(pages_a.buf[1], pages_b.buf[1]);
}
